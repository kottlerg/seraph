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
the date, the QEMU version, and the reference it was checked against. A change to a gated
userspace path regenerates both architectures, rewrites the block, and revises the prose below
where its numbers moved.

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

`ubench.ipc_rt words=0` is 5662 / 7479, 5006 / 4775 of it in the kernel. The kernel's `memset`, four
calls per round trip, is 2268 on x86_64, against 1223 in ktest's round trip; the zeroing of the
whole 576-byte `Message` each way, which #1541 removes, is among it. On riscv64 the message moves
through `compiler_builtins`' word loops in both ubench and the kernel (`memcpy` 1448 and 762,
`memset` 667 and 452, `memmove` 385). On x86_64 each round trip also takes the lazy FPU switch's
`#NM` trap once a thread is switched back in (`isr_nm` and its handler, 132).

### Page Faults

`ubench.fault_fill path=fault pages=16` is 37273 / 60795: memmgr 13990 / 31652, of which its
`memset` zeroing the 16 frames is 8298 / 24812 (x86_64's `rep stos` is about one iteration per 8
bytes, riscv64's loop about one instruction per 2.6 bytes), and the kernel 23272 / 29135, spread
over the page-table walk and install (`level_shift`, `table_index`, `names_table`, `read_entry`,
`install_user_leaf`), the frame map's counters, and `sys_mem_map`. `fault_scaling threads=1` runs
the same path. `path=grant` adds the grant's capability operations, 37745 / 64915.

### Shared-Memory Ring

`ubench.shmem_ring` runs in ubench alone: `shmem_ring::transfer` is 49342 / 57448 of the
4096-byte transfer, about 12 / 14 instructions per byte.

### Console Writes

`ubench.console_write bytes=4096` is 48965767 / 177131885, all but 0.2 % in the framebuffer
driver. Its scroll moves the whole framebuffer up a text row at each line it fills
(`memmove` 28673472 / 143364824 and `FramebufferWriter::scroll` 9013440 / 19662656), and
drawing the glyphs is 7156800 / 12820888.

### File Reads and Opens

A read through the inline path (`fsbench.read path=inline`) is fatfs's copy and zeroing of the reply
and the kernel's copy to and from user memory. A read through granted frames (`path=frame`) spends
12628 / 12530 in the kernel's Keccak permutation (`keccak_f1600`, a kernel entropy draw) per 4 KiB
frame the grant names, 202048 / 200480 of 788719 / 1156072 at 64 KiB; #1550 serves such small draws
from one squeezed block. `fsbench.open depth=3` is 77448 / 110982, one such draw (12628 / 12530) and
fatfs's long-name parsing (`LfnAccum`, 8405 / 7125) among it.

## Account

<!-- path-account: begin; generated by cargo xtask path-account write -->

| Configuration | Head | Taken | QEMU | Checked against |
|---|---|---|---|---|
| x86_64 release | `56284edb8820` | 2026-11-23 | QEMU emulator version 11.1.3 | 1 icount boot(s) of the image without debuginfo |
| riscv64 release | `56284edb8820` | 2026-11-23 | QEMU emulator version 11.1.3 | 1 icount boot(s) of the image without debuginfo |

#### Totals

| Path | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `ubench.ipc_rt words=0 cpus=1` | all | 5662 | 7479 |
| `ubench.ipc_rt words=0 cpus=1` | ubench | 656 | 2351 |
| `ubench.ipc_rt words=0 cpus=1` | kernel | 5006 | 4775 |
| `ubench.ipc_rt words=0 cpus=1` | other | 0 | 353 |
| `ubench.ipc_rt words=6 cpus=1` | all | 5905 | 8507 |
| `ubench.ipc_rt words=6 cpus=1` | ubench | 757 | 2573 |
| `ubench.ipc_rt words=6 cpus=1` | kernel | 5148 | 5228 |
| `ubench.ipc_rt words=6 cpus=1` | other | 0 | 706 |
| `ubench.ipc_rt words=7 cpus=1` | all | 6157 | 9328 |
| `ubench.ipc_rt words=7 cpus=1` | ubench | 842 | 2558 |
| `ubench.ipc_rt words=7 cpus=1` | kernel | 5315 | 6417 |
| `ubench.ipc_rt words=7 cpus=1` | other | 0 | 353 |
| `ubench.ipc_rt words=64 cpus=1` | all | 9078 | 23639 |
| `ubench.ipc_rt words=64 cpus=1` | ubench | 1939 | 4097 |
| `ubench.ipc_rt words=64 cpus=1` | kernel | 7139 | 19189 |
| `ubench.ipc_rt words=64 cpus=1` | other | 0 | 353 |
| `ubench.fault_fill path=fault pages=16 cpus=1` | all | 37273 | 60795 |
| `ubench.fault_fill path=fault pages=16 cpus=1` | ubench | 11 | 8 |
| `ubench.fault_fill path=fault pages=16 cpus=1` | memmgr | 13990 | 31652 |
| `ubench.fault_fill path=fault pages=16 cpus=1` | kernel | 23272 | 29135 |
| `ubench.fault_fill path=grant pages=16 cpus=1` | all | 37745 | 64915 |
| `ubench.fault_fill path=grant pages=16 cpus=1` | ubench | 115 | 353 |
| `ubench.fault_fill path=grant pages=16 cpus=1` | memmgr | 11145 | 30217 |
| `ubench.fault_fill path=grant pages=16 cpus=1` | kernel | 26485 | 33992 |
| `ubench.fault_fill path=grant pages=16 cpus=1` | other | 0 | 353 |
| `ubench.fault_scaling threads=1 pages=16 cpus=1` | all | 37166 | 60708 |
| `ubench.fault_scaling threads=1 pages=16 cpus=1` | ubench | 11 | 8 |
| `ubench.fault_scaling threads=1 pages=16 cpus=1` | memmgr | 13883 | 31556 |
| `ubench.fault_scaling threads=1 pages=16 cpus=1` | kernel | 23272 | 29144 |
| `ubench.shmem_ring bytes=64 cpus=1` | all | 219 | 103 |
| `ubench.shmem_ring bytes=64 cpus=1` | ubench | 219 | 103 |
| `ubench.shmem_ring bytes=512 cpus=1` | all | 207 | 383 |
| `ubench.shmem_ring bytes=512 cpus=1` | ubench | 207 | 383 |
| `ubench.shmem_ring bytes=4096 cpus=1` | all | 49353 | 57455 |
| `ubench.shmem_ring bytes=4096 cpus=1` | ubench | 49353 | 57455 |
| `ubench.shmem_ring bytes=65536 cpus=1` | all | 789862 | 919564 |
| `ubench.shmem_ring bytes=65536 cpus=1` | ubench | 789423 | 919115 |
| `ubench.shmem_ring bytes=65536 cpus=1` | kernel | 439 | 449 |
| `ubench.console_write bytes=64 cpus=1` | all | 770494 | 2775951 |
| `ubench.console_write bytes=64 cpus=1` | ubench | 989 | 3099 |
| `ubench.console_write bytes=64 cpus=1` | /services/drivers/framebuffer | 763764 | 2764543 |
| `ubench.console_write bytes=64 cpus=1` | kernel | 5741 | 7603 |
| `ubench.console_write bytes=64 cpus=1` | other | 0 | 706 |
| `ubench.console_write bytes=4096 cpus=1` | all | 48965767 | 177131885 |
| `ubench.console_write bytes=4096 cpus=1` | ubench | 25251 | 60079 |
| `ubench.console_write bytes=4096 cpus=1` | /services/drivers/framebuffer | 48865048 | 176873272 |
| `ubench.console_write bytes=4096 cpus=1` | /services/drivers/iommu-riscv | 0 | 113 |
| `ubench.console_write bytes=4096 cpus=1` | /services/drivers/iommu-vtd | 63 | 0 |
| `ubench.console_write bytes=4096 cpus=1` | kernel | 75405 | 192773 |
| `ubench.console_write bytes=4096 cpus=1` | other | 0 | 5648 |
| `fsbench.read size=16 path=inline cpus=1` | all | 8704 | 14489 |
| `fsbench.read size=16 path=inline cpus=1` | /programs/fsbench | 577 | 1541 |
| `fsbench.read size=16 path=inline cpus=1` | fatfs:/ | 2344 | 5967 |
| `fsbench.read size=16 path=inline cpus=1` | fatfs:/data | 1 | 1 |
| `fsbench.read size=16 path=inline cpus=1` | kernel | 5782 | 6213 |
| `fsbench.read size=16 path=inline cpus=1` | other | 0 | 767 |
| `fsbench.read size=16 path=frame cpus=1` | all | 48999 | 71911 |
| `fsbench.read size=16 path=frame cpus=1` | /programs/fsbench | 11322 | 27036 |
| `fsbench.read size=16 path=frame cpus=1` | fatfs:/ | 4226 | 5986 |
| `fsbench.read size=16 path=frame cpus=1` | fatfs:/data | 27 | 27 |
| `fsbench.read size=16 path=frame cpus=1` | kernel | 33424 | 37328 |
| `fsbench.read size=16 path=frame cpus=1` | other | 0 | 1534 |
| `fsbench.read size=1024 path=inline cpus=1` | all | 42083 | 83109 |
| `fsbench.read size=1024 path=inline cpus=1` | /programs/fsbench | 2643 | 7249 |
| `fsbench.read size=1024 path=inline cpus=1` | fatfs:/ | 14300 | 33852 |
| `fsbench.read size=1024 path=inline cpus=1` | fatfs:/data | 4 | 4 |
| `fsbench.read size=1024 path=inline cpus=1` | kernel | 25136 | 39058 |
| `fsbench.read size=1024 path=inline cpus=1` | other | 0 | 2946 |
| `fsbench.read size=1024 path=frame cpus=1` | all | 48999 | 71911 |
| `fsbench.read size=1024 path=frame cpus=1` | /programs/fsbench | 11322 | 27036 |
| `fsbench.read size=1024 path=frame cpus=1` | fatfs:/ | 4226 | 5986 |
| `fsbench.read size=1024 path=frame cpus=1` | fatfs:/data | 27 | 27 |
| `fsbench.read size=1024 path=frame cpus=1` | kernel | 33424 | 37328 |
| `fsbench.read size=1024 path=frame cpus=1` | other | 0 | 1534 |
| `fsbench.read size=4096 path=inline cpus=1` | all | 168197 | 332295 |
| `fsbench.read size=4096 path=inline cpus=1` | /programs/fsbench | 10437 | 28855 |
| `fsbench.read size=4096 path=inline cpus=1` | fatfs:/ | 57200 | 135408 |
| `fsbench.read size=4096 path=inline cpus=1` | fatfs:/data | 16 | 16 |
| `fsbench.read size=4096 path=inline cpus=1` | kernel | 100544 | 156232 |
| `fsbench.read size=4096 path=inline cpus=1` | other | 0 | 11784 |
| `fsbench.read size=4096 path=frame cpus=1` | all | 48999 | 71911 |
| `fsbench.read size=4096 path=frame cpus=1` | /programs/fsbench | 11322 | 27036 |
| `fsbench.read size=4096 path=frame cpus=1` | fatfs:/ | 4226 | 5986 |
| `fsbench.read size=4096 path=frame cpus=1` | fatfs:/data | 27 | 27 |
| `fsbench.read size=4096 path=frame cpus=1` | kernel | 33424 | 37328 |
| `fsbench.read size=4096 path=frame cpus=1` | other | 0 | 1534 |
| `fsbench.read size=16384 path=inline cpus=1` | all | 685238 | 1343553 |
| `fsbench.read size=16384 path=inline cpus=1` | /programs/fsbench | 41613 | 115279 |
| `fsbench.read size=16384 path=inline cpus=1` | fatfs:/ | 240936 | 555696 |
| `fsbench.read size=16384 path=inline cpus=1` | fatfs:/data | 72 | 64 |
| `fsbench.read size=16384 path=inline cpus=1` | kernel | 402617 | 625378 |
| `fsbench.read size=16384 path=inline cpus=1` | other | 0 | 47136 |
| `fsbench.read size=16384 path=frame cpus=1` | all | 196480 | 288209 |
| `fsbench.read size=16384 path=frame cpus=1` | /programs/fsbench | 45153 | 108003 |
| `fsbench.read size=16384 path=frame cpus=1` | fatfs:/ | 17523 | 24638 |
| `fsbench.read size=16384 path=frame cpus=1` | fatfs:/data | 108 | 120 |
| `fsbench.read size=16384 path=frame cpus=1` | kernel | 133696 | 149312 |
| `fsbench.read size=16384 path=frame cpus=1` | other | 0 | 6136 |
| `fsbench.read size=65536 path=inline cpus=1` | all | 2923880 | 5589193 |
| `fsbench.read size=65536 path=inline cpus=1` | /programs/fsbench | 166317 | 460975 |
| `fsbench.read size=65536 path=inline cpus=1` | fatfs:/ | 1147172 | 2437002 |
| `fsbench.read size=65536 path=inline cpus=1` | fatfs:/data | 364 | 262 |
| `fsbench.read size=65536 path=inline cpus=1` | kernel | 1610027 | 2502410 |
| `fsbench.read size=65536 path=inline cpus=1` | other | 0 | 188544 |
| `fsbench.read size=65536 path=frame cpus=1` | all | 788719 | 1156072 |
| `fsbench.read size=65536 path=frame cpus=1` | /programs/fsbench | 180477 | 431871 |
| `fsbench.read size=65536 path=frame cpus=1` | fatfs:/ | 72585 | 101516 |
| `fsbench.read size=65536 path=frame cpus=1` | fatfs:/data | 432 | 444 |
| `fsbench.read size=65536 path=frame cpus=1` | kernel | 535225 | 597697 |
| `fsbench.read size=65536 path=frame cpus=1` | other | 0 | 24544 |
| `fsbench.open depth=3 cpus=1` | all | 77448 | 110982 |
| `fsbench.open depth=3 cpus=1` | /programs/fsbench | 3274 | 7055 |
| `fsbench.open depth=3 cpus=1` | fatfs:/ | 25067 | 42866 |
| `fsbench.open depth=3 cpus=1` | fatfs:/data | 19 | 83 |
| `fsbench.open depth=3 cpus=1` | vfsd | 1182 | 3579 |
| `fsbench.open depth=3 cpus=1` | kernel | 47906 | 55098 |
| `fsbench.open depth=3 cpus=1` | other | 0 | 2301 |

#### `ubench.ipc_rt words=0 cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `memset` | kernel | 2268 | 452 |
| `compiler_builtins::mem::memcpy` | ubench | | 1448 |
| `compiler_builtins::mem::memcpy` | kernel | | 762 |
| `memset` | ubench | 93 | 667 |
| `compiler_builtins::mem::memmove` | kernel | | 385 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | 372 |
| `memcpy` | ubench | 347 | 10 |
| `memcpy` | kernel | 264 | 4 |
| `kernel::sched::schedule` | kernel | 192 | 236 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 186 | |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | 153 |
| `<page 0x8000c000>` | other | | 134 |
| `<page 0x80000000>` | other | | 104 |
| `<kernel::sync::Spinlock>::lock_raw` | kernel | 100 | 68 |
| `<kernel::sched::run_queue::PerCpuScheduler>::dequeue_highest` | kernel | 32 | 92 |
| `kernel::arch::current::context::switch` | kernel | 92 | 74 |
| `kernel::sched::scheduler_ptr` | kernel | 30 | 91 |
| `kernel::syscall::pin_checked` | kernel | 84 | 90 |
| `kernel::syscall::ipc::sys_ipc_call` | kernel | 70 | 83 |
| `kernel::arch::current::idt::isr_nm` | kernel | 80 | |
| `kernel::sched::enqueue_and_wake` | kernel | 58 | 78 |
| `kernel::arch::current::interrupts::handle_trap` | kernel | | 76 |
| `kernel::syscall::ipc::sys_ipc_reply` | kernel | 53 | 72 |
| `kernel::syscall::dispatch` | kernel | 69 | 24 |
| `kernel::arch::current::fpu::save_fp_to` | kernel | | 68 |
| `kernel::ipc::upcall::deliver` | kernel | | 66 |
| `kernel::syscall::ipc::sys_ipc_recv` | kernel | 40 | 66 |
| `ipc::ipc_call_timeout` | ubench | 48 | 61 |
| `kernel::sched::scheduler_for` | kernel | 47 | 60 |
| `kernel::arch::current::cpu::current_cpu` | kernel | 59 | 34 |
| `kernel::syscall::dispatch_in_range` | kernel | 57 | 51 |
| `ubench::ipc_rt::serve` | ubench | 57 | 52 |
| `kernel::arch::current::cpu::restore_interrupts` | kernel | 36 | 54 |
| `kernel::ipc::endpoint::endpoint_call` | kernel | 31 | 53 |
| `kernel::arch::current::cpu::save_and_disable_interrupts` | kernel | 51 | 26 |
| `ipc::ipc_recv_timeout` | ubench | 36 | 51 |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 24 | 50 |
| `<page 0x80017000>` | other | | 45 |
| `kernel::syscall::finish_syscall` | kernel | 42 | 12 |
| `kernel::sched::commit_blocked_under_local_lock` | kernel | 32 | 40 |
| `seraph_enter_from_user` | kernel | 40 | |
| `<kernel::sync::Spinlock>::unlock_raw` | kernel | 13 | 39 |
| `kernel::arch::current::fpu::switch_out_save` | kernel | 18 | 38 |
| 132 functions below 37 each |  | 1013 | 1138 |

#### `ubench.ipc_rt words=6 cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `memset` | kernel | 2268 | 452 |
| `compiler_builtins::mem::memcpy` | ubench | | 1592 |
| `compiler_builtins::mem::memcpy` | kernel | | 864 |
| `memset` | ubench | 93 | 667 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | 465 |
| `memcpy` | ubench | 397 | 14 |
| `compiler_builtins::mem::memmove` | kernel | | 385 |
| `memcpy` | kernel | 308 | 8 |
| `<page 0x8000c000>` | other | | 268 |
| `kernel::sched::schedule` | kernel | 192 | 236 |
| `<page 0x80000000>` | other | | 208 |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | 192 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 186 | |
| `<kernel::sync::Spinlock>::lock_raw` | kernel | 100 | 68 |
| `ipc::ipc_call_timeout` | ubench | 72 | 99 |
| `<kernel::sched::run_queue::PerCpuScheduler>::dequeue_highest` | kernel | 32 | 92 |
| `kernel::arch::current::context::switch` | kernel | 92 | 74 |
| `kernel::arch::current::interrupts::handle_trap` | kernel | | 92 |
| `kernel::sched::scheduler_ptr` | kernel | 30 | 91 |
| `kernel::syscall::pin_checked` | kernel | 84 | 90 |
| `<page 0x80017000>` | other | | 90 |
| `kernel::syscall::ipc::sys_ipc_call` | kernel | 75 | 89 |
| `kernel::arch::current::idt::isr_nm` | kernel | 80 | |
| `kernel::sched::enqueue_and_wake` | kernel | 58 | 78 |
| `ipc::ipc_recv_timeout` | ubench | 53 | 78 |
| `kernel::syscall::ipc::sys_ipc_recv` | kernel | 45 | 72 |
| `kernel::syscall::ipc::sys_ipc_reply` | kernel | 53 | 72 |
| `kernel::syscall::dispatch` | kernel | 69 | 24 |
| `kernel::arch::current::fpu::restore_fp_from` | kernel | | 68 |
| `kernel::arch::current::fpu::save_fp_to` | kernel | | 68 |
| `kernel::ipc::upcall::deliver` | kernel | | 66 |
| `kernel::sched::scheduler_for` | kernel | 47 | 60 |
| `kernel::arch::current::cpu::current_cpu` | kernel | 59 | 34 |
| `ubench::ipc_rt::serve` | ubench | 58 | 53 |
| `kernel::syscall::dispatch_in_range` | kernel | 57 | 51 |
| `kernel::arch::current::cpu::restore_interrupts` | kernel | 36 | 54 |
| `kernel::ipc::endpoint::endpoint_call` | kernel | 31 | 53 |
| `kernel::arch::current::cpu::save_and_disable_interrupts` | kernel | 51 | 26 |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 24 | 50 |
| `<page 0x80010000>` | other | | 48 |
| `<kernel::arch::current::trap_frame::TrapFrame>::set_msg_regs` | kernel | 44 | 46 |
| `kernel::syscall::finish_syscall` | kernel | 42 | 12 |
| 137 functions below 42 each |  | 1169 | 1358 |

#### `ubench.ipc_rt words=7 cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `memset` | kernel | 2268 | 452 |
| `compiler_builtins::mem::memcpy` | ubench | | 1495 |
| `__copy_user_fault_end` | kernel | 8 | 908 |
| `compiler_builtins::mem::memcpy` | kernel | | 762 |
| `memset` | ubench | 93 | 667 |
| `__copy_user_fault_start` | kernel | 228 | 448 |
| `compiler_builtins::mem::memmove` | kernel | | 385 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | 372 |
| `memcpy` | ubench | 354 | 10 |
| `memcpy` | kernel | 264 | 4 |
| `__copy_user` | kernel | 12 | 236 |
| `kernel::sched::schedule` | kernel | 192 | 236 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 186 | |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | 153 |
| `ipc::ipc_call_timeout` | ubench | 134 | 138 |
| `<page 0x8000c000>` | other | | 134 |
| `<page 0x80000000>` | other | | 104 |
| `<kernel::sync::Spinlock>::lock_raw` | kernel | 100 | 68 |
| `<kernel::sched::run_queue::PerCpuScheduler>::dequeue_highest` | kernel | 32 | 92 |
| `kernel::arch::current::context::switch` | kernel | 92 | 74 |
| `kernel::sched::scheduler_ptr` | kernel | 30 | 91 |
| `kernel::syscall::ipc::sys_ipc_call` | kernel | 77 | 90 |
| `kernel::syscall::pin_checked` | kernel | 84 | 90 |
| `ipc::ipc_recv_timeout` | ubench | 77 | 83 |
| `kernel::arch::current::idt::isr_nm` | kernel | 80 | |
| `kernel::sched::enqueue_and_wake` | kernel | 58 | 78 |
| `kernel::arch::current::interrupts::handle_trap` | kernel | | 76 |
| `ipc::ipc_reply` | ubench | 74 | 73 |
| `kernel::syscall::ipc::sys_ipc_recv` | kernel | 45 | 72 |
| `kernel::syscall::ipc::sys_ipc_reply` | kernel | 53 | 72 |
| `kernel::syscall::dispatch` | kernel | 69 | 24 |
| `kernel::arch::current::fpu::save_fp_to` | kernel | | 68 |
| `kernel::ipc::upcall::deliver` | kernel | | 66 |
| `kernel::sched::scheduler_for` | kernel | 47 | 60 |
| `kernel::arch::current::cpu::current_cpu` | kernel | 59 | 34 |
| `ubench::ipc_rt::serve` | ubench | 58 | 53 |
| `kernel::syscall::dispatch_in_range` | kernel | 57 | 51 |
| `kernel::arch::current::cpu::restore_interrupts` | kernel | 36 | 54 |
| `kernel::ipc::endpoint::endpoint_call` | kernel | 31 | 53 |
| `kernel::arch::current::cpu::save_and_disable_interrupts` | kernel | 51 | 26 |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 24 | 50 |
| 144 functions below 46 each |  | 1184 | 1326 |

#### `ubench.ipc_rt words=64 cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `__copy_user_fault_end` | kernel | 8 | 8204 |
| `__copy_user_fault_start` | kernel | 2052 | 4096 |
| `memset` | kernel | 2268 | 452 |
| `__copy_user` | kernel | 12 | 2060 |
| `compiler_builtins::mem::memcpy` | ubench | | 1780 |
| `ipc::ipc_call_timeout` | ubench | 654 | 765 |
| `compiler_builtins::mem::memcpy` | kernel | | 762 |
| `memset` | ubench | 93 | 667 |
| `ipc::ipc_reply` | ubench | 416 | 415 |
| `memcpy` | ubench | 411 | 10 |
| `compiler_builtins::mem::memmove` | kernel | | 385 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | 372 |
| `ipc::ipc_recv_timeout` | ubench | 255 | 368 |
| `memcpy` | kernel | 264 | 4 |
| `kernel::sched::schedule` | kernel | 192 | 236 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 186 | |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | 153 |
| `<page 0x8000c000>` | other | | 134 |
| 167 functions below 118 each |  | 2267 | 2776 |

#### `ubench.fault_fill path=fault pages=16 cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `memset` | memmgr | 8298 | 24812 |
| `memset` | kernel | 2175 | 284 |
| `boot_protocol::riscv_paging::level_shift` | kernel | | 2136 |
| `<memmgr::MappedSlots as memmgr_free_pool::arena::SlotStore>::read` | memmgr | 1320 | 1481 |
| `<kernel::mm::address_space::AddressSpace>::map_page_pooled` | kernel | 576 | 1472 |
| `kernel::arch::current::paging::install_user_leaf` | kernel | | 1216 |
| `<kernel::mm::frame_map::FrameMap>::counter` | kernel | 896 | 1168 |
| `kernel::arch::current::paging::entry` | kernel | 48 | 1161 |
| `compiler_builtins::mem::memcpy` | memmgr | | 1119 |
| `compiler_builtins::mem::memcpy` | kernel | | 1072 |
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
| `<kernel::mm::address_space::AddressSpace>::pt_lock` | kernel | 144 | 400 |
| `<kernel::arch::current::paging::PageTableEntry>::new_page` | kernel | 352 | 384 |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | 381 |
| `kernel::arch::current::cpu::current_cpu` | kernel | 223 | 378 |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 192 | 374 |
| `memmgr_free_pool::chunk::child::<memmgr::MappedSlots>` | memmgr | 369 | 363 |
| `memmgr_free_pool::chunk::leaf::<memmgr::MappedSlots>` | memmgr | 369 | 225 |
| 411 functions below 303 each |  | 13246 | 13628 |

#### `ubench.fault_fill path=grant pages=16 cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `memset` | memmgr | 8388 | 25041 |
| `compiler_builtins::mem::memcpy` | memmgr | | 2846 |
| `memset` | kernel | 2268 | 522 |
| `boot_protocol::riscv_paging::level_shift` | kernel | | 2112 |
| `<kernel::mm::address_space::AddressSpace>::map_page_pooled` | kernel | 576 | 1472 |
| `compiler_builtins::mem::memcpy` | kernel | | 1220 |
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
| `<memmgr::MappedSlots as memmgr_free_pool::arena::SlotStore>::read` | memmgr | 522 | 646 |
| `<kernel::mm::frame_map::FrameMap>::raise` | kernel | 288 | 640 |
| `kernel::mm::tlb_shootdown::shootdown_range` | kernel | 416 | 640 |
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
| `compiler_builtins::mem::memmove` | kernel | | 385 |
| `<kernel::arch::current::paging::PageTableEntry>::new_page` | kernel | 352 | 384 |
| 440 functions below 324 each |  | 14309 | 15887 |

#### `ubench.fault_scaling threads=1 pages=16 cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `memset` | memmgr | 8298 | 24812 |
| `memset` | kernel | 2175 | 284 |
| `boot_protocol::riscv_paging::level_shift` | kernel | | 2136 |
| `<kernel::mm::address_space::AddressSpace>::map_page_pooled` | kernel | 576 | 1472 |
| `<memmgr::MappedSlots as memmgr_free_pool::arena::SlotStore>::read` | memmgr | 1248 | 1400 |
| `kernel::arch::current::paging::install_user_leaf` | kernel | | 1216 |
| `<kernel::mm::frame_map::FrameMap>::counter` | kernel | 896 | 1168 |
| `kernel::arch::current::paging::entry` | kernel | 48 | 1161 |
| `compiler_builtins::mem::memcpy` | memmgr | | 1119 |
| `compiler_builtins::mem::memcpy` | kernel | | 1072 |
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
| `<kernel::mm::address_space::AddressSpace>::pt_lock` | kernel | 144 | 400 |
| `<kernel::arch::current::paging::PageTableEntry>::new_page` | kernel | 352 | 384 |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | 381 |
| `kernel::arch::current::cpu::current_cpu` | kernel | 223 | 378 |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 192 | 374 |
| `memmgr_free_pool::chunk::child::<memmgr::MappedSlots>` | memmgr | 369 | 363 |
| `memmgr_free_pool::chunk::leaf::<memmgr::MappedSlots>` | memmgr | 369 | 225 |
| 413 functions below 303 each |  | 13211 | 13622 |

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
| 249 functions below 13879 each |  | 11851 | 17023 |

#### `ubench.console_write bytes=4096 cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `compiler_builtins::mem::memmove` | /services/drivers/framebuffer | | 143361600 |
| `memmove` | /services/drivers/framebuffer | 28673472 | 128 |
| `<framebuffer::render::FramebufferWriter>::scroll` | /services/drivers/framebuffer | 9013440 | 19662656 |
| `<framebuffer::render::FramebufferWriter>::draw_glyph_bitmap` | /services/drivers/framebuffer | 7156800 | 12820888 |
| `<framebuffer::render::FramebufferWriter>::pixel_bytes` | /services/drivers/framebuffer | 3709440 | 725760 |
| 307 functions below 885659 each |  | 412615 | 560853 |

#### `fsbench.read size=16 path=inline cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `memset` | fatfs:/ | 1154 | 3553 |
| `memset` | kernel | 2268 | 452 |
| `compiler_builtins::mem::memcpy` | fatfs:/ | | 1598 |
| `compiler_builtins::mem::memcpy` | kernel | | 829 |
| `compiler_builtins::mem::memcpy` | /programs/fsbench | | 759 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | 651 |
| `memset` | /programs/fsbench | 87 | 434 |
| `memcpy` | fatfs:/ | 398 | 16 |
| `compiler_builtins::mem::memmove` | kernel | | 385 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 310 | |
| `memcpy` | kernel | 301 | 8 |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | 268 |
| `<page 0x8000c000>` | other | | 268 |
| `kernel::sched::schedule` | kernel | 190 | 240 |
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
| `<kernel::sync::Spinlock>::lock_raw` | kernel | 100 | 68 |
| `kernel::syscall::dispatch_in_range` | kernel | 95 | 85 |
| `<kernel::sched::run_queue::PerCpuScheduler>::dequeue_highest` | kernel | 32 | 92 |
| `kernel::arch::current::context::switch` | kernel | 92 | 74 |
| `kernel::sched::scheduler_for` | kernel | 73 | 92 |
| `kernel::syscall::pin_checked` | kernel | 84 | 90 |
| `kernel::syscall::ipc::sys_ipc_call` | kernel | 75 | 89 |
| `<kernel::mm::address_space::AddressSpace>::activate` | kernel | 6 | 88 |
| `kernel::arch::current::cpu::current_cpu` | kernel | 81 | 62 |
| `kernel::arch::current::idt::isr_nm` | kernel | 80 | |
| `kernel::sched::enqueue_and_wake` | kernel | 58 | 78 |
| `fatfs::handle_read` | fatfs:/ | 66 | 75 |
| `kernel::syscall::ipc::sys_ipc_recv` | kernel | 45 | 72 |
| `kernel::syscall::ipc::sys_ipc_reply` | kernel | 53 | 72 |
| 221 functions below 72 each |  | 2358 | 2836 |

#### `fsbench.read size=16 path=frame cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `<std::fs::File as alloc::io::read::Read>::read` | /programs/fsbench | 10407 | 24744 |
| `crypto::keccak::keccak_f1600` | kernel | 12628 | 12530 |
| `memset` | kernel | 4627 | 1095 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | 2325 |
| `compiler_builtins::mem::memcpy` | fatfs:/ | | 1816 |
| `compiler_builtins::mem::memcpy` | kernel | | 1703 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 1302 | |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | 954 |
| `memset` | /programs/fsbench | 175 | 871 |
| `compiler_builtins::mem::memmove` | kernel | | 770 |
| `compiler_builtins::mem::memcpy` | /programs/fsbench | | 769 |
| `<kernel::cap::cspace::CSpace>::slot_mut` | kernel | 456 | 690 |
| `memset` | fatfs:/ | | 651 |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 360 | 616 |
| `memcpy` | kernel | 599 | 16 |
| `kernel::syscall::pin_checked` | kernel | 343 | 585 |
| `<page 0x8000c000>` | other | | 536 |
| `kernel::sched::scheduler_ptr` | kernel | 158 | 521 |
| `kernel::arch::current::interrupts::handle_trap` | kernel | | 484 |
| `kernel::syscall::dispatch` | kernel | 483 | 168 |
| `kernel::sched::schedule` | kernel | 380 | 480 |
| `kernel::ipc::upcall::deliver` | kernel | | 462 |
| `<fatfs::session::SessionPages>::va` | fatfs:/ | 436 | 356 |
| `memcpy` | fatfs:/ | 416 | 12 |
| `<page 0x80000000>` | other | | 416 |
| `kernel::syscall::dispatch_in_range` | kernel | 411 | 355 |
| `<kernel::cap::cspace::CSpace>::leaf_ptr` | kernel | 204 | 408 |
| `kernel::sched::scheduler_for` | kernel | 289 | 360 |
| 453 functions below 359 each |  | 15325 | 17218 |

#### `fsbench.read size=1024 path=inline cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `memset` | fatfs:/ | 4616 | 14212 |
| `compiler_builtins::mem::memcpy` | fatfs:/ | | 13690 |
| `memset` | kernel | 9072 | 1808 |
| `__copy_user_fault_end` | kernel | 8 | 8204 |
| `__copy_user_fault_start` | kernel | 2052 | 4096 |
| `memcpy` | fatfs:/ | 3712 | 300 |
| `compiler_builtins::mem::memcpy` | /programs/fsbench | | 3696 |
| `compiler_builtins::mem::memcpy` | kernel | | 3234 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | 2604 |
| `fatfs::handle_read` | fatfs:/ | 2304 | 1980 |
| `__copy_user` | kernel | 12 | 2060 |
| `memset` | /programs/fsbench | 348 | 1736 |
| `compiler_builtins::mem::memmove` | kernel | | 1540 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 1240 | |
| `std::os::seraph::memmgr_call` | /programs/fsbench | 854 | 1170 |
| `memcpy` | kernel | 1164 | 28 |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | 1072 |
| `<page 0x8000c000>` | other | | 1072 |
| `kernel::sched::schedule` | kernel | 760 | 960 |
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
| 238 functions below 415 each |  | 12633 | 14771 |

#### `fsbench.read size=1024 path=frame cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `<std::fs::File as alloc::io::read::Read>::read` | /programs/fsbench | 10407 | 24744 |
| `crypto::keccak::keccak_f1600` | kernel | 12628 | 12530 |
| `memset` | kernel | 4627 | 1095 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | 2325 |
| `compiler_builtins::mem::memcpy` | fatfs:/ | | 1816 |
| `compiler_builtins::mem::memcpy` | kernel | | 1703 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 1302 | |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | 954 |
| `memset` | /programs/fsbench | 175 | 871 |
| `compiler_builtins::mem::memmove` | kernel | | 770 |
| `compiler_builtins::mem::memcpy` | /programs/fsbench | | 769 |
| `<kernel::cap::cspace::CSpace>::slot_mut` | kernel | 456 | 690 |
| `memset` | fatfs:/ | | 651 |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 360 | 616 |
| `memcpy` | kernel | 599 | 16 |
| `kernel::syscall::pin_checked` | kernel | 343 | 585 |
| `<page 0x8000c000>` | other | | 536 |
| `kernel::sched::scheduler_ptr` | kernel | 158 | 521 |
| `kernel::arch::current::interrupts::handle_trap` | kernel | | 484 |
| `kernel::syscall::dispatch` | kernel | 483 | 168 |
| `kernel::sched::schedule` | kernel | 380 | 480 |
| `kernel::ipc::upcall::deliver` | kernel | | 462 |
| `<fatfs::session::SessionPages>::va` | fatfs:/ | 436 | 356 |
| `memcpy` | fatfs:/ | 416 | 12 |
| `<page 0x80000000>` | other | | 416 |
| `kernel::syscall::dispatch_in_range` | kernel | 411 | 355 |
| `<kernel::cap::cspace::CSpace>::leaf_ptr` | kernel | 204 | 408 |
| `kernel::sched::scheduler_for` | kernel | 289 | 360 |
| 453 functions below 359 each |  | 15325 | 17218 |

#### `fsbench.read size=4096 path=inline cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `memset` | fatfs:/ | 18464 | 56848 |
| `compiler_builtins::mem::memcpy` | fatfs:/ | | 54760 |
| `memset` | kernel | 36288 | 7232 |
| `__copy_user_fault_end` | kernel | 32 | 32816 |
| `__copy_user_fault_start` | kernel | 8208 | 16384 |
| `memcpy` | fatfs:/ | 14848 | 1200 |
| `compiler_builtins::mem::memcpy` | /programs/fsbench | | 14784 |
| `compiler_builtins::mem::memcpy` | kernel | | 12936 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | 10416 |
| `fatfs::handle_read` | fatfs:/ | 9216 | 7920 |
| `__copy_user` | kernel | 48 | 8240 |
| `memset` | /programs/fsbench | 1392 | 6944 |
| `compiler_builtins::mem::memmove` | kernel | | 6160 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 4960 | |
| `std::os::seraph::memmgr_call` | /programs/fsbench | 3416 | 4680 |
| `memcpy` | kernel | 4656 | 112 |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | 4288 |
| `<page 0x8000c000>` | other | | 4288 |
| `kernel::sched::schedule` | kernel | 3040 | 3840 |
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
| 238 functions below 1661 each |  | 50397 | 58943 |

#### `fsbench.read size=4096 path=frame cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `<std::fs::File as alloc::io::read::Read>::read` | /programs/fsbench | 10407 | 24744 |
| `crypto::keccak::keccak_f1600` | kernel | 12628 | 12530 |
| `memset` | kernel | 4627 | 1095 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | 2325 |
| `compiler_builtins::mem::memcpy` | fatfs:/ | | 1816 |
| `compiler_builtins::mem::memcpy` | kernel | | 1703 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 1302 | |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | 954 |
| `memset` | /programs/fsbench | 175 | 871 |
| `compiler_builtins::mem::memmove` | kernel | | 770 |
| `compiler_builtins::mem::memcpy` | /programs/fsbench | | 769 |
| `<kernel::cap::cspace::CSpace>::slot_mut` | kernel | 456 | 690 |
| `memset` | fatfs:/ | | 651 |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 360 | 616 |
| `memcpy` | kernel | 599 | 16 |
| `kernel::syscall::pin_checked` | kernel | 343 | 585 |
| `<page 0x8000c000>` | other | | 536 |
| `kernel::sched::scheduler_ptr` | kernel | 158 | 521 |
| `kernel::arch::current::interrupts::handle_trap` | kernel | | 484 |
| `kernel::syscall::dispatch` | kernel | 483 | 168 |
| `kernel::sched::schedule` | kernel | 380 | 480 |
| `kernel::ipc::upcall::deliver` | kernel | | 462 |
| `<fatfs::session::SessionPages>::va` | fatfs:/ | 436 | 356 |
| `memcpy` | fatfs:/ | 416 | 12 |
| `<page 0x80000000>` | other | | 416 |
| `kernel::syscall::dispatch_in_range` | kernel | 411 | 355 |
| `<kernel::cap::cspace::CSpace>::leaf_ptr` | kernel | 204 | 408 |
| `kernel::sched::scheduler_for` | kernel | 289 | 360 |
| 453 functions below 359 each |  | 15325 | 17218 |

#### `fsbench.read size=16384 path=inline cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `memset` | fatfs:/ | 73856 | 227392 |
| `compiler_builtins::mem::memcpy` | fatfs:/ | | 219040 |
| `memset` | kernel | 145152 | 28928 |
| `__copy_user_fault_end` | kernel | 128 | 131264 |
| `__copy_user_fault_start` | kernel | 32832 | 65536 |
| `memcpy` | fatfs:/ | 59384 | 4800 |
| `compiler_builtins::mem::memcpy` | /programs/fsbench | | 59136 |
| `compiler_builtins::mem::memcpy` | kernel | | 51744 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | 41757 |
| `fatfs::handle_read` | fatfs:/ | 36864 | 31680 |
| `__copy_user` | kernel | 192 | 32960 |
| `memset` | /programs/fsbench | 5568 | 27776 |
| `compiler_builtins::mem::memmove` | kernel | | 24640 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 19840 | |
| `std::os::seraph::memmgr_call` | /programs/fsbench | 13664 | 18720 |
| `memcpy` | kernel | 18624 | 448 |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | 17192 |
| `<page 0x8000c000>` | other | | 17152 |
| `kernel::sched::schedule` | kernel | 12160 | 15360 |
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
| 273 functions below 6717 each |  | 213988 | 249920 |

#### `fsbench.read size=16384 path=frame cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `<std::fs::File as alloc::io::read::Read>::read` | /programs/fsbench | 41628 | 98976 |
| `crypto::keccak::keccak_f1600` | kernel | 50512 | 50120 |
| `memset` | kernel | 18508 | 4380 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | 9300 |
| `compiler_builtins::mem::memcpy` | fatfs:/ | | 7264 |
| `compiler_builtins::mem::memcpy` | kernel | | 6812 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 5208 | |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | 3816 |
| `memset` | /programs/fsbench | 700 | 3484 |
| `compiler_builtins::mem::memmove` | kernel | | 3080 |
| `compiler_builtins::mem::memcpy` | /programs/fsbench | | 3076 |
| `<kernel::cap::cspace::CSpace>::slot_mut` | kernel | 1824 | 2760 |
| `memset` | fatfs:/ | | 2604 |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 1440 | 2464 |
| `memcpy` | kernel | 2396 | 64 |
| `kernel::syscall::pin_checked` | kernel | 1372 | 2340 |
| `<page 0x8000c000>` | other | | 2144 |
| `kernel::sched::scheduler_ptr` | kernel | 632 | 2084 |
| `kernel::arch::current::interrupts::handle_trap` | kernel | | 1936 |
| `kernel::syscall::dispatch` | kernel | 1932 | 672 |
| `kernel::sched::schedule` | kernel | 1520 | 1920 |
| `kernel::ipc::upcall::deliver` | kernel | | 1848 |
| `<fatfs::session::SessionPages>::va` | fatfs:/ | 1744 | 1424 |
| `memcpy` | fatfs:/ | 1664 | 48 |
| `<page 0x80000000>` | other | | 1664 |
| `kernel::syscall::dispatch_in_range` | kernel | 1644 | 1420 |
| `<kernel::cap::cspace::CSpace>::leaf_ptr` | kernel | 816 | 1632 |
| 462 functions below 1441 each |  | 62940 | 70877 |

#### `fsbench.read size=65536 path=inline cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `memset` | fatfs:/ | 295409 | 909568 |
| `compiler_builtins::mem::memcpy` | fatfs:/ | | 876154 |
| `memset` | kernel | 580608 | 115712 |
| `__copy_user_fault_end` | kernel | 512 | 525056 |
| `__copy_user_fault_start` | kernel | 131328 | 262144 |
| `memcpy` | fatfs:/ | 237568 | 19200 |
| `compiler_builtins::mem::memcpy` | /programs/fsbench | | 236544 |
| `compiler_builtins::mem::memcpy` | kernel | | 206976 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | 167214 |
| `fatfs::handle_read` | fatfs:/ | 147442 | 126720 |
| `__copy_user` | kernel | 768 | 131840 |
| `memset` | /programs/fsbench | 22272 | 111104 |
| `fatfs::fat::chain_next` | fatfs:/ | 99840 | 96000 |
| `compiler_builtins::mem::memmove` | kernel | | 98560 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 79360 | |
| `fatfs::alloc::read_fat_entry` | fatfs:/ | 36480 | 76800 |
| `std::os::seraph::memmgr_call` | /programs/fsbench | 54656 | 74880 |
| `memcpy` | kernel | 74496 | 1792 |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | 68848 |
| `<page 0x8000c000>` | other | | 68608 |
| `kernel::sched::schedule` | kernel | 48640 | 61440 |
| `ipc::ipc_reply` | fatfs:/ | 57587 | 59136 |
| `memcpy` | /programs/fsbench | 58624 | 2048 |
| `<page 0x80000000>` | other | | 53248 |
| `fatfs::fat::read_file_data` | fatfs:/ | 40909 | 44800 |
| `kernel::sched::scheduler_ptr` | kernel | 11788 | 37168 |
| `<fatfs::bpb::FatState>::fat_entry_location` | fatfs:/ | 30720 | 34560 |
| `kernel::arch::current::interrupts::handle_trap` | kernel | | 33876 |
| `<std::fs::File as alloc::io::read::Read>::read` | /programs/fsbench | 24576 | 31744 |
| `fatfs::service_loop` | fatfs:/ | 29934 | 29296 |
| `kernel::syscall::dispatch` | kernel | 29440 | 10240 |
| `kernel::ipc::upcall::deliver` | kernel | 18 | 28292 |
| 278 functions below 27945 each |  | 830905 | 989625 |

#### `fsbench.read size=65536 path=frame cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `<std::fs::File as alloc::io::read::Read>::read` | /programs/fsbench | 166512 | 395904 |
| `crypto::keccak::keccak_f1600` | kernel | 202048 | 200480 |
| `memset` | kernel | 74032 | 17520 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | 37293 |
| `compiler_builtins::mem::memcpy` | fatfs:/ | | 29056 |
| `compiler_builtins::mem::memcpy` | kernel | | 27248 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 20832 | |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | 15304 |
| `memset` | /programs/fsbench | 2800 | 13936 |
| `compiler_builtins::mem::memmove` | kernel | | 12320 |
| `compiler_builtins::mem::memcpy` | /programs/fsbench | | 12304 |
| `<kernel::cap::cspace::CSpace>::slot_mut` | kernel | 7296 | 11040 |
| `memset` | fatfs:/ | | 10416 |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 5760 | 9856 |
| `memcpy` | kernel | 9584 | 256 |
| `kernel::syscall::pin_checked` | kernel | 5488 | 9360 |
| `<page 0x8000c000>` | other | | 8576 |
| `kernel::sched::scheduler_ptr` | kernel | 2532 | 8344 |
| `kernel::arch::current::interrupts::handle_trap` | kernel | | 7758 |
| `kernel::syscall::dispatch` | kernel | 7728 | 2688 |
| `kernel::sched::schedule` | kernel | 6080 | 7680 |
| `kernel::ipc::upcall::deliver` | kernel | 6 | 7414 |
| `<fatfs::session::SessionPages>::va` | fatfs:/ | 6976 | 5696 |
| `memcpy` | fatfs:/ | 6656 | 192 |
| `<page 0x80000000>` | other | | 6656 |
| `kernel::syscall::dispatch_in_range` | kernel | 6576 | 5680 |
| `<kernel::cap::cspace::CSpace>::leaf_ptr` | kernel | 3264 | 6528 |
| 491 functions below 5780 each |  | 254549 | 286567 |

#### `fsbench.open depth=3 cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `memset` | fatfs:/ | 5251 | 15155 |
| `crypto::keccak::keccak_f1600` | kernel | 12628 | 12530 |
| `compiler_builtins::mem::memcpy` | fatfs:/ | | 8746 |
| `memset` | kernel | 6895 | 1547 |
| `<fatfs_parse::LfnAccum>::add_lfn_entry` | fatfs:/ | 4528 | 4736 |
| `fatfs::dir::scan_sector_for_name` | fatfs:/ | 3303 | 4025 |
| `compiler_builtins::mem::memcpy` | /programs/fsbench | | 3420 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | 3162 |
| `<fatfs_parse::LfnAccum>::assemble_utf8` | fatfs:/ | 3065 | 2335 |
| `compiler_builtins::mem::memcpy` | kernel | | 2639 |
| `compiler_builtins::mem::memcpy` | vfsd | | 2359 |
| `<kernel::cap::cspace::CSpace>::slot_mut` | kernel | 1248 | 2092 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 1736 | |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 924 | 1516 |
| `memcpy` | fatfs:/ | 1364 | 62 |
| `memset` | /programs/fsbench | 260 | 1299 |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | 1298 |
| `<fatfs::cache::PageCache>::lookup_cached` | fatfs:/ | 618 | 1283 |
| `compiler_builtins::mem::memmove` | kernel | | 1155 |
| `<kernel::cap::cspace::CSpace>::leaf_ptr` | kernel | 543 | 1086 |
| `std::sys::fs::seraph::walk_components` | /programs/fsbench | 958 | 891 |
| `std::sys::alloc::seraph::alloc` | fatfs:/ | 948 | 666 |
| `kernel::syscall::pin_checked` | kernel | 535 | 945 |
| `memcpy` | kernel | 939 | 28 |
| `kernel::arch::nospec::select_ptr::<kernel::cap::cspace::CSpacePage>` | kernel | 724 | 905 |
| `memcpy` | /programs/fsbench | 861 | 32 |
| `<page 0x8000c000>` | other | | 804 |
| `<fatfs::cache::PageCache>::pages_held` | fatfs:/ | 781 | 775 |
| `<fatfs_parse::LfnAccum>::matches` | fatfs:/ | 777 | |
| `<fatfs::cache::PageCache>::pages_held::{closure#0}` | fatfs:/ | 256 | 768 |
| `<kernel::cap::registry::CSpaceRegistry>::entry` | kernel | 596 | 768 |
| `<kernel::cap::registry::CSpaceRegistry>::slot` | kernel | 636 | 757 |
| `kernel::sched::schedule` | kernel | 570 | 720 |
| `kernel::sched::scheduler_ptr` | kernel | 220 | 720 |
| `kernel::arch::current::speculation::index_mask` | kernel | 700 | 708 |
| `kernel::arch::current::interrupts::handle_trap` | kernel | | 656 |
| `memset` | vfsd | 88 | 651 |
| `kernel::syscall::dispatch` | kernel | 646 | 226 |
| `<page 0x80000000>` | other | | 624 |
| `kernel::ipc::upcall::deliver` | kernel | | 616 |
| `<kernel::cap::registry::CSpaceRegistry>::lookup` | kernel | 589 | 545 |
| `memcpy` | vfsd | 584 | 22 |
| 434 functions below 554 each |  | 23677 | 27710 |

<!-- path-account: end -->

---

## Summarized By

[core/kernel/README.md](../README.md), [Kernel Hot-Path Instruction Account](hot-path-account.md)
