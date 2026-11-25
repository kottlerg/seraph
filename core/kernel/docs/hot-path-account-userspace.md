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

`ubench.ipc_rt words=0` is 2857 / 5512, 2201 / 2807 of it in the kernel. The kernel copies and
zeroes no whole `Message` on either side: its largest functions are the entries
(`syscall_entry` 186 on x86_64; `trap_entry` and `trap_dispatch`, 372 and 154, on riscv64) and
`schedule` (168 / 222). On riscv64 ubench moves the message through `compiler_builtins`' word
loops (`memcpy` 1448, `memset` 667), and the firmware's pages take 353 (`other`). On x86_64
each round trip also takes the lazy FPU switch's `#NM` trap once a thread is switched back in
(`isr_nm` and its handler, 114).

### Page Faults

`ubench.fault_fill path=fault pages=16` is 33884 / 58164: memmgr 14084 / 31714, of which its
`memset` zeroing the 16 frames is 8298 / 24812 (x86_64's `rep stos` is about one iteration per 8
bytes, riscv64's loop about one instruction per 2.6 bytes), and the kernel 19789 / 26442, spread
over the page-table walk and install (`level_shift`, `table_index`, `names_table`, `read_entry`,
`install_user_leaf`), the frame map's counters, and `sys_mem_map`. `fault_scaling threads=1` runs
the same path. `path=grant` adds the grant's capability operations, 33882 / 61195.

### Shared-Memory Ring

`ubench.shmem_ring` runs in ubench alone: `shmem_ring::transfer` is 49342 / 57448 of the
4096-byte transfer, about 12 / 14 instructions per byte.

### Console Writes

`ubench.console_write bytes=4096` is 48940764 / 177056209, all but 0.2 % in the framebuffer
driver. Its scroll moves the whole framebuffer up a text row at each line it fills
(`memmove` 28673472 / 143361728 and `FramebufferWriter::scroll` 9013440 / 19662656), and
drawing the glyphs is 7156800 / 12820888.

### File Reads and Opens

A read through the inline path (`fsbench.read path=inline`) is fatfs's copy and zeroing of the reply
and the kernel's copy to and from user memory. A read through granted frames (`path=frame`) spends
12628 / 12530 in the kernel's Keccak permutation (`keccak_f1600`) per 4 KiB frame the grant names,
202048 / 200480 of 677675 / 1063109 at 64 KiB: std draws each request's 8-byte cookie through
`SYS_GETRANDOM`, fresh output with its own squeeze and ratchet
([entropy.md](entropy.md) § Draw API and consumers). `fsbench.open depth=3` is 66281 / 100880, one
such draw (12628 / 12530, the release badge `File::open` allocates) and
fatfs's long-name parsing (`LfnAccum`, 7670 / 6478) among it.

## Account

<!-- path-account: begin; generated by cargo xtask path-account write -->

| Configuration | Head | Taken | QEMU | Checked against |
|---|---|---|---|---|
| x86_64 release | `0cd44ea479dd` | 2026-11-25 | QEMU emulator version 11.1.3 | 1 icount boot(s) of the image without debuginfo |
| riscv64 release | `0cd44ea479dd` | 2026-11-25 | QEMU emulator version 11.1.3 | 1 icount boot(s) of the image without debuginfo |

#### Totals

| Path | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `ubench.ipc_rt words=0 cpus=1` | all | 2857 | 5512 |
| `ubench.ipc_rt words=0 cpus=1` | ubench | 656 | 2352 |
| `ubench.ipc_rt words=0 cpus=1` | kernel | 2201 | 2807 |
| `ubench.ipc_rt words=0 cpus=1` | other | 0 | 353 |
| `ubench.ipc_rt words=6 cpus=1` | all | 3103 | 6571 |
| `ubench.ipc_rt words=6 cpus=1` | ubench | 757 | 2574 |
| `ubench.ipc_rt words=6 cpus=1` | kernel | 2346 | 3291 |
| `ubench.ipc_rt words=6 cpus=1` | other | 0 | 706 |
| `ubench.ipc_rt words=7 cpus=1` | all | 3352 | 6035 |
| `ubench.ipc_rt words=7 cpus=1` | ubench | 842 | 2560 |
| `ubench.ipc_rt words=7 cpus=1` | kernel | 2510 | 3122 |
| `ubench.ipc_rt words=7 cpus=1` | other | 0 | 353 |
| `ubench.ipc_rt words=64 cpus=1` | all | 6330 | 8329 |
| `ubench.ipc_rt words=64 cpus=1` | ubench | 1939 | 4099 |
| `ubench.ipc_rt words=64 cpus=1` | kernel | 4391 | 3877 |
| `ubench.ipc_rt words=64 cpus=1` | other | 0 | 353 |
| `ubench.fault_fill path=fault pages=16 cpus=1` | all | 33884 | 58164 |
| `ubench.fault_fill path=fault pages=16 cpus=1` | ubench | 11 | 8 |
| `ubench.fault_fill path=fault pages=16 cpus=1` | memmgr | 14084 | 31714 |
| `ubench.fault_fill path=fault pages=16 cpus=1` | kernel | 19789 | 26442 |
| `ubench.fault_fill path=grant pages=16 cpus=1` | all | 33882 | 61195 |
| `ubench.fault_fill path=grant pages=16 cpus=1` | ubench | 115 | 353 |
| `ubench.fault_fill path=grant pages=16 cpus=1` | memmgr | 11173 | 30183 |
| `ubench.fault_fill path=grant pages=16 cpus=1` | kernel | 22594 | 30306 |
| `ubench.fault_fill path=grant pages=16 cpus=1` | other | 0 | 353 |
| `ubench.fault_scaling threads=1 pages=16 cpus=1` | all | 33743 | 58077 |
| `ubench.fault_scaling threads=1 pages=16 cpus=1` | ubench | 11 | 8 |
| `ubench.fault_scaling threads=1 pages=16 cpus=1` | memmgr | 13943 | 31618 |
| `ubench.fault_scaling threads=1 pages=16 cpus=1` | kernel | 19789 | 26451 |
| `ubench.shmem_ring bytes=64 cpus=1` | all | 219 | 103 |
| `ubench.shmem_ring bytes=64 cpus=1` | ubench | 219 | 103 |
| `ubench.shmem_ring bytes=512 cpus=1` | all | 207 | 383 |
| `ubench.shmem_ring bytes=512 cpus=1` | ubench | 207 | 383 |
| `ubench.shmem_ring bytes=4096 cpus=1` | all | 49353 | 57455 |
| `ubench.shmem_ring bytes=4096 cpus=1` | ubench | 49353 | 57455 |
| `ubench.shmem_ring bytes=65536 cpus=1` | all | 789827 | 919512 |
| `ubench.shmem_ring bytes=65536 cpus=1` | ubench | 789423 | 919115 |
| `ubench.shmem_ring bytes=65536 cpus=1` | kernel | 404 | 397 |
| `ubench.console_write bytes=64 cpus=1` | all | 767744 | 2773127 |
| `ubench.console_write bytes=64 cpus=1` | ubench | 989 | 3098 |
| `ubench.console_write bytes=64 cpus=1` | /services/drivers/framebuffer | 763764 | 2764543 |
| `ubench.console_write bytes=64 cpus=1` | kernel | 2991 | 4780 |
| `ubench.console_write bytes=64 cpus=1` | other | 0 | 706 |
| `ubench.console_write bytes=4096 cpus=1` | all | 48940764 | 177056209 |
| `ubench.console_write bytes=4096 cpus=1` | ubench | 25251 | 60078 |
| `ubench.console_write bytes=4096 cpus=1` | /services/drivers/framebuffer | 48865048 | 176873272 |
| `ubench.console_write bytes=4096 cpus=1` | /services/drivers/iommu-riscv | 0 | 119 |
| `ubench.console_write bytes=4096 cpus=1` | /services/drivers/iommu-vtd | 63 | 0 |
| `ubench.console_write bytes=4096 cpus=1` | kernel | 50402 | 117092 |
| `ubench.console_write bytes=4096 cpus=1` | other | 0 | 5648 |
| `fsbench.read size=16 path=inline cpus=1` | all | 5799 | 12385 |
| `fsbench.read size=16 path=inline cpus=1` | /tests/fixtures/programs/fsbench | 583 | 1547 |
| `fsbench.read size=16 path=inline cpus=1` | fatfs:/ | 2344 | 5967 |
| `fsbench.read size=16 path=inline cpus=1` | fatfs:/data | 1 | 1 |
| `fsbench.read size=16 path=inline cpus=1` | kernel | 2871 | 4103 |
| `fsbench.read size=16 path=inline cpus=1` | other | 0 | 767 |
| `fsbench.read size=16 path=frame cpus=1` | all | 42061 | 66103 |
| `fsbench.read size=16 path=frame cpus=1` | /tests/fixtures/programs/fsbench | 11334 | 27048 |
| `fsbench.read size=16 path=frame cpus=1` | fatfs:/ | 4226 | 5986 |
| `fsbench.read size=16 path=frame cpus=1` | fatfs:/data | 27 | 27 |
| `fsbench.read size=16 path=frame cpus=1` | kernel | 26474 | 31508 |
| `fsbench.read size=16 path=frame cpus=1` | other | 0 | 1534 |
| `fsbench.read size=1024 path=inline cpus=1` | all | 30461 | 61025 |
| `fsbench.read size=1024 path=inline cpus=1` | /tests/fixtures/programs/fsbench | 2667 | 7273 |
| `fsbench.read size=1024 path=inline cpus=1` | fatfs:/ | 14300 | 33852 |
| `fsbench.read size=1024 path=inline cpus=1` | fatfs:/data | 4 | 4 |
| `fsbench.read size=1024 path=inline cpus=1` | kernel | 13490 | 16950 |
| `fsbench.read size=1024 path=inline cpus=1` | other | 0 | 2946 |
| `fsbench.read size=1024 path=frame cpus=1` | all | 42061 | 66103 |
| `fsbench.read size=1024 path=frame cpus=1` | /tests/fixtures/programs/fsbench | 11334 | 27048 |
| `fsbench.read size=1024 path=frame cpus=1` | fatfs:/ | 4226 | 5986 |
| `fsbench.read size=1024 path=frame cpus=1` | fatfs:/data | 27 | 27 |
| `fsbench.read size=1024 path=frame cpus=1` | kernel | 26474 | 31508 |
| `fsbench.read size=1024 path=frame cpus=1` | other | 0 | 1534 |
| `fsbench.read size=4096 path=inline cpus=1` | all | 121709 | 243959 |
| `fsbench.read size=4096 path=inline cpus=1` | /tests/fixtures/programs/fsbench | 10533 | 28951 |
| `fsbench.read size=4096 path=inline cpus=1` | fatfs:/ | 57200 | 135408 |
| `fsbench.read size=4096 path=inline cpus=1` | fatfs:/data | 16 | 16 |
| `fsbench.read size=4096 path=inline cpus=1` | kernel | 53960 | 67800 |
| `fsbench.read size=4096 path=inline cpus=1` | other | 0 | 11784 |
| `fsbench.read size=4096 path=frame cpus=1` | all | 42061 | 66103 |
| `fsbench.read size=4096 path=frame cpus=1` | /tests/fixtures/programs/fsbench | 11334 | 27048 |
| `fsbench.read size=4096 path=frame cpus=1` | fatfs:/ | 4226 | 5986 |
| `fsbench.read size=4096 path=frame cpus=1` | fatfs:/data | 27 | 27 |
| `fsbench.read size=4096 path=frame cpus=1` | kernel | 26474 | 31508 |
| `fsbench.read size=4096 path=frame cpus=1` | other | 0 | 1534 |
| `fsbench.read size=16384 path=inline cpus=1` | all | 498845 | 990174 |
| `fsbench.read size=16384 path=inline cpus=1` | /tests/fixtures/programs/fsbench | 41997 | 115663 |
| `fsbench.read size=16384 path=inline cpus=1` | fatfs:/ | 240944 | 555696 |
| `fsbench.read size=16384 path=inline cpus=1` | fatfs:/data | 64 | 64 |
| `fsbench.read size=16384 path=inline cpus=1` | kernel | 215840 | 271615 |
| `fsbench.read size=16384 path=inline cpus=1` | other | 0 | 47136 |
| `fsbench.read size=16384 path=frame cpus=1` | all | 168728 | 264977 |
| `fsbench.read size=16384 path=frame cpus=1` | /tests/fixtures/programs/fsbench | 45201 | 108051 |
| `fsbench.read size=16384 path=frame cpus=1` | fatfs:/ | 17523 | 24638 |
| `fsbench.read size=16384 path=frame cpus=1` | fatfs:/data | 108 | 120 |
| `fsbench.read size=16384 path=frame cpus=1` | kernel | 105896 | 126032 |
| `fsbench.read size=16384 path=frame cpus=1` | other | 0 | 6136 |
| `fsbench.read size=65536 path=inline cpus=1` | all | 2179559 | 4175039 |
| `fsbench.read size=65536 path=inline cpus=1` | /tests/fixtures/programs/fsbench | 167853 | 462511 |
| `fsbench.read size=65536 path=inline cpus=1` | fatfs:/ | 1147280 | 2436996 |
| `fsbench.read size=65536 path=inline cpus=1` | fatfs:/data | 256 | 268 |
| `fsbench.read size=65536 path=inline cpus=1` | kernel | 864170 | 1086720 |
| `fsbench.read size=65536 path=inline cpus=1` | other | 0 | 188544 |
| `fsbench.read size=65536 path=frame cpus=1` | all | 677675 | 1063109 |
| `fsbench.read size=65536 path=frame cpus=1` | /tests/fixtures/programs/fsbench | 180669 | 432063 |
| `fsbench.read size=65536 path=frame cpus=1` | fatfs:/ | 72585 | 101516 |
| `fsbench.read size=65536 path=frame cpus=1` | fatfs:/data | 432 | 444 |
| `fsbench.read size=65536 path=frame cpus=1` | kernel | 423989 | 504542 |
| `fsbench.read size=65536 path=frame cpus=1` | other | 0 | 24544 |
| `fsbench.open depth=3 cpus=1` | all | 66281 | 100880 |
| `fsbench.open depth=3 cpus=1` | /tests/fixtures/programs/fsbench | 3418 | 7171 |
| `fsbench.open depth=3 cpus=1` | fatfs:/ | 23921 | 41272 |
| `fsbench.open depth=3 cpus=1` | fatfs:/data | 19 | 83 |
| `fsbench.open depth=3 cpus=1` | vfsd | 1182 | 3579 |
| `fsbench.open depth=3 cpus=1` | kernel | 37741 | 46474 |
| `fsbench.open depth=3 cpus=1` | other | 0 | 2301 |

#### `ubench.ipc_rt words=0 cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `compiler_builtins::mem::memcpy` | ubench | | 1448 |
| `memset` | ubench | 93 | 667 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | 372 |
| `memcpy` | ubench | 347 | 10 |
| `kernel::sched::schedule` | kernel | 168 | 222 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 186 | |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | 154 |
| `<page 0x8000c000>` | other | | 134 |
| `<page 0x80000000>` | other | | 104 |
| `<kernel::sync::Spinlock>::lock_raw` | kernel | 99 | 68 |
| `<kernel::sched::run_queue::PerCpuScheduler>::dequeue_highest` | kernel | 32 | 92 |
| `kernel::arch::current::context::switch` | kernel | 92 | 74 |
| `kernel::syscall::pin_checked` | kernel | 84 | 90 |
| `kernel::arch::current::idt::isr_nm` | kernel | 80 | |
| `kernel::sched::enqueue_and_wake` | kernel | 58 | 78 |
| `kernel::arch::current::interrupts::handle_trap` | kernel | | 73 |
| `kernel::syscall::dispatch` | kernel | 69 | 21 |
| `kernel::syscall::ipc::sys_ipc_call` | kernel | 58 | 69 |
| `kernel::arch::current::fpu::save_fp_to` | kernel | | 68 |
| `ipc::ipc_call_timeout` | ubench | 48 | 61 |
| `kernel::arch::current::cpu::save_and_disable_interrupts` | kernel | 58 | 26 |
| `kernel::syscall::dispatch_in_range` | kernel | 57 | 45 |
| `ubench::ipc_rt::serve` | ubench | 57 | 52 |
| `kernel::arch::current::cpu::restore_interrupts` | kernel | 32 | 54 |
| `ipc::ipc_recv_timeout` | ubench | 36 | 51 |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 24 | 50 |
| `kernel::syscall::ipc::sys_ipc_reply` | kernel | 30 | 50 |
| `kernel::syscall::ipc::sys_ipc_recv` | kernel | 26 | 48 |
| `kernel::ipc::endpoint::endpoint_call` | kernel | 19 | 46 |
| `<page 0x80017000>` | other | | 45 |
| `<kernel::sched::run_queue::PerCpuScheduler>::link` | kernel | 44 | 42 |
| `kernel::sched::commit_blocked_under_local_lock` | kernel | 31 | 40 |
| `seraph_enter_from_user` | kernel | 40 | |
| `<kernel::sync::Spinlock>::unlock_raw` | kernel | 13 | 39 |
| `kernel::arch::current::fpu::switch_out_save` | kernel | 18 | 38 |
| `kernel::arch::current::fpu::save_v_to` | kernel | | 36 |
| `kernel::arch::current::encoding::ticks_to_us` | kernel | | 34 |
| `kernel::arch::current::fpu::restore_fp_from` | kernel | | 34 |
| `kernel::arch::current::idt::nm_handler` | kernel | 34 | |
| `kernel::ipc::endpoint::bind_next_sender` | kernel | 18 | 34 |
| `kernel::syscall::ipc::deliver_message` | kernel | 32 | 34 |
| `kernel::syscall::pin_checked::{closure#0}` | kernel | 24 | 34 |
| `memcpy` | kernel | 32 | 4 |
| `<kernel::arch::current::trap_frame::TrapFrame>::arg` | kernel | 30 | 6 |
| `<kernel::ipc::message::Message>::caps` | kernel | 28 | 26 |
| 132 functions below 27 each |  | 760 | 839 |

#### `ubench.ipc_rt words=6 cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `compiler_builtins::mem::memcpy` | ubench | | 1592 |
| `memset` | ubench | 93 | 667 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | 465 |
| `memcpy` | ubench | 397 | 14 |
| `<page 0x8000c000>` | other | | 268 |
| `kernel::sched::schedule` | kernel | 168 | 222 |
| `<page 0x80000000>` | other | | 208 |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | 194 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 186 | |
| `compiler_builtins::mem::memcpy` | kernel | | 162 |
| `<kernel::sync::Spinlock>::lock_raw` | kernel | 99 | 68 |
| `ipc::ipc_call_timeout` | ubench | 72 | 99 |
| `<kernel::sched::run_queue::PerCpuScheduler>::dequeue_highest` | kernel | 32 | 92 |
| `kernel::arch::current::context::switch` | kernel | 92 | 74 |
| `kernel::syscall::pin_checked` | kernel | 84 | 90 |
| `<page 0x80017000>` | other | | 90 |
| `kernel::arch::current::interrupts::handle_trap` | kernel | | 89 |
| `memcpy` | kernel | 82 | 8 |
| `kernel::arch::current::idt::isr_nm` | kernel | 80 | |
| `kernel::sched::enqueue_and_wake` | kernel | 58 | 78 |
| `ipc::ipc_recv_timeout` | ubench | 53 | 78 |
| `kernel::syscall::dispatch` | kernel | 69 | 21 |
| `kernel::syscall::ipc::sys_ipc_call` | kernel | 60 | 69 |
| `kernel::arch::current::fpu::restore_fp_from` | kernel | | 68 |
| `kernel::arch::current::fpu::save_fp_to` | kernel | | 68 |
| `kernel::arch::current::cpu::save_and_disable_interrupts` | kernel | 58 | 26 |
| `ubench::ipc_rt::serve` | ubench | 58 | 53 |
| `kernel::syscall::dispatch_in_range` | kernel | 57 | 45 |
| `kernel::arch::current::cpu::restore_interrupts` | kernel | 32 | 54 |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 24 | 50 |
| `kernel::syscall::ipc::sys_ipc_reply` | kernel | 30 | 50 |
| `kernel::syscall::ipc::sys_ipc_recv` | kernel | 26 | 48 |
| `<page 0x80010000>` | other | | 48 |
| `<kernel::arch::current::trap_frame::TrapFrame>::set_msg_regs` | kernel | 46 | 46 |
| `kernel::ipc::endpoint::endpoint_call` | kernel | 19 | 46 |
| `<kernel::sched::run_queue::PerCpuScheduler>::link` | kernel | 44 | 42 |
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
| `kernel::ipc::endpoint::bind_next_sender` | kernel | 18 | 34 |
| `kernel::syscall::ipc::deliver_message` | kernel | 32 | 34 |
| `kernel::syscall::pin_checked::{closure#0}` | kernel | 24 | 34 |
| `ipc::ipc_reply` | ubench | 32 | 31 |
| 133 functions below 32 each |  | 842 | 847 |

#### `ubench.ipc_rt words=7 cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `compiler_builtins::mem::memcpy` | ubench | | 1495 |
| `memset` | ubench | 93 | 667 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | 372 |
| `memcpy` | ubench | 354 | 10 |
| `__copy_user_fault_start` | kernel | 228 | |
| `kernel::sched::schedule` | kernel | 168 | 222 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 186 | |
| `__copy_user_words` | kernel | | 180 |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | 154 |
| `ipc::ipc_call_timeout` | ubench | 134 | 139 |
| `<page 0x8000c000>` | other | | 134 |
| `<page 0x80000000>` | other | | 104 |
| `<kernel::sync::Spinlock>::lock_raw` | kernel | 99 | 68 |
| `<kernel::sched::run_queue::PerCpuScheduler>::dequeue_highest` | kernel | 32 | 92 |
| `kernel::arch::current::context::switch` | kernel | 92 | 74 |
| `kernel::syscall::pin_checked` | kernel | 84 | 90 |
| `ipc::ipc_recv_timeout` | ubench | 77 | 83 |
| `kernel::arch::current::idt::isr_nm` | kernel | 80 | |
| `kernel::sched::enqueue_and_wake` | kernel | 58 | 78 |
| `ipc::ipc_reply` | ubench | 74 | 73 |
| `kernel::arch::current::interrupts::handle_trap` | kernel | | 73 |
| `kernel::syscall::dispatch` | kernel | 69 | 21 |
| `kernel::syscall::ipc::sys_ipc_call` | kernel | 60 | 69 |
| `kernel::arch::current::fpu::save_fp_to` | kernel | | 68 |
| `compiler_builtins::mem::memcpy` | kernel | | 65 |
| `kernel::arch::current::cpu::save_and_disable_interrupts` | kernel | 58 | 26 |
| `ubench::ipc_rt::serve` | ubench | 58 | 53 |
| `kernel::syscall::dispatch_in_range` | kernel | 57 | 45 |
| `kernel::arch::current::cpu::restore_interrupts` | kernel | 32 | 54 |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 24 | 50 |
| `kernel::syscall::ipc::sys_ipc_reply` | kernel | 30 | 50 |
| `kernel::syscall::ipc::sys_ipc_recv` | kernel | 26 | 48 |
| `kernel::ipc::endpoint::endpoint_call` | kernel | 19 | 46 |
| `<page 0x80017000>` | other | | 45 |
| `<kernel::sched::run_queue::PerCpuScheduler>::link` | kernel | 44 | 42 |
| `kernel::sched::commit_blocked_under_local_lock` | kernel | 31 | 40 |
| `seraph_enter_from_user` | kernel | 40 | |
| `<kernel::sync::Spinlock>::unlock_raw` | kernel | 13 | 39 |
| `memcpy` | kernel | 39 | 4 |
| `kernel::arch::current::fpu::switch_out_save` | kernel | 18 | 38 |
| `kernel::arch::current::fpu::save_v_to` | kernel | | 36 |
| `kernel::arch::current::encoding::ticks_to_us` | kernel | | 34 |
| `kernel::arch::current::fpu::restore_fp_from` | kernel | | 34 |
| `kernel::arch::current::idt::nm_handler` | kernel | 34 | |
| `kernel::ipc::endpoint::bind_next_sender` | kernel | 18 | 34 |
| `kernel::syscall::ipc::deliver_message` | kernel | 32 | 34 |
| `kernel::syscall::pin_checked::{closure#0}` | kernel | 24 | 34 |
| `__copy_user` | kernel | 12 | 32 |
| `<kernel::arch::current::trap_frame::TrapFrame>::arg` | kernel | 30 | 6 |
| 140 functions below 30 each |  | 825 | 880 |

#### `ubench.ipc_rt words=64 cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `__copy_user_fault_start` | kernel | 2052 | |
| `compiler_builtins::mem::memcpy` | ubench | | 1780 |
| `ipc::ipc_call_timeout` | ubench | 654 | 766 |
| `memset` | ubench | 93 | 667 |
| `__copy_user_block_start` | kernel | | 640 |
| `ipc::ipc_reply` | ubench | 416 | 415 |
| `memcpy` | ubench | 411 | 10 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | 372 |
| `ipc::ipc_recv_timeout` | ubench | 255 | 368 |
| `compiler_builtins::mem::memcpy` | kernel | | 350 |
| `kernel::sched::schedule` | kernel | 168 | 222 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 186 | |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | 154 |
| `<page 0x8000c000>` | other | | 134 |
| `<page 0x80000000>` | other | | 104 |
| `<kernel::sync::Spinlock>::lock_raw` | kernel | 99 | 68 |
| `memcpy` | kernel | 96 | 4 |
| `<kernel::sched::run_queue::PerCpuScheduler>::dequeue_highest` | kernel | 32 | 92 |
| `kernel::arch::current::context::switch` | kernel | 92 | 74 |
| `kernel::syscall::pin_checked` | kernel | 84 | 90 |
| `kernel::arch::current::idt::isr_nm` | kernel | 80 | |
| `kernel::sched::enqueue_and_wake` | kernel | 58 | 78 |
| `kernel::arch::current::interrupts::handle_trap` | kernel | | 73 |
| `kernel::syscall::ipc::sys_ipc_call` | kernel | 60 | 70 |
| `kernel::syscall::dispatch` | kernel | 69 | 21 |
| `kernel::arch::current::fpu::save_fp_to` | kernel | | 68 |
| `kernel::arch::current::cpu::save_and_disable_interrupts` | kernel | 58 | 26 |
| `ubench::ipc_rt::serve` | ubench | 58 | 53 |
| `kernel::syscall::dispatch_in_range` | kernel | 57 | 45 |
| `kernel::arch::current::cpu::restore_interrupts` | kernel | 32 | 54 |
| `kernel::syscall::ipc::sys_ipc_reply` | kernel | 30 | 51 |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 24 | 50 |
| `kernel::syscall::ipc::sys_ipc_recv` | kernel | 26 | 48 |
| `kernel::ipc::endpoint::endpoint_call` | kernel | 19 | 46 |
| `<page 0x80017000>` | other | | 45 |
| `<kernel::sched::run_queue::PerCpuScheduler>::link` | kernel | 44 | 42 |
| 154 functions below 41 each |  | 1077 | 1249 |

#### `ubench.fault_fill path=fault pages=16 cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `memset` | memmgr | 8298 | 24812 |
| `boot_protocol::riscv_paging::level_shift` | kernel | | 2136 |
| `<kernel::mm::address_space::AddressSpace>::map_page_pooled` | kernel | 608 | 1504 |
| `<memmgr::MappedSlots as memmgr_free_pool::arena::SlotStore>::read` | memmgr | 1320 | 1454 |
| `kernel::arch::current::paging::install_user_leaf` | kernel | | 1216 |
| `<kernel::mm::frame_map::FrameMap>::counter` | kernel | 896 | 1200 |
| `kernel::arch::current::paging::entry` | kernel | 48 | 1161 |
| `compiler_builtins::mem::memcpy` | memmgr | | 1119 |
| `boot_protocol::x86_paging::level_shift` | kernel | 1065 | |
| `kernel::arch::current::paging::names_table` | kernel | 975 | |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | 930 |
| `boot_protocol::x86_paging::table_index` | kernel | 921 | |
| `<kernel::mm::frame_map::FrameMap>::lower` | kernel | 240 | 912 |
| `kernel::syscall::mem::sys_mem_map` | kernel | 876 | 908 |
| `<kernel::mm::frame_map::FrameMap>::slot` | kernel | 674 | 688 |
| `kernel::arch::current::paging::descend_existing::<kernel::mm::paging::phys_to_virt>` | kernel | 48 | 682 |
| `kernel::mm::tlb_shootdown::shootdown_range` | kernel | 416 | 640 |
| `<kernel::arch::current::paging::PageTableEntry>::phys_addr` | kernel | 387 | 598 |
| `boot_protocol::riscv_paging::vpn_index` | kernel | | 582 |
| `kernel::arch::current::paging::walk_to_4k_leaf::<kernel::mm::paging::phys_to_virt>` | kernel | 571 | |
| `<boot_protocol::riscv_paging::PagingMode>::levels` | kernel | | 565 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 558 | |
| `<kernel::mm::frame_map::FrameMap>::raise` | kernel | 288 | 544 |
| `kernel::syscall::pin_checked` | kernel | 303 | 540 |
| `kernel::arch::current::paging::root_level` | kernel | 531 | |
| `kernel::arch::current::paging::read_entry` | kernel | 521 | |
| `<memmgr_free_pool::arena::ArenaLayout>::slot_va` | memmgr | 414 | 450 |
| `compiler_builtins::mem::memcpy` | kernel | | 401 |
| `<kernel::mm::address_space::AddressSpace>::pt_lock` | kernel | 144 | 400 |
| `<kernel::arch::current::paging::PageTableEntry>::new_page` | kernel | 352 | 384 |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | 382 |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 192 | 374 |
| `memmgr_free_pool::chunk::child::<memmgr::MappedSlots>` | memmgr | 369 | 363 |
| `memmgr_free_pool::chunk::leaf::<memmgr::MappedSlots>` | memmgr | 369 | 225 |
| `kernel::arch::current::paging::user_va_top` | kernel | 298 | 109 |
| `kernel::arch::current::paging::direct_map_base` | kernel | 292 | 294 |
| `kernel::mm::paging::phys_to_virt` | kernel | 292 | 292 |
| 433 functions below 290 each |  | 11618 | 12299 |

#### `ubench.fault_fill path=grant pages=16 cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `memset` | memmgr | 8388 | 25041 |
| `compiler_builtins::mem::memcpy` | memmgr | | 2846 |
| `boot_protocol::riscv_paging::level_shift` | kernel | | 2112 |
| `<kernel::mm::address_space::AddressSpace>::map_page_pooled` | kernel | 608 | 1504 |
| `kernel::arch::current::paging::install_user_leaf` | kernel | | 1216 |
| `<kernel::mm::frame_map::FrameMap>::counter` | kernel | 896 | 1200 |
| `kernel::arch::current::paging::entry` | kernel | 48 | 1152 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | 1116 |
| `boot_protocol::x86_paging::level_shift` | kernel | 1056 | |
| `kernel::arch::current::paging::names_table` | kernel | 960 | |
| `<kernel::mm::frame_map::FrameMap>::lower` | kernel | 240 | 912 |
| `boot_protocol::x86_paging::table_index` | kernel | 912 | |
| `kernel::syscall::mem::sys_mem_map` | kernel | 876 | 908 |
| `<kernel::mm::frame_map::FrameMap>::slot` | kernel | 674 | 688 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 682 | |
| `kernel::arch::current::paging::descend_existing::<kernel::mm::paging::phys_to_virt>` | kernel | 48 | 672 |
| `kernel::mm::tlb_shootdown::shootdown_range` | kernel | 416 | 640 |
| `compiler_builtins::mem::memcpy` | kernel | | 635 |
| `kernel::syscall::pin_checked` | kernel | 359 | 630 |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 348 | 629 |
| `memcpy` | memmgr | 609 | 22 |
| `<kernel::arch::current::paging::PageTableEntry>::phys_addr` | kernel | 384 | 592 |
| `<memmgr::MappedSlots as memmgr_free_pool::arena::SlotStore>::read` | memmgr | 522 | 592 |
| `boot_protocol::riscv_paging::vpn_index` | kernel | | 576 |
| `<boot_protocol::riscv_paging::PagingMode>::levels` | kernel | | 560 |
| `kernel::arch::current::paging::walk_to_4k_leaf::<kernel::mm::paging::phys_to_virt>` | kernel | 560 | |
| `<kernel::mm::frame_map::FrameMap>::raise` | kernel | 288 | 544 |
| `kernel::arch::current::paging::root_level` | kernel | 528 | |
| `kernel::arch::current::paging::read_entry` | kernel | 512 | |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | 458 |
| `<kernel::cap::cspace::CSpace>::slot_mut` | kernel | 252 | 414 |
| `<kernel::mm::address_space::AddressSpace>::pt_lock` | kernel | 144 | 400 |
| `<kernel::arch::current::paging::PageTableEntry>::new_page` | kernel | 352 | 384 |
| 466 functions below 305 each |  | 13220 | 14752 |

#### `ubench.fault_scaling threads=1 pages=16 cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `memset` | memmgr | 8298 | 24812 |
| `boot_protocol::riscv_paging::level_shift` | kernel | | 2136 |
| `<kernel::mm::address_space::AddressSpace>::map_page_pooled` | kernel | 608 | 1504 |
| `<memmgr::MappedSlots as memmgr_free_pool::arena::SlotStore>::read` | memmgr | 1224 | 1373 |
| `kernel::arch::current::paging::install_user_leaf` | kernel | | 1216 |
| `<kernel::mm::frame_map::FrameMap>::counter` | kernel | 896 | 1200 |
| `kernel::arch::current::paging::entry` | kernel | 48 | 1161 |
| `compiler_builtins::mem::memcpy` | memmgr | | 1119 |
| `boot_protocol::x86_paging::level_shift` | kernel | 1065 | |
| `kernel::arch::current::paging::names_table` | kernel | 975 | |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | 930 |
| `boot_protocol::x86_paging::table_index` | kernel | 921 | |
| `<kernel::mm::frame_map::FrameMap>::lower` | kernel | 240 | 912 |
| `kernel::syscall::mem::sys_mem_map` | kernel | 876 | 908 |
| `<kernel::mm::frame_map::FrameMap>::slot` | kernel | 674 | 688 |
| `kernel::arch::current::paging::descend_existing::<kernel::mm::paging::phys_to_virt>` | kernel | 48 | 682 |
| `kernel::mm::tlb_shootdown::shootdown_range` | kernel | 416 | 640 |
| `<kernel::arch::current::paging::PageTableEntry>::phys_addr` | kernel | 387 | 598 |
| `boot_protocol::riscv_paging::vpn_index` | kernel | | 582 |
| `kernel::arch::current::paging::walk_to_4k_leaf::<kernel::mm::paging::phys_to_virt>` | kernel | 571 | |
| `<boot_protocol::riscv_paging::PagingMode>::levels` | kernel | | 565 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 558 | |
| `<kernel::mm::frame_map::FrameMap>::raise` | kernel | 288 | 544 |
| `kernel::syscall::pin_checked` | kernel | 303 | 540 |
| `kernel::arch::current::paging::root_level` | kernel | 531 | |
| `kernel::arch::current::paging::read_entry` | kernel | 521 | |
| `<memmgr_free_pool::arena::ArenaLayout>::slot_va` | memmgr | 414 | 450 |
| `compiler_builtins::mem::memcpy` | kernel | | 401 |
| `<kernel::mm::address_space::AddressSpace>::pt_lock` | kernel | 144 | 400 |
| `<kernel::arch::current::paging::PageTableEntry>::new_page` | kernel | 352 | 384 |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | 382 |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 192 | 374 |
| `memmgr_free_pool::chunk::child::<memmgr::MappedSlots>` | memmgr | 369 | 363 |
| `memmgr_free_pool::chunk::leaf::<memmgr::MappedSlots>` | memmgr | 369 | 225 |
| `kernel::arch::current::paging::user_va_top` | kernel | 298 | 109 |
| `kernel::arch::current::paging::direct_map_base` | kernel | 292 | 294 |
| `kernel::mm::paging::phys_to_virt` | kernel | 292 | 292 |
| 435 functions below 290 each |  | 11573 | 12293 |

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
| 56 functions below 4597 each |  | 415 | 404 |

#### `ubench.console_write bytes=64 cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `compiler_builtins::mem::memmove` | /services/drivers/framebuffer | | 2240025 |
| `memmove` | /services/drivers/framebuffer | 448023 | 2 |
| `<framebuffer::render::FramebufferWriter>::scroll` | /services/drivers/framebuffer | 140835 | 307229 |
| `<framebuffer::render::FramebufferWriter>::draw_glyph_bitmap` | /services/drivers/framebuffer | 111825 | 200332 |
| `<framebuffer::render::FramebufferWriter>::pixel_bytes` | /services/drivers/framebuffer | 57960 | 11340 |
| 267 functions below 13865 each |  | 9101 | 14199 |

#### `ubench.console_write bytes=4096 cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `compiler_builtins::mem::memmove` | /services/drivers/framebuffer | | 143361600 |
| `memmove` | /services/drivers/framebuffer | 28673472 | 128 |
| `<framebuffer::render::FramebufferWriter>::scroll` | /services/drivers/framebuffer | 9013440 | 19662656 |
| `<framebuffer::render::FramebufferWriter>::draw_glyph_bitmap` | /services/drivers/framebuffer | 7156800 | 12820888 |
| `<framebuffer::render::FramebufferWriter>::pixel_bytes` | /services/drivers/framebuffer | 3709440 | 725760 |
| 335 functions below 885281 each |  | 387612 | 485177 |

#### `fsbench.read size=16 path=inline cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `memset` | fatfs:/ | 1154 | 3553 |
| `compiler_builtins::mem::memcpy` | fatfs:/ | | 1598 |
| `compiler_builtins::mem::memcpy` | /tests/fixtures/programs/fsbench | | 759 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | 651 |
| `memset` | /tests/fixtures/programs/fsbench | 87 | 434 |
| `memcpy` | fatfs:/ | 398 | 16 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 310 | |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | 270 |
| `<page 0x8000c000>` | other | | 268 |
| `kernel::sched::schedule` | kernel | 170 | 226 |
| `<page 0x80000000>` | other | | 208 |
| `memcpy` | /tests/fixtures/programs/fsbench | 199 | 8 |
| `std::os::seraph::deadline_call` | /tests/fixtures/programs/fsbench | 132 | 157 |
| `kernel::arch::current::interrupts::handle_trap` | kernel | | 127 |
| `<page 0x80017000>` | other | | 125 |
| `<std::fs::File as alloc::io::read::Read>::read` | /tests/fixtures/programs/fsbench | 96 | 124 |
| `fatfs::service_loop` | fatfs:/ | 116 | 112 |
| `kernel::syscall::dispatch` | kernel | 115 | 35 |
| `compiler_builtins::mem::memcpy` | kernel | | 107 |
| `<kernel::sync::Spinlock>::lock_raw` | kernel | 99 | 68 |
| `kernel::syscall::dispatch_in_range` | kernel | 95 | 75 |
| `<kernel::sched::run_queue::PerCpuScheduler>::dequeue_highest` | kernel | 32 | 92 |
| `kernel::arch::current::context::switch` | kernel | 92 | 74 |
| `kernel::syscall::pin_checked` | kernel | 84 | 90 |
| `<kernel::mm::address_space::AddressSpace>::activate` | kernel | 4 | 88 |
| `kernel::arch::current::idt::isr_nm` | kernel | 80 | |
| `kernel::sched::enqueue_and_wake` | kernel | 58 | 78 |
| `fatfs::handle_read` | fatfs:/ | 66 | 75 |
| `memcpy` | kernel | 71 | 8 |
| `kernel::arch::current::encoding::ticks_to_us` | kernel | | 70 |
| `kernel::syscall::ipc::sys_ipc_call` | kernel | 60 | 69 |
| `kernel::arch::current::fpu::restore_fp_from` | kernel | | 68 |
| `kernel::arch::current::fpu::save_fp_to` | kernel | | 68 |
| `ipc::ipc_recv_timeout` | fatfs:/ | 43 | 64 |
| 241 functions below 61 each |  | 2238 | 2620 |

#### `fsbench.read size=16 path=frame cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `<std::fs::File as alloc::io::read::Read>::read` | /tests/fixtures/programs/fsbench | 10407 | 24744 |
| `crypto::keccak::keccak_f1600` | kernel | 12628 | 12530 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | 2325 |
| `compiler_builtins::mem::memcpy` | fatfs:/ | | 1816 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 1302 | |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | 958 |
| `memset` | /tests/fixtures/programs/fsbench | 175 | 871 |
| `compiler_builtins::mem::memcpy` | /tests/fixtures/programs/fsbench | | 769 |
| `<kernel::cap::cspace::CSpace>::slot_mut` | kernel | 456 | 690 |
| `memset` | fatfs:/ | | 651 |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 360 | 618 |
| `kernel::syscall::pin_checked` | kernel | 343 | 585 |
| `<page 0x8000c000>` | other | | 536 |
| `kernel::syscall::dispatch` | kernel | 483 | 147 |
| `kernel::arch::current::interrupts::handle_trap` | kernel | | 463 |
| `kernel::sched::schedule` | kernel | 340 | 452 |
| `<fatfs::session::SessionPages>::va` | fatfs:/ | 436 | 356 |
| `memcpy` | fatfs:/ | 416 | 12 |
| `<page 0x80000000>` | other | | 416 |
| `kernel::syscall::dispatch_in_range` | kernel | 411 | 314 |
| `<kernel::cap::cspace::CSpace>::leaf_ptr` | kernel | 204 | 408 |
| `compiler_builtins::mem::memcpy` | kernel | | 396 |
| `<fatfs_parse::session_pool::SessionPool<fatfs::session::SessionPages>>::find` | fatfs:/ | 341 | 275 |
| `kernel::arch::nospec::select_ptr::<kernel::cap::cspace::CSpacePage>` | kernel | 272 | 340 |
| `kernel::arch::current::speculation::index_mask` | kernel | 332 | 339 |
| 479 functions below 330 each |  | 13155 | 15092 |

#### `fsbench.read size=1024 path=inline cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `memset` | fatfs:/ | 4616 | 14212 |
| `compiler_builtins::mem::memcpy` | fatfs:/ | | 13690 |
| `memcpy` | fatfs:/ | 3712 | 300 |
| `compiler_builtins::mem::memcpy` | /tests/fixtures/programs/fsbench | | 3696 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | 2604 |
| `fatfs::handle_read` | fatfs:/ | 2304 | 1980 |
| `__copy_user_fault_start` | kernel | 2052 | |
| `memset` | /tests/fixtures/programs/fsbench | 348 | 1736 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 1240 | |
| `std::os::seraph::deadline_call` | /tests/fixtures/programs/fsbench | 878 | 1194 |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | 1080 |
| `<page 0x8000c000>` | other | | 1072 |
| `ipc::ipc_reply` | fatfs:/ | 900 | 924 |
| `memcpy` | /tests/fixtures/programs/fsbench | 916 | 32 |
| `kernel::sched::schedule` | kernel | 680 | 904 |
| `<page 0x80000000>` | other | | 832 |
| `__copy_user_block_start` | kernel | | 640 |
| `kernel::arch::current::interrupts::handle_trap` | kernel | | 508 |
| `<std::fs::File as alloc::io::read::Read>::read` | /tests/fixtures/programs/fsbench | 384 | 496 |
| `fatfs::service_loop` | fatfs:/ | 464 | 454 |
| `kernel::syscall::dispatch` | kernel | 460 | 140 |
| `<page 0x80017000>` | other | | 430 |
| `<kernel::sync::Spinlock>::lock_raw` | kernel | 396 | 272 |
| `kernel::syscall::dispatch_in_range` | kernel | 380 | 300 |
| `<kernel::sched::run_queue::PerCpuScheduler>::dequeue_highest` | kernel | 128 | 368 |
| `kernel::arch::current::context::switch` | kernel | 368 | 296 |
| `kernel::syscall::pin_checked` | kernel | 336 | 360 |
| `<kernel::mm::address_space::AddressSpace>::activate` | kernel | 16 | 352 |
| `compiler_builtins::mem::memcpy` | kernel | | 346 |
| `kernel::arch::current::idt::isr_nm` | kernel | 320 | |
| `kernel::sched::enqueue_and_wake` | kernel | 232 | 312 |
| 253 functions below 305 each |  | 9331 | 11495 |

#### `fsbench.read size=1024 path=frame cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `<std::fs::File as alloc::io::read::Read>::read` | /tests/fixtures/programs/fsbench | 10407 | 24744 |
| `crypto::keccak::keccak_f1600` | kernel | 12628 | 12530 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | 2325 |
| `compiler_builtins::mem::memcpy` | fatfs:/ | | 1816 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 1302 | |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | 958 |
| `memset` | /tests/fixtures/programs/fsbench | 175 | 871 |
| `compiler_builtins::mem::memcpy` | /tests/fixtures/programs/fsbench | | 769 |
| `<kernel::cap::cspace::CSpace>::slot_mut` | kernel | 456 | 690 |
| `memset` | fatfs:/ | | 651 |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 360 | 618 |
| `kernel::syscall::pin_checked` | kernel | 343 | 585 |
| `<page 0x8000c000>` | other | | 536 |
| `kernel::syscall::dispatch` | kernel | 483 | 147 |
| `kernel::arch::current::interrupts::handle_trap` | kernel | | 463 |
| `kernel::sched::schedule` | kernel | 340 | 452 |
| `<fatfs::session::SessionPages>::va` | fatfs:/ | 436 | 356 |
| `memcpy` | fatfs:/ | 416 | 12 |
| `<page 0x80000000>` | other | | 416 |
| `kernel::syscall::dispatch_in_range` | kernel | 411 | 314 |
| `<kernel::cap::cspace::CSpace>::leaf_ptr` | kernel | 204 | 408 |
| `compiler_builtins::mem::memcpy` | kernel | | 396 |
| `<fatfs_parse::session_pool::SessionPool<fatfs::session::SessionPages>>::find` | fatfs:/ | 341 | 275 |
| `kernel::arch::nospec::select_ptr::<kernel::cap::cspace::CSpacePage>` | kernel | 272 | 340 |
| `kernel::arch::current::speculation::index_mask` | kernel | 332 | 339 |
| 479 functions below 330 each |  | 13155 | 15092 |

#### `fsbench.read size=4096 path=inline cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `memset` | fatfs:/ | 18464 | 56848 |
| `compiler_builtins::mem::memcpy` | fatfs:/ | | 54760 |
| `memcpy` | fatfs:/ | 14848 | 1200 |
| `compiler_builtins::mem::memcpy` | /tests/fixtures/programs/fsbench | | 14784 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | 10416 |
| `fatfs::handle_read` | fatfs:/ | 9216 | 7920 |
| `__copy_user_fault_start` | kernel | 8208 | |
| `memset` | /tests/fixtures/programs/fsbench | 1392 | 6944 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 4960 | |
| `std::os::seraph::deadline_call` | /tests/fixtures/programs/fsbench | 3512 | 4776 |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | 4320 |
| `<page 0x8000c000>` | other | | 4288 |
| `ipc::ipc_reply` | fatfs:/ | 3600 | 3696 |
| `memcpy` | /tests/fixtures/programs/fsbench | 3664 | 128 |
| `kernel::sched::schedule` | kernel | 2720 | 3616 |
| `<page 0x80000000>` | other | | 3328 |
| `__copy_user_block_start` | kernel | | 2560 |
| `kernel::arch::current::interrupts::handle_trap` | kernel | | 2032 |
| `<std::fs::File as alloc::io::read::Read>::read` | /tests/fixtures/programs/fsbench | 1536 | 1984 |
| `fatfs::service_loop` | fatfs:/ | 1856 | 1816 |
| `kernel::syscall::dispatch` | kernel | 1840 | 560 |
| `<page 0x80017000>` | other | | 1720 |
| `<kernel::sync::Spinlock>::lock_raw` | kernel | 1584 | 1088 |
| `kernel::syscall::dispatch_in_range` | kernel | 1520 | 1200 |
| `<kernel::sched::run_queue::PerCpuScheduler>::dequeue_highest` | kernel | 512 | 1472 |
| `kernel::arch::current::context::switch` | kernel | 1472 | 1184 |
| `kernel::syscall::pin_checked` | kernel | 1344 | 1440 |
| `<kernel::mm::address_space::AddressSpace>::activate` | kernel | 64 | 1408 |
| `compiler_builtins::mem::memcpy` | kernel | | 1384 |
| `kernel::arch::current::idt::isr_nm` | kernel | 1280 | |
| `kernel::sched::enqueue_and_wake` | kernel | 928 | 1248 |
| 253 functions below 1219 each |  | 37189 | 45839 |

#### `fsbench.read size=4096 path=frame cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `<std::fs::File as alloc::io::read::Read>::read` | /tests/fixtures/programs/fsbench | 10407 | 24744 |
| `crypto::keccak::keccak_f1600` | kernel | 12628 | 12530 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | 2325 |
| `compiler_builtins::mem::memcpy` | fatfs:/ | | 1816 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 1302 | |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | 958 |
| `memset` | /tests/fixtures/programs/fsbench | 175 | 871 |
| `compiler_builtins::mem::memcpy` | /tests/fixtures/programs/fsbench | | 769 |
| `<kernel::cap::cspace::CSpace>::slot_mut` | kernel | 456 | 690 |
| `memset` | fatfs:/ | | 651 |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 360 | 618 |
| `kernel::syscall::pin_checked` | kernel | 343 | 585 |
| `<page 0x8000c000>` | other | | 536 |
| `kernel::syscall::dispatch` | kernel | 483 | 147 |
| `kernel::arch::current::interrupts::handle_trap` | kernel | | 463 |
| `kernel::sched::schedule` | kernel | 340 | 452 |
| `<fatfs::session::SessionPages>::va` | fatfs:/ | 436 | 356 |
| `memcpy` | fatfs:/ | 416 | 12 |
| `<page 0x80000000>` | other | | 416 |
| `kernel::syscall::dispatch_in_range` | kernel | 411 | 314 |
| `<kernel::cap::cspace::CSpace>::leaf_ptr` | kernel | 204 | 408 |
| `compiler_builtins::mem::memcpy` | kernel | | 396 |
| `<fatfs_parse::session_pool::SessionPool<fatfs::session::SessionPages>>::find` | fatfs:/ | 341 | 275 |
| `kernel::arch::nospec::select_ptr::<kernel::cap::cspace::CSpacePage>` | kernel | 272 | 340 |
| `kernel::arch::current::speculation::index_mask` | kernel | 332 | 339 |
| 479 functions below 330 each |  | 13155 | 15092 |

#### `fsbench.read size=16384 path=inline cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `memset` | fatfs:/ | 73856 | 227392 |
| `compiler_builtins::mem::memcpy` | fatfs:/ | | 219040 |
| `memcpy` | fatfs:/ | 59392 | 4800 |
| `compiler_builtins::mem::memcpy` | /tests/fixtures/programs/fsbench | | 59136 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | 41757 |
| `fatfs::handle_read` | fatfs:/ | 36864 | 31680 |
| `__copy_user_fault_start` | kernel | 32832 | |
| `memset` | /tests/fixtures/programs/fsbench | 5568 | 27776 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 19840 | |
| `std::os::seraph::deadline_call` | /tests/fixtures/programs/fsbench | 14048 | 19104 |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | 17320 |
| `<page 0x8000c000>` | other | | 17152 |
| `ipc::ipc_reply` | fatfs:/ | 14400 | 14784 |
| `memcpy` | /tests/fixtures/programs/fsbench | 14656 | 512 |
| `kernel::sched::schedule` | kernel | 10880 | 14464 |
| `<page 0x80000000>` | other | | 13312 |
| `__copy_user_block_start` | kernel | | 10240 |
| `kernel::arch::current::interrupts::handle_trap` | kernel | | 8143 |
| `<std::fs::File as alloc::io::read::Read>::read` | /tests/fixtures/programs/fsbench | 6144 | 7936 |
| `fatfs::service_loop` | fatfs:/ | 7472 | 7312 |
| `kernel::syscall::dispatch` | kernel | 7360 | 2240 |
| `<page 0x80017000>` | other | | 6880 |
| `<kernel::sync::Spinlock>::lock_raw` | kernel | 6336 | 4370 |
| `kernel::syscall::dispatch_in_range` | kernel | 6080 | 4800 |
| `<kernel::sched::run_queue::PerCpuScheduler>::dequeue_highest` | kernel | 2048 | 5888 |
| `kernel::arch::current::context::switch` | kernel | 5888 | 4736 |
| `kernel::syscall::pin_checked` | kernel | 5376 | 5760 |
| `<kernel::mm::address_space::AddressSpace>::activate` | kernel | 256 | 5632 |
| `compiler_builtins::mem::memcpy` | kernel | | 5536 |
| `kernel::arch::current::idt::isr_nm` | kernel | 5120 | |
| `fatfs::fat::read_file_data` | fatfs:/ | 4848 | 5056 |
| `fatfs::fat::chain_next` | fatfs:/ | 4992 | 4800 |
| `kernel::sched::enqueue_and_wake` | kernel | 3712 | 4992 |
| 278 functions below 4950 each |  | 150877 | 187624 |

#### `fsbench.read size=16384 path=frame cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `<std::fs::File as alloc::io::read::Read>::read` | /tests/fixtures/programs/fsbench | 41628 | 98976 |
| `crypto::keccak::keccak_f1600` | kernel | 50512 | 50120 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | 9300 |
| `compiler_builtins::mem::memcpy` | fatfs:/ | | 7264 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 5208 | |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | 3832 |
| `memset` | /tests/fixtures/programs/fsbench | 700 | 3484 |
| `compiler_builtins::mem::memcpy` | /tests/fixtures/programs/fsbench | | 3076 |
| `<kernel::cap::cspace::CSpace>::slot_mut` | kernel | 1824 | 2760 |
| `memset` | fatfs:/ | | 2604 |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 1440 | 2472 |
| `kernel::syscall::pin_checked` | kernel | 1372 | 2340 |
| `<page 0x8000c000>` | other | | 2144 |
| `kernel::syscall::dispatch` | kernel | 1932 | 588 |
| `kernel::arch::current::interrupts::handle_trap` | kernel | | 1852 |
| `kernel::sched::schedule` | kernel | 1360 | 1808 |
| `<fatfs::session::SessionPages>::va` | fatfs:/ | 1744 | 1424 |
| `memcpy` | fatfs:/ | 1664 | 48 |
| `<page 0x80000000>` | other | | 1664 |
| `kernel::syscall::dispatch_in_range` | kernel | 1644 | 1256 |
| `<kernel::cap::cspace::CSpace>::leaf_ptr` | kernel | 816 | 1632 |
| `compiler_builtins::mem::memcpy` | kernel | | 1584 |
| `<fatfs_parse::session_pool::SessionPool<fatfs::session::SessionPages>>::find` | fatfs:/ | 1364 | 1100 |
| `kernel::arch::nospec::select_ptr::<kernel::cap::cspace::CSpacePage>` | kernel | 1088 | 1360 |
| `kernel::arch::current::speculation::index_mask` | kernel | 1328 | 1356 |
| 487 functions below 1324 each |  | 53104 | 60933 |

#### `fsbench.read size=65536 path=inline cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `memset` | fatfs:/ | 295424 | 909568 |
| `compiler_builtins::mem::memcpy` | fatfs:/ | | 876154 |
| `memcpy` | fatfs:/ | 237568 | 19200 |
| `compiler_builtins::mem::memcpy` | /tests/fixtures/programs/fsbench | | 236544 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | 167028 |
| `fatfs::handle_read` | fatfs:/ | 147456 | 126720 |
| `__copy_user_fault_start` | kernel | 131328 | |
| `memset` | /tests/fixtures/programs/fsbench | 22272 | 111104 |
| `fatfs::fat::chain_next` | fatfs:/ | 99840 | 96000 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 79360 | |
| `fatfs::alloc::read_fat_entry` | fatfs:/ | 36480 | 76800 |
| `std::os::seraph::deadline_call` | /tests/fixtures/programs/fsbench | 56192 | 76416 |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | 69280 |
| `<page 0x8000c000>` | other | | 68608 |
| `ipc::ipc_reply` | fatfs:/ | 57600 | 59136 |
| `memcpy` | /tests/fixtures/programs/fsbench | 58624 | 2048 |
| `kernel::sched::schedule` | kernel | 43520 | 57950 |
| `<page 0x80000000>` | other | | 53248 |
| `fatfs::fat::read_file_data` | fatfs:/ | 40944 | 44800 |
| `__copy_user_block_start` | kernel | | 40960 |
| `<fatfs::bpb::FatState>::fat_entry_location` | fatfs:/ | 30720 | 34560 |
| `kernel::arch::current::interrupts::handle_trap` | kernel | | 32572 |
| `<std::fs::File as alloc::io::read::Read>::read` | /tests/fixtures/programs/fsbench | 24576 | 31744 |
| `fatfs::service_loop` | fatfs:/ | 29936 | 29296 |
| `kernel::syscall::dispatch` | kernel | 29440 | 8960 |
| `<page 0x80017000>` | other | | 27520 |
| `<kernel::sync::Spinlock>::lock_raw` | kernel | 25382 | 17488 |
| `<fatfs::cache::PageCache>::lookup_cached` | fatfs:/ | 24848 | 24848 |
| `kernel::syscall::dispatch_in_range` | kernel | 24320 | 19200 |
| `<kernel::sched::run_queue::PerCpuScheduler>::dequeue_highest` | kernel | 8192 | 23598 |
| `kernel::arch::current::context::switch` | kernel | 23552 | 18944 |
| `kernel::syscall::pin_checked` | kernel | 21504 | 23040 |
| `<kernel::mm::address_space::AddressSpace>::activate` | kernel | 1024 | 22528 |
| `compiler_builtins::mem::memcpy` | kernel | | 22144 |
| 294 functions below 20875 each |  | 629457 | 747033 |

#### `fsbench.read size=65536 path=frame cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `<std::fs::File as alloc::io::read::Read>::read` | /tests/fixtures/programs/fsbench | 166512 | 395904 |
| `crypto::keccak::keccak_f1600` | kernel | 202048 | 200480 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | 37293 |
| `compiler_builtins::mem::memcpy` | fatfs:/ | | 29056 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 20832 | |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | 15368 |
| `memset` | /tests/fixtures/programs/fsbench | 2800 | 13936 |
| `compiler_builtins::mem::memcpy` | /tests/fixtures/programs/fsbench | | 12304 |
| `<kernel::cap::cspace::CSpace>::slot_mut` | kernel | 7296 | 11040 |
| `memset` | fatfs:/ | | 10416 |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 5760 | 9888 |
| `kernel::syscall::pin_checked` | kernel | 5488 | 9360 |
| `<page 0x8000c000>` | other | | 8576 |
| `kernel::syscall::dispatch` | kernel | 7728 | 2352 |
| `kernel::arch::current::interrupts::handle_trap` | kernel | | 7423 |
| `kernel::sched::schedule` | kernel | 5440 | 7232 |
| `<fatfs::session::SessionPages>::va` | fatfs:/ | 6976 | 5696 |
| `memcpy` | fatfs:/ | 6656 | 192 |
| `<page 0x80000000>` | other | | 6656 |
| `kernel::syscall::dispatch_in_range` | kernel | 6576 | 5024 |
| `<kernel::cap::cspace::CSpace>::leaf_ptr` | kernel | 3264 | 6528 |
| `compiler_builtins::mem::memcpy` | kernel | | 6336 |
| `<fatfs_parse::session_pool::SessionPool<fatfs::session::SessionPages>>::find` | fatfs:/ | 5456 | 4400 |
| `kernel::arch::nospec::select_ptr::<kernel::cap::cspace::CSpacePage>` | kernel | 4352 | 5440 |
| `kernel::arch::current::speculation::index_mask` | kernel | 5312 | 5424 |
| 521 functions below 5315 each |  | 215179 | 246785 |

#### `fsbench.open depth=3 cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `memset` | fatfs:/ | 5009 | 14500 |
| `crypto::keccak::keccak_f1600` | kernel | 12628 | 12530 |
| `compiler_builtins::mem::memcpy` | fatfs:/ | | 8672 |
| `<fatfs_parse::LfnAccum>::add_lfn_entry` | fatfs:/ | 4168 | 4350 |
| `fatfs::dir::scan_sector_for_name` | fatfs:/ | 3012 | 3728 |
| `compiler_builtins::mem::memcpy` | /tests/fixtures/programs/fsbench | | 3420 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | 3162 |
| `<fatfs_parse::LfnAccum>::assemble_utf8` | fatfs:/ | 2786 | 2128 |
| `compiler_builtins::mem::memcpy` | vfsd | | 2359 |
| `<kernel::cap::cspace::CSpace>::slot_mut` | kernel | 1248 | 2092 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 1736 | |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 924 | 1520 |
| `memcpy` | fatfs:/ | 1364 | 60 |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | 1304 |
| `memset` | /tests/fixtures/programs/fsbench | 260 | 1299 |
| `<fatfs::cache::PageCache>::lookup_cached` | fatfs:/ | 688 | 1297 |
| `<kernel::cap::cspace::CSpace>::leaf_ptr` | kernel | 543 | 1086 |
| `std::sys::fs::seraph::walk_components` | /tests/fixtures/programs/fsbench | 958 | 891 |
| `std::sys::alloc::seraph::alloc` | fatfs:/ | 948 | 666 |
| `kernel::syscall::pin_checked` | kernel | 540 | 945 |
| `kernel::arch::nospec::select_ptr::<kernel::cap::cspace::CSpacePage>` | kernel | 724 | 905 |
| `compiler_builtins::mem::memcpy` | kernel | | 891 |
| `memcpy` | /tests/fixtures/programs/fsbench | 861 | 32 |
| `<page 0x8000c000>` | other | | 804 |
| `<fatfs::cache::PageCache>::pages_held` | fatfs:/ | 781 | 775 |
| `<fatfs::cache::PageCache>::pages_held::{closure#0}` | fatfs:/ | 256 | 768 |
| `<kernel::cap::registry::CSpaceRegistry>::entry` | kernel | 595 | 768 |
| `<kernel::cap::registry::CSpaceRegistry>::slot` | kernel | 636 | 747 |
| `<fatfs_parse::LfnAccum>::matches` | fatfs:/ | 716 | |
| `kernel::arch::current::speculation::index_mask` | kernel | 700 | 708 |
| `kernel::sched::schedule` | kernel | 510 | 678 |
| `memset` | vfsd | 88 | 651 |
| `kernel::syscall::dispatch` | kernel | 646 | 198 |
| `kernel::arch::current::interrupts::handle_trap` | kernel | | 628 |
| `<page 0x80000000>` | other | | 624 |
| `<kernel::cap::registry::CSpaceRegistry>::lookup` | kernel | 589 | 549 |
| `memcpy` | vfsd | 584 | 22 |
| `kernel::syscall::dispatch_in_range` | kernel | 545 | 418 |
| `kernel::cap::cspace::load_at::<kernel::cap::cspace::CSpacePage>` | kernel | | 543 |
| `<kernel::sync::Spinlock>::lock_raw` | kernel | 533 | 382 |
| `kernel::cap::derivation::resolve_slot_mut` | kernel | 522 | 143 |
| 457 functions below 504 each |  | 20183 | 23637 |

<!-- path-account: end -->

---

## Summarized By

[core/kernel/README.md](../README.md), [Kernel Hot-Path Instruction Account](hot-path-account.md)
