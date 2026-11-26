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

`ubench.ipc_rt words=0` is 2723 / 5045, 2069 / 2694 of it in the kernel. The kernel copies and
zeroes no whole `Message` on either side: its largest functions are the entries
(`syscall_entry` 186 on x86_64; `trap_entry` and `trap_dispatch`, 279 and 114, on riscv64) and
`schedule` (172 / 228). On riscv64 ubench moves the message through `compiler_builtins`' word
loops (`memcpy` 1448, `memset` 667). Each switch-in makes the incoming thread's floating-point
and vector state live (`fpu::switch_in_restore`, 18 / 28): on riscv64 it loads the F/D and V
files (`restore_fp_from` 68, `restore_v_from` 34) and each switch-out saves the dirty V file
(`save_v_to` 36); x86_64's `XSAVE` and `XRSTOR` fall in the closing row.

### Page Faults

`ubench.fault_fill path=fault pages=16` is 34016 / 57713: memmgr 13992 / 31915, of which its
`memset` zeroing the 16 frames is 8298 / 24812 (x86_64's `rep stos` is about one iteration per 8
bytes, riscv64's loop about one instruction per 2.6 bytes), and the kernel 20013 / 25790, spread
over the page-table walk and install (`level_shift`, `table_index`, `names_table`, `read_entry`,
`install_user_leaf`), the frame map's counters, and `sys_mem_map`. `fault_scaling threads=1` runs
the same path. `path=grant` adds the grant's capability operations, 33839 / 60064.

### Shared-Memory Ring

`ubench.shmem_ring` runs in ubench alone: `shmem_ring::transfer` is 49342 / 57448 of the
4096-byte transfer, about 12 / 14 instructions per byte.

### Console Writes

`ubench.console_write bytes=4096` is 48941354 / 177049288, all but 0.2 % in the framebuffer
driver. Its scroll moves the whole framebuffer up a text row at each line it fills
(`memmove` 28673472 / 143361728 and `FramebufferWriter::scroll` 9013440 / 19662656), and
drawing the glyphs is 7156800 / 12820888.

### File Reads and Opens

A read through the inline path (`fsbench.read path=inline`) is fatfs's copy and zeroing of the reply
and the kernel's copy to and from user memory. A read through granted frames (`path=frame`) spends
12628 / 12530 in the kernel's Keccak permutation (`keccak_f1600`) per 4 KiB frame the grant names,
202048 / 200480 of 674341 / 1027915 at 64 KiB: std draws each request's 8-byte cookie through
`SYS_GETRANDOM`, fresh output with its own squeeze and ratchet
([entropy.md](entropy.md) § Draw API and consumers). `fsbench.open depth=3` is 70175 / 97439, one
such draw (12628 / 12530, the release badge `File::open` allocates) and
fatfs's long-name parsing (`LfnAccum`, 7670 / 6478) among it.

## Account

<!-- path-account: begin; generated by cargo xtask path-account write -->

| Configuration | Head | Taken | QEMU | Checked against |
|---|---|---|---|---|
| x86_64 release | `43c1fc2a2c66` | 2026-11-26 | QEMU emulator version 11.1.3 | 1 icount boot(s) of the image without debuginfo |
| riscv64 release | `43c1fc2a2c66` | 2026-11-26 | QEMU emulator version 11.1.3 | 1 icount boot(s) of the image without debuginfo |

#### Totals

| Path | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `ubench.ipc_rt words=0 cpus=1` | all | 2723 | 5045 |
| `ubench.ipc_rt words=0 cpus=1` | ubench | 654 | 2351 |
| `ubench.ipc_rt words=0 cpus=1` | kernel | 2069 | 2694 |
| `ubench.ipc_rt words=6 cpus=1` | all | 2969 | 5508 |
| `ubench.ipc_rt words=6 cpus=1` | ubench | 755 | 2572 |
| `ubench.ipc_rt words=6 cpus=1` | kernel | 2214 | 2936 |
| `ubench.ipc_rt words=7 cpus=1` | all | 3216 | 5568 |
| `ubench.ipc_rt words=7 cpus=1` | ubench | 840 | 2559 |
| `ubench.ipc_rt words=7 cpus=1` | kernel | 2376 | 3009 |
| `ubench.ipc_rt words=64 cpus=1` | all | 6194 | 7862 |
| `ubench.ipc_rt words=64 cpus=1` | ubench | 1937 | 4098 |
| `ubench.ipc_rt words=64 cpus=1` | kernel | 4257 | 3764 |
| `ubench.fault_fill path=fault pages=16 cpus=1` | all | 34016 | 57713 |
| `ubench.fault_fill path=fault pages=16 cpus=1` | ubench | 11 | 8 |
| `ubench.fault_fill path=fault pages=16 cpus=1` | memmgr | 13992 | 31915 |
| `ubench.fault_fill path=fault pages=16 cpus=1` | kernel | 20013 | 25790 |
| `ubench.fault_fill path=grant pages=16 cpus=1` | all | 33839 | 60064 |
| `ubench.fault_fill path=grant pages=16 cpus=1` | ubench | 114 | 352 |
| `ubench.fault_fill path=grant pages=16 cpus=1` | memmgr | 11168 | 30298 |
| `ubench.fault_fill path=grant pages=16 cpus=1` | kernel | 22557 | 29414 |
| `ubench.fault_scaling threads=1 pages=16 cpus=1` | all | 33900 | 57594 |
| `ubench.fault_scaling threads=1 pages=16 cpus=1` | ubench | 11 | 8 |
| `ubench.fault_scaling threads=1 pages=16 cpus=1` | memmgr | 14060 | 31787 |
| `ubench.fault_scaling threads=1 pages=16 cpus=1` | kernel | 19829 | 25799 |
| `ubench.shmem_ring bytes=64 cpus=1` | all | 219 | 103 |
| `ubench.shmem_ring bytes=64 cpus=1` | ubench | 219 | 103 |
| `ubench.shmem_ring bytes=512 cpus=1` | all | 207 | 383 |
| `ubench.shmem_ring bytes=512 cpus=1` | ubench | 207 | 383 |
| `ubench.shmem_ring bytes=4096 cpus=1` | all | 49353 | 57455 |
| `ubench.shmem_ring bytes=4096 cpus=1` | ubench | 49353 | 57455 |
| `ubench.shmem_ring bytes=65536 cpus=1` | all | 789835 | 919517 |
| `ubench.shmem_ring bytes=65536 cpus=1` | ubench | 789423 | 919115 |
| `ubench.shmem_ring bytes=65536 cpus=1` | kernel | 412 | 402 |
| `ubench.console_write bytes=64 cpus=1` | all | 767661 | 2772129 |
| `ubench.console_write bytes=64 cpus=1` | ubench | 988 | 3097 |
| `ubench.console_write bytes=64 cpus=1` | /services/drivers/framebuffer | 763763 | 2764542 |
| `ubench.console_write bytes=64 cpus=1` | kernel | 2910 | 4490 |
| `ubench.console_write bytes=4096 cpus=1` | all | 48941354 | 177049288 |
| `ubench.console_write bytes=4096 cpus=1` | ubench | 25243 | 60070 |
| `ubench.console_write bytes=4096 cpus=1` | /services/drivers/framebuffer | 48865040 | 176873264 |
| `ubench.console_write bytes=4096 cpus=1` | /services/drivers/iommu-riscv | 0 | 119 |
| `ubench.console_write bytes=4096 cpus=1` | /services/drivers/iommu-vtd | 63 | 0 |
| `ubench.console_write bytes=4096 cpus=1` | kernel | 51008 | 115835 |
| `fsbench.read size=16 path=inline cpus=1` | all | 5704 | 11294 |
| `fsbench.read size=16 path=inline cpus=1` | /tests/fixtures/programs/fsbench | 582 | 1547 |
| `fsbench.read size=16 path=inline cpus=1` | fatfs:/ | 2121 | 5737 |
| `fsbench.read size=16 path=inline cpus=1` | fatfs:/data | 223 | 230 |
| `fsbench.read size=16 path=inline cpus=1` | kernel | 2778 | 3780 |
| `fsbench.read size=16 path=frame cpus=1` | all | 41851 | 63903 |
| `fsbench.read size=16 path=frame cpus=1` | /tests/fixtures/programs/fsbench | 11332 | 27048 |
| `fsbench.read size=16 path=frame cpus=1` | fatfs:/ | 4251 | 5984 |
| `fsbench.read size=16 path=frame cpus=1` | fatfs:/data | 0 | 27 |
| `fsbench.read size=16 path=frame cpus=1` | kernel | 26268 | 30844 |
| `fsbench.read size=1024 path=inline cpus=1` | all | 30081 | 56815 |
| `fsbench.read size=1024 path=inline cpus=1` | /tests/fixtures/programs/fsbench | 2663 | 7271 |
| `fsbench.read size=1024 path=inline cpus=1` | fatfs:/ | 10604 | 30482 |
| `fsbench.read size=1024 path=inline cpus=1` | fatfs:/data | 3696 | 3370 |
| `fsbench.read size=1024 path=inline cpus=1` | kernel | 13118 | 15692 |
| `fsbench.read size=1024 path=frame cpus=1` | all | 41851 | 63903 |
| `fsbench.read size=1024 path=frame cpus=1` | /tests/fixtures/programs/fsbench | 11332 | 27048 |
| `fsbench.read size=1024 path=frame cpus=1` | fatfs:/ | 4251 | 5984 |
| `fsbench.read size=1024 path=frame cpus=1` | fatfs:/data | 0 | 27 |
| `fsbench.read size=1024 path=frame cpus=1` | kernel | 26268 | 30844 |
| `fsbench.read size=4096 path=inline cpus=1` | all | 120189 | 227119 |
| `fsbench.read size=4096 path=inline cpus=1` | /tests/fixtures/programs/fsbench | 10517 | 28943 |
| `fsbench.read size=4096 path=inline cpus=1` | fatfs:/ | 42416 | 121928 |
| `fsbench.read size=4096 path=inline cpus=1` | fatfs:/data | 14784 | 13480 |
| `fsbench.read size=4096 path=inline cpus=1` | kernel | 52472 | 62768 |
| `fsbench.read size=4096 path=frame cpus=1` | all | 41851 | 63903 |
| `fsbench.read size=4096 path=frame cpus=1` | /tests/fixtures/programs/fsbench | 11332 | 27048 |
| `fsbench.read size=4096 path=frame cpus=1` | fatfs:/ | 4251 | 5984 |
| `fsbench.read size=4096 path=frame cpus=1` | fatfs:/data | 0 | 27 |
| `fsbench.read size=4096 path=frame cpus=1` | kernel | 26268 | 30844 |
| `fsbench.read size=16384 path=inline cpus=1` | all | 492765 | 922819 |
| `fsbench.read size=16384 path=inline cpus=1` | /tests/fixtures/programs/fsbench | 41933 | 115631 |
| `fsbench.read size=16384 path=inline cpus=1` | fatfs:/ | 180080 | 499856 |
| `fsbench.read size=16384 path=inline cpus=1` | fatfs:/data | 60864 | 55840 |
| `fsbench.read size=16384 path=inline cpus=1` | kernel | 209888 | 251492 |
| `fsbench.read size=16384 path=frame cpus=1` | all | 167888 | 256177 |
| `fsbench.read size=16384 path=frame cpus=1` | /tests/fixtures/programs/fsbench | 45193 | 108051 |
| `fsbench.read size=16384 path=frame cpus=1` | fatfs:/ | 17623 | 24630 |
| `fsbench.read size=16384 path=frame cpus=1` | fatfs:/data | 0 | 120 |
| `fsbench.read size=16384 path=frame cpus=1` | kernel | 105072 | 123376 |
| `fsbench.read size=65536 path=inline cpus=1` | all | 2155291 | 3905359 |
| `fsbench.read size=65536 path=inline cpus=1` | /tests/fixtures/programs/fsbench | 167597 | 462383 |
| `fsbench.read size=65536 path=inline cpus=1` | fatfs:/ | 881928 | 2188677 |
| `fsbench.read size=65536 path=inline cpus=1` | fatfs:/data | 265352 | 248331 |
| `fsbench.read size=65536 path=inline cpus=1` | kernel | 840414 | 1005968 |
| `fsbench.read size=65536 path=frame cpus=1` | all | 674341 | 1027915 |
| `fsbench.read size=65536 path=frame cpus=1` | /tests/fixtures/programs/fsbench | 180637 | 432063 |
| `fsbench.read size=65536 path=frame cpus=1` | fatfs:/ | 72985 | 101484 |
| `fsbench.read size=65536 path=frame cpus=1` | fatfs:/data | 0 | 444 |
| `fsbench.read size=65536 path=frame cpus=1` | kernel | 420719 | 493924 |
| `fsbench.open depth=3 cpus=1` | all | 70175 | 97439 |
| `fsbench.open depth=3 cpus=1` | /tests/fixtures/programs/fsbench | 3416 | 7171 |
| `fsbench.open depth=3 cpus=1` | fatfs:/ | 28137 | 41158 |
| `fsbench.open depth=3 cpus=1` | fatfs:/data | 15 | 83 |
| `fsbench.open depth=3 cpus=1` | vfsd | 1180 | 3578 |
| `fsbench.open depth=3 cpus=1` | kernel | 37427 | 45449 |

#### `ubench.ipc_rt words=0 cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `compiler_builtins::mem::memcpy` | ubench | | 1448 |
| `memset` | ubench | 93 | 667 |
| `memcpy` | ubench | 347 | 10 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | 279 |
| `kernel::sched::schedule` | kernel | 172 | 228 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 186 | |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | 114 |
| `<kernel::sync::Spinlock>::lock_raw` | kernel | 99 | 68 |
| `<kernel::sched::run_queue::PerCpuScheduler>::dequeue_highest` | kernel | 32 | 92 |
| `kernel::arch::current::context::switch` | kernel | 92 | 74 |
| `kernel::syscall::pin_checked` | kernel | 84 | 90 |
| `kernel::syscall::ipc::sys_ipc_call` | kernel | 62 | 74 |
| `kernel::sched::enqueue_and_wake` | kernel | 46 | 72 |
| `kernel::syscall::dispatch` | kernel | 69 | 21 |
| `kernel::arch::current::fpu::restore_fp_from` | kernel | | 68 |
| `ipc::ipc_call_timeout` | ubench | 48 | 61 |
| `kernel::arch::current::cpu::save_and_disable_interrupts` | kernel | 58 | 26 |
| `kernel::arch::current::interrupts::handle_trap` | kernel | | 57 |
| `kernel::syscall::dispatch_in_range` | kernel | 57 | 45 |
| `ubench::ipc_rt::serve` | ubench | 57 | 52 |
| `kernel::ipc::endpoint::endpoint_call` | kernel | 21 | 56 |
| `kernel::arch::current::cpu::restore_interrupts` | kernel | 35 | 54 |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 24 | 50 |
| `kernel::syscall::ipc::sys_ipc_reply` | kernel | 28 | 50 |
| `ipc::ipc_recv_timeout` | ubench | 36 | 50 |
| `kernel::syscall::ipc::sys_ipc_recv` | kernel | 26 | 48 |
| `<kernel::sched::run_queue::PerCpuScheduler>::link` | kernel | 44 | 42 |
| `kernel::sched::commit_blocked_under_local_lock` | kernel | 31 | 40 |
| `<kernel::sync::Spinlock>::unlock_raw` | kernel | 13 | 39 |
| `kernel::arch::current::fpu::save_v_to` | kernel | | 36 |
| `kernel::arch::current::encoding::ticks_to_us` | kernel | | 34 |
| `kernel::arch::current::fpu::restore_v_from` | kernel | | 34 |
| `kernel::arch::current::fpu::set_frame_units` | kernel | | 34 |
| `kernel::ipc::endpoint::bind_next_sender` | kernel | 18 | 34 |
| `kernel::syscall::ipc::deliver_message` | kernel | 32 | 34 |
| `kernel::syscall::pin_checked::{closure#0}` | kernel | 24 | 34 |
| `memcpy` | kernel | 32 | 4 |
| `<kernel::arch::current::trap_frame::TrapFrame>::arg` | kernel | 30 | 6 |
| `<kernel::ipc::message::Message>::caps` | kernel | 28 | 26 |
| `kernel::arch::current::fpu::switch_in_restore` | kernel | 18 | 28 |
| 127 functions below 25 each |  | 781 | 766 |

#### `ubench.ipc_rt words=6 cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `compiler_builtins::mem::memcpy` | ubench | | 1592 |
| `memset` | ubench | 93 | 667 |
| `memcpy` | ubench | 397 | 14 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | 279 |
| `kernel::sched::schedule` | kernel | 172 | 228 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 186 | |
| `compiler_builtins::mem::memcpy` | kernel | | 162 |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | 114 |
| `<kernel::sync::Spinlock>::lock_raw` | kernel | 99 | 68 |
| `ipc::ipc_call_timeout` | ubench | 72 | 98 |
| `<kernel::sched::run_queue::PerCpuScheduler>::dequeue_highest` | kernel | 32 | 92 |
| `kernel::arch::current::context::switch` | kernel | 92 | 74 |
| `kernel::syscall::pin_checked` | kernel | 84 | 90 |
| `memcpy` | kernel | 82 | 8 |
| `ipc::ipc_recv_timeout` | ubench | 53 | 77 |
| `kernel::syscall::ipc::sys_ipc_call` | kernel | 64 | 74 |
| `kernel::sched::enqueue_and_wake` | kernel | 46 | 72 |
| `kernel::syscall::dispatch` | kernel | 69 | 21 |
| `kernel::arch::current::fpu::restore_fp_from` | kernel | | 68 |
| `kernel::arch::current::cpu::save_and_disable_interrupts` | kernel | 58 | 26 |
| `ubench::ipc_rt::serve` | ubench | 58 | 53 |
| `kernel::arch::current::interrupts::handle_trap` | kernel | | 57 |
| `kernel::syscall::dispatch_in_range` | kernel | 57 | 45 |
| `kernel::ipc::endpoint::endpoint_call` | kernel | 21 | 56 |
| `kernel::arch::current::cpu::restore_interrupts` | kernel | 35 | 54 |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 24 | 50 |
| `kernel::syscall::ipc::sys_ipc_reply` | kernel | 28 | 50 |
| `kernel::syscall::ipc::sys_ipc_recv` | kernel | 26 | 48 |
| `<kernel::arch::current::trap_frame::TrapFrame>::set_msg_regs` | kernel | 46 | 46 |
| `<kernel::sched::run_queue::PerCpuScheduler>::link` | kernel | 44 | 42 |
| `kernel::sched::commit_blocked_under_local_lock` | kernel | 31 | 40 |
| `<kernel::sync::Spinlock>::unlock_raw` | kernel | 13 | 39 |
| `kernel::arch::current::fpu::save_v_to` | kernel | | 36 |
| `kernel::arch::current::encoding::ticks_to_us` | kernel | | 34 |
| `kernel::arch::current::fpu::restore_v_from` | kernel | | 34 |
| `kernel::arch::current::fpu::set_frame_units` | kernel | | 34 |
| `kernel::ipc::endpoint::bind_next_sender` | kernel | 18 | 34 |
| `kernel::syscall::ipc::deliver_message` | kernel | 32 | 34 |
| `kernel::syscall::pin_checked::{closure#0}` | kernel | 24 | 34 |
| `ipc::ipc_reply` | ubench | 32 | 31 |
| `<kernel::arch::current::trap_frame::TrapFrame>::arg` | kernel | 30 | 6 |
| `<kernel::ipc::message::Message>::caps` | kernel | 28 | 26 |
| `kernel::arch::current::fpu::switch_in_restore` | kernel | 18 | 28 |
| 130 functions below 27 each |  | 805 | 773 |

#### `ubench.ipc_rt words=7 cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `compiler_builtins::mem::memcpy` | ubench | | 1495 |
| `memset` | ubench | 93 | 667 |
| `memcpy` | ubench | 354 | 10 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | 279 |
| `__copy_user_fault_start` | kernel | 228 | |
| `kernel::sched::schedule` | kernel | 172 | 228 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 186 | |
| `__copy_user_words` | kernel | | 180 |
| `ipc::ipc_call_timeout` | ubench | 134 | 139 |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | 114 |
| `<kernel::sync::Spinlock>::lock_raw` | kernel | 99 | 68 |
| `<kernel::sched::run_queue::PerCpuScheduler>::dequeue_highest` | kernel | 32 | 92 |
| `kernel::arch::current::context::switch` | kernel | 92 | 74 |
| `kernel::syscall::pin_checked` | kernel | 84 | 90 |
| `ipc::ipc_recv_timeout` | ubench | 77 | 82 |
| `kernel::syscall::ipc::sys_ipc_call` | kernel | 64 | 74 |
| `ipc::ipc_reply` | ubench | 74 | 73 |
| `kernel::sched::enqueue_and_wake` | kernel | 46 | 72 |
| `kernel::syscall::dispatch` | kernel | 69 | 21 |
| `kernel::arch::current::fpu::restore_fp_from` | kernel | | 68 |
| `compiler_builtins::mem::memcpy` | kernel | | 65 |
| `kernel::arch::current::cpu::save_and_disable_interrupts` | kernel | 58 | 26 |
| `ubench::ipc_rt::serve` | ubench | 58 | 53 |
| `kernel::arch::current::interrupts::handle_trap` | kernel | | 57 |
| `kernel::syscall::dispatch_in_range` | kernel | 57 | 45 |
| `kernel::ipc::endpoint::endpoint_call` | kernel | 21 | 56 |
| `kernel::arch::current::cpu::restore_interrupts` | kernel | 35 | 54 |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 24 | 50 |
| `kernel::syscall::ipc::sys_ipc_reply` | kernel | 28 | 50 |
| `kernel::syscall::ipc::sys_ipc_recv` | kernel | 26 | 48 |
| `<kernel::sched::run_queue::PerCpuScheduler>::link` | kernel | 44 | 42 |
| `kernel::sched::commit_blocked_under_local_lock` | kernel | 31 | 40 |
| `<kernel::sync::Spinlock>::unlock_raw` | kernel | 13 | 39 |
| `memcpy` | kernel | 39 | 4 |
| `kernel::arch::current::fpu::save_v_to` | kernel | | 36 |
| `kernel::arch::current::encoding::ticks_to_us` | kernel | | 34 |
| `kernel::arch::current::fpu::restore_v_from` | kernel | | 34 |
| `kernel::arch::current::fpu::set_frame_units` | kernel | | 34 |
| `kernel::ipc::endpoint::bind_next_sender` | kernel | 18 | 34 |
| `kernel::syscall::ipc::deliver_message` | kernel | 32 | 34 |
| `kernel::syscall::pin_checked::{closure#0}` | kernel | 24 | 34 |
| `__copy_user` | kernel | 12 | 32 |
| `<kernel::arch::current::trap_frame::TrapFrame>::arg` | kernel | 30 | 6 |
| `<kernel::ipc::message::Message>::caps` | kernel | 28 | 26 |
| `kernel::arch::current::fpu::switch_in_restore` | kernel | 18 | 28 |
| 134 functions below 27 each |  | 816 | 781 |

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
| `ipc::ipc_recv_timeout` | ubench | 255 | 367 |
| `compiler_builtins::mem::memcpy` | kernel | | 350 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | 279 |
| `kernel::sched::schedule` | kernel | 172 | 228 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 186 | |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | 114 |
| `<kernel::sync::Spinlock>::lock_raw` | kernel | 99 | 68 |
| `memcpy` | kernel | 96 | 4 |
| `<kernel::sched::run_queue::PerCpuScheduler>::dequeue_highest` | kernel | 32 | 92 |
| `kernel::arch::current::context::switch` | kernel | 92 | 74 |
| `kernel::syscall::pin_checked` | kernel | 84 | 90 |
| `kernel::syscall::ipc::sys_ipc_call` | kernel | 64 | 75 |
| `kernel::sched::enqueue_and_wake` | kernel | 46 | 72 |
| `kernel::syscall::dispatch` | kernel | 69 | 21 |
| `kernel::arch::current::fpu::restore_fp_from` | kernel | | 68 |
| `kernel::arch::current::cpu::save_and_disable_interrupts` | kernel | 58 | 26 |
| `ubench::ipc_rt::serve` | ubench | 58 | 53 |
| `kernel::arch::current::interrupts::handle_trap` | kernel | | 57 |
| `kernel::syscall::dispatch_in_range` | kernel | 57 | 45 |
| `kernel::ipc::endpoint::endpoint_call` | kernel | 21 | 56 |
| `kernel::arch::current::cpu::restore_interrupts` | kernel | 35 | 54 |
| `kernel::syscall::ipc::sys_ipc_reply` | kernel | 28 | 51 |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 24 | 50 |
| `kernel::syscall::ipc::sys_ipc_recv` | kernel | 26 | 48 |
| `<kernel::sched::run_queue::PerCpuScheduler>::link` | kernel | 44 | 42 |
| `kernel::sched::commit_blocked_under_local_lock` | kernel | 31 | 40 |
| `<kernel::sync::Spinlock>::unlock_raw` | kernel | 13 | 39 |
| 146 functions below 39 each |  | 978 | 1121 |

#### `ubench.fault_fill path=fault pages=16 cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `memset` | memmgr | 8298 | 24812 |
| `boot_protocol::riscv_paging::level_shift` | kernel | | 2136 |
| `<memmgr::MappedSlots as memmgr_free_pool::arena::SlotStore>::read` | memmgr | 1287 | 1498 |
| `<kernel::mm::address_space::AddressSpace>::map_page_pooled` | kernel | 608 | 1344 |
| `kernel::arch::current::paging::install_user_leaf` | kernel | | 1216 |
| `kernel::arch::current::paging::entry` | kernel | 48 | 1161 |
| `<kernel::mm::frame_map::FrameMap>::counter` | kernel | 896 | 1152 |
| `compiler_builtins::mem::memcpy` | memmgr | | 1119 |
| `boot_protocol::x86_paging::level_shift` | kernel | 1065 | |
| `kernel::arch::current::paging::names_table` | kernel | 975 | |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | 930 |
| `boot_protocol::x86_paging::table_index` | kernel | 921 | |
| `kernel::syscall::mem::sys_mem_map` | kernel | 876 | 914 |
| `kernel::arch::current::paging::descend_existing::<kernel::mm::paging::phys_to_virt>` | kernel | 48 | 682 |
| `<kernel::mm::frame_map::FrameMap>::slot` | kernel | 674 | 608 |
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
| `<memmgr_free_pool::arena::ArenaLayout>::slot_va` | memmgr | 391 | 450 |
| `<kernel::mm::address_space::AddressSpace>::pt_lock` | kernel | 144 | 416 |
| `<kernel::mm::frame_map::FrameMap>::lower` | kernel | 208 | 416 |
| `compiler_builtins::mem::memcpy` | kernel | | 401 |
| `<kernel::arch::current::paging::PageTableEntry>::new_page` | kernel | 352 | 384 |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | 382 |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 192 | 374 |
| `memmgr_free_pool::chunk::child::<memmgr::MappedSlots>` | memmgr | 262 | 366 |
| `memmgr_free_pool::chunk::leaf::<memmgr::MappedSlots>` | memmgr | 303 | 225 |
| `kernel::arch::current::paging::user_va_top` | kernel | 298 | 109 |
| `kernel::arch::current::paging::direct_map_base` | kernel | 295 | 294 |
| `kernel::mm::paging::phys_to_virt` | kernel | 293 | 292 |
| `kernel::arch::current::paging::new_user_leaf` | kernel | 288 | |
| `kernel::arch::current::paging::user_walk_or_alloc_pooled` | kernel | 288 | |
| 455 functions below 288 each |  | 11431 | 12563 |

#### `ubench.fault_fill path=grant pages=16 cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `memset` | memmgr | 8388 | 25041 |
| `compiler_builtins::mem::memcpy` | memmgr | | 2846 |
| `boot_protocol::riscv_paging::level_shift` | kernel | | 2112 |
| `<kernel::mm::address_space::AddressSpace>::map_page_pooled` | kernel | 608 | 1344 |
| `kernel::arch::current::paging::install_user_leaf` | kernel | | 1216 |
| `<kernel::mm::frame_map::FrameMap>::counter` | kernel | 896 | 1152 |
| `kernel::arch::current::paging::entry` | kernel | 48 | 1152 |
| `boot_protocol::x86_paging::level_shift` | kernel | 1056 | |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | 1023 |
| `kernel::arch::current::paging::names_table` | kernel | 960 | |
| `kernel::syscall::mem::sys_mem_map` | kernel | 876 | 914 |
| `boot_protocol::x86_paging::table_index` | kernel | 912 | |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 682 | |
| `<kernel::mm::frame_map::FrameMap>::slot` | kernel | 674 | 608 |
| `kernel::arch::current::paging::descend_existing::<kernel::mm::paging::phys_to_virt>` | kernel | 48 | 672 |
| `kernel::mm::tlb_shootdown::shootdown_range` | kernel | 416 | 640 |
| `compiler_builtins::mem::memcpy` | kernel | | 635 |
| `kernel::syscall::pin_checked` | kernel | 359 | 630 |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 348 | 629 |
| `<memmgr::MappedSlots as memmgr_free_pool::arena::SlotStore>::read` | memmgr | 476 | 620 |
| `memcpy` | memmgr | 609 | 22 |
| `<kernel::arch::current::paging::PageTableEntry>::phys_addr` | kernel | 384 | 592 |
| `boot_protocol::riscv_paging::vpn_index` | kernel | | 576 |
| `<boot_protocol::riscv_paging::PagingMode>::levels` | kernel | | 560 |
| `kernel::arch::current::paging::walk_to_4k_leaf::<kernel::mm::paging::phys_to_virt>` | kernel | 560 | |
| `<kernel::mm::frame_map::FrameMap>::raise` | kernel | 288 | 544 |
| `kernel::arch::current::paging::root_level` | kernel | 528 | |
| `kernel::arch::current::paging::read_entry` | kernel | 512 | |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | 418 |
| `<kernel::mm::address_space::AddressSpace>::pt_lock` | kernel | 144 | 416 |
| `<kernel::mm::frame_map::FrameMap>::lower` | kernel | 208 | 416 |
| `<kernel::cap::cspace::CSpace>::slot_mut` | kernel | 252 | 414 |
| `<kernel::arch::current::paging::PageTableEntry>::new_page` | kernel | 352 | 384 |
| `<kernel::cap::cspace::CSpace>::leaf_ptr` | kernel | 150 | 300 |
| 468 functions below 300 each |  | 13105 | 14188 |

#### `ubench.fault_scaling threads=1 pages=16 cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `memset` | memmgr | 8298 | 24812 |
| `boot_protocol::riscv_paging::level_shift` | kernel | | 2136 |
| `<memmgr::MappedSlots as memmgr_free_pool::arena::SlotStore>::read` | memmgr | 1219 | 1390 |
| `<kernel::mm::address_space::AddressSpace>::map_page_pooled` | kernel | 608 | 1344 |
| `kernel::arch::current::paging::install_user_leaf` | kernel | | 1216 |
| `kernel::arch::current::paging::entry` | kernel | 48 | 1161 |
| `<kernel::mm::frame_map::FrameMap>::counter` | kernel | 896 | 1152 |
| `compiler_builtins::mem::memcpy` | memmgr | | 1119 |
| `boot_protocol::x86_paging::level_shift` | kernel | 1065 | |
| `kernel::arch::current::paging::names_table` | kernel | 975 | |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | 930 |
| `boot_protocol::x86_paging::table_index` | kernel | 921 | |
| `kernel::syscall::mem::sys_mem_map` | kernel | 876 | 914 |
| `kernel::arch::current::paging::descend_existing::<kernel::mm::paging::phys_to_virt>` | kernel | 48 | 682 |
| `<kernel::mm::frame_map::FrameMap>::slot` | kernel | 674 | 608 |
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
| `<kernel::mm::address_space::AddressSpace>::pt_lock` | kernel | 144 | 416 |
| `<kernel::mm::frame_map::FrameMap>::lower` | kernel | 208 | 416 |
| `compiler_builtins::mem::memcpy` | kernel | | 401 |
| `<kernel::arch::current::paging::PageTableEntry>::new_page` | kernel | 352 | 384 |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | 382 |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 192 | 374 |
| `memmgr_free_pool::chunk::child::<memmgr::MappedSlots>` | memmgr | 369 | 366 |
| `memmgr_free_pool::chunk::leaf::<memmgr::MappedSlots>` | memmgr | 369 | 225 |
| `kernel::arch::current::paging::user_va_top` | kernel | 298 | 109 |
| `kernel::arch::current::paging::direct_map_base` | kernel | 292 | 294 |
| `kernel::mm::paging::phys_to_virt` | kernel | 292 | 292 |
| `kernel::arch::current::paging::new_user_leaf` | kernel | 288 | |
| `kernel::arch::current::paging::user_walk_or_alloc_pooled` | kernel | 288 | |
| 453 functions below 287 each |  | 11191 | 12552 |

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
| 57 functions below 4597 each |  | 423 | 409 |

#### `ubench.console_write bytes=64 cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `compiler_builtins::mem::memmove` | /services/drivers/framebuffer | | 2240025 |
| `memmove` | /services/drivers/framebuffer | 448023 | 2 |
| `<framebuffer::render::FramebufferWriter>::scroll` | /services/drivers/framebuffer | 140835 | 307229 |
| `<framebuffer::render::FramebufferWriter>::draw_glyph_bitmap` | /services/drivers/framebuffer | 111825 | 200332 |
| `<framebuffer::render::FramebufferWriter>::pixel_bytes` | /services/drivers/framebuffer | 57960 | 11340 |
| 266 functions below 13860 each |  | 9018 | 13201 |

#### `ubench.console_write bytes=4096 cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `compiler_builtins::mem::memmove` | /services/drivers/framebuffer | | 143361600 |
| `memmove` | /services/drivers/framebuffer | 28673472 | 128 |
| `<framebuffer::render::FramebufferWriter>::scroll` | /services/drivers/framebuffer | 9013440 | 19662656 |
| `<framebuffer::render::FramebufferWriter>::draw_glyph_bitmap` | /services/drivers/framebuffer | 7156800 | 12820888 |
| `<framebuffer::render::FramebufferWriter>::pixel_bytes` | /services/drivers/framebuffer | 3709440 | 725760 |
| 334 functions below 885246 each |  | 388202 | 478256 |

#### `fsbench.read size=16 path=inline cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `memset` | fatfs:/ | 1154 | 3553 |
| `compiler_builtins::mem::memcpy` | fatfs:/ | | 1598 |
| `compiler_builtins::mem::memcpy` | /tests/fixtures/programs/fsbench | | 759 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | 465 |
| `memset` | /tests/fixtures/programs/fsbench | 87 | 434 |
| `memcpy` | fatfs:/ | 398 | 16 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 310 | |
| `kernel::sched::schedule` | kernel | 174 | 232 |
| `memcpy` | /tests/fixtures/programs/fsbench | 199 | 8 |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | 190 |
| `std::os::seraph::deadline_call` | /tests/fixtures/programs/fsbench | 131 | 157 |
| `<std::fs::File as alloc::io::read::Read>::read` | /tests/fixtures/programs/fsbench | 96 | 124 |
| `kernel::syscall::dispatch` | kernel | 115 | 35 |
| `fatfs::service_loop` | fatfs:/ | 113 | 104 |
| `compiler_builtins::mem::memcpy` | kernel | | 107 |
| `<kernel::sync::Spinlock>::lock_raw` | kernel | 99 | 68 |
| `kernel::arch::current::interrupts::handle_trap` | kernel | | 95 |
| `kernel::syscall::dispatch_in_range` | kernel | 95 | 75 |
| `<kernel::sched::run_queue::PerCpuScheduler>::dequeue_highest` | kernel | 32 | 92 |
| `kernel::arch::current::context::switch` | kernel | 92 | 74 |
| `kernel::syscall::pin_checked` | kernel | 84 | 90 |
| `<kernel::mm::address_space::AddressSpace>::activate` | kernel | 4 | 88 |
| `fatfs::handle_read` | fatfs:/data | 66 | 75 |
| `kernel::syscall::ipc::sys_ipc_call` | kernel | 64 | 74 |
| `memcpy` | kernel | 71 | 8 |
| `kernel::arch::current::encoding::ticks_to_us` | kernel | | 70 |
| `kernel::sched::enqueue_and_wake` | kernel | 46 | 70 |
| `kernel::arch::current::fpu::restore_fp_from` | kernel | | 68 |
| `ipc::ipc_recv_timeout` | fatfs:/ | 43 | 63 |
| `kernel::arch::current::cpu::save_and_disable_interrupts` | kernel | 58 | 26 |
| `kernel::ipc::endpoint::endpoint_call` | kernel | 21 | 56 |
| 241 functions below 56 each |  | 2152 | 2420 |

#### `fsbench.read size=16 path=frame cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `<std::fs::File as alloc::io::read::Read>::read` | /tests/fixtures/programs/fsbench | 10407 | 24744 |
| `crypto::keccak::keccak_f1600` | kernel | 12628 | 12530 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | 1953 |
| `compiler_builtins::mem::memcpy` | fatfs:/ | | 1816 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 1302 | |
| `memset` | /tests/fixtures/programs/fsbench | 175 | 871 |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | 798 |
| `compiler_builtins::mem::memcpy` | /tests/fixtures/programs/fsbench | | 769 |
| `<kernel::cap::cspace::CSpace>::slot_mut` | kernel | 456 | 690 |
| `memset` | fatfs:/ | | 651 |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 360 | 618 |
| `kernel::syscall::pin_checked` | kernel | 343 | 585 |
| `kernel::syscall::dispatch` | kernel | 483 | 147 |
| `kernel::sched::schedule` | kernel | 348 | 464 |
| `<fatfs::session::SessionPages>::va` | fatfs:/ | 436 | 356 |
| `memcpy` | fatfs:/ | 416 | 12 |
| `kernel::syscall::dispatch_in_range` | kernel | 409 | 314 |
| `<kernel::cap::cspace::CSpace>::leaf_ptr` | kernel | 204 | 408 |
| `kernel::arch::current::interrupts::handle_trap` | kernel | | 399 |
| `compiler_builtins::mem::memcpy` | kernel | | 396 |
| `<fatfs_parse::session_pool::SessionPool<fatfs::session::SessionPages>>::find` | fatfs:/ | 341 | 275 |
| `kernel::arch::current::speculation::index_mask` | kernel | 332 | 340 |
| `kernel::arch::nospec::select_ptr::<kernel::cap::cspace::CSpacePage>` | kernel | 272 | 340 |
| 479 functions below 319 each |  | 12939 | 14427 |

#### `fsbench.read size=1024 path=inline cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `memset` | fatfs:/ | 4616 | 14212 |
| `compiler_builtins::mem::memcpy` | fatfs:/ | | 13690 |
| `memcpy` | fatfs:/ | 3712 | 300 |
| `compiler_builtins::mem::memcpy` | /tests/fixtures/programs/fsbench | | 3696 |
| `fatfs::handle_read` | fatfs:/data | 2304 | 1980 |
| `__copy_user_fault_start` | kernel | 2052 | |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | 1860 |
| `memset` | /tests/fixtures/programs/fsbench | 348 | 1736 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 1240 | |
| `std::os::seraph::deadline_call` | /tests/fixtures/programs/fsbench | 874 | 1192 |
| `kernel::sched::schedule` | kernel | 696 | 928 |
| `ipc::ipc_reply` | fatfs:/data | 900 | 924 |
| `memcpy` | /tests/fixtures/programs/fsbench | 916 | 32 |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | 760 |
| `__copy_user_block_start` | kernel | | 640 |
| `<std::fs::File as alloc::io::read::Read>::read` | /tests/fixtures/programs/fsbench | 384 | 496 |
| `kernel::syscall::dispatch` | kernel | 460 | 140 |
| `fatfs::service_loop` | fatfs:/ | 452 | 416 |
| `<kernel::sync::Spinlock>::lock_raw` | kernel | 396 | 272 |
| `kernel::arch::current::interrupts::handle_trap` | kernel | | 380 |
| `kernel::syscall::dispatch_in_range` | kernel | 380 | 300 |
| `<kernel::sched::run_queue::PerCpuScheduler>::dequeue_highest` | kernel | 128 | 368 |
| `kernel::arch::current::context::switch` | kernel | 368 | 296 |
| `kernel::syscall::pin_checked` | kernel | 336 | 360 |
| `<kernel::mm::address_space::AddressSpace>::activate` | kernel | 16 | 352 |
| `compiler_builtins::mem::memcpy` | kernel | | 346 |
| `kernel::syscall::ipc::sys_ipc_call` | kernel | 256 | 296 |
| 254 functions below 284 each |  | 9247 | 10843 |

#### `fsbench.read size=1024 path=frame cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `<std::fs::File as alloc::io::read::Read>::read` | /tests/fixtures/programs/fsbench | 10407 | 24744 |
| `crypto::keccak::keccak_f1600` | kernel | 12628 | 12530 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | 1953 |
| `compiler_builtins::mem::memcpy` | fatfs:/ | | 1816 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 1302 | |
| `memset` | /tests/fixtures/programs/fsbench | 175 | 871 |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | 798 |
| `compiler_builtins::mem::memcpy` | /tests/fixtures/programs/fsbench | | 769 |
| `<kernel::cap::cspace::CSpace>::slot_mut` | kernel | 456 | 690 |
| `memset` | fatfs:/ | | 651 |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 360 | 618 |
| `kernel::syscall::pin_checked` | kernel | 343 | 585 |
| `kernel::syscall::dispatch` | kernel | 483 | 147 |
| `kernel::sched::schedule` | kernel | 348 | 464 |
| `<fatfs::session::SessionPages>::va` | fatfs:/ | 436 | 356 |
| `memcpy` | fatfs:/ | 416 | 12 |
| `kernel::syscall::dispatch_in_range` | kernel | 409 | 314 |
| `<kernel::cap::cspace::CSpace>::leaf_ptr` | kernel | 204 | 408 |
| `kernel::arch::current::interrupts::handle_trap` | kernel | | 399 |
| `compiler_builtins::mem::memcpy` | kernel | | 396 |
| `<fatfs_parse::session_pool::SessionPool<fatfs::session::SessionPages>>::find` | fatfs:/ | 341 | 275 |
| `kernel::arch::current::speculation::index_mask` | kernel | 332 | 340 |
| `kernel::arch::nospec::select_ptr::<kernel::cap::cspace::CSpacePage>` | kernel | 272 | 340 |
| 479 functions below 319 each |  | 12939 | 14427 |

#### `fsbench.read size=4096 path=inline cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `memset` | fatfs:/ | 18464 | 56848 |
| `compiler_builtins::mem::memcpy` | fatfs:/ | | 54760 |
| `memcpy` | fatfs:/ | 14848 | 1200 |
| `compiler_builtins::mem::memcpy` | /tests/fixtures/programs/fsbench | | 14784 |
| `fatfs::handle_read` | fatfs:/data | 9216 | 7920 |
| `__copy_user_fault_start` | kernel | 8208 | |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | 7440 |
| `memset` | /tests/fixtures/programs/fsbench | 1392 | 6944 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 4960 | |
| `std::os::seraph::deadline_call` | /tests/fixtures/programs/fsbench | 3496 | 4768 |
| `kernel::sched::schedule` | kernel | 2784 | 3712 |
| `ipc::ipc_reply` | fatfs:/data | 3600 | 3696 |
| `memcpy` | /tests/fixtures/programs/fsbench | 3664 | 128 |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | 3040 |
| `__copy_user_block_start` | kernel | | 2560 |
| `<std::fs::File as alloc::io::read::Read>::read` | /tests/fixtures/programs/fsbench | 1536 | 1984 |
| `kernel::syscall::dispatch` | kernel | 1840 | 560 |
| `fatfs::service_loop` | fatfs:/ | 1808 | 1664 |
| `<kernel::sync::Spinlock>::lock_raw` | kernel | 1584 | 1088 |
| `kernel::arch::current::interrupts::handle_trap` | kernel | | 1520 |
| `kernel::syscall::dispatch_in_range` | kernel | 1520 | 1200 |
| `<kernel::sched::run_queue::PerCpuScheduler>::dequeue_highest` | kernel | 512 | 1472 |
| `kernel::arch::current::context::switch` | kernel | 1472 | 1184 |
| `kernel::syscall::pin_checked` | kernel | 1344 | 1440 |
| `<kernel::mm::address_space::AddressSpace>::activate` | kernel | 64 | 1408 |
| `compiler_builtins::mem::memcpy` | kernel | | 1384 |
| `kernel::syscall::ipc::sys_ipc_call` | kernel | 1024 | 1184 |
| 254 functions below 1135 each |  | 36853 | 43231 |

#### `fsbench.read size=4096 path=frame cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `<std::fs::File as alloc::io::read::Read>::read` | /tests/fixtures/programs/fsbench | 10407 | 24744 |
| `crypto::keccak::keccak_f1600` | kernel | 12628 | 12530 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | 1953 |
| `compiler_builtins::mem::memcpy` | fatfs:/ | | 1816 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 1302 | |
| `memset` | /tests/fixtures/programs/fsbench | 175 | 871 |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | 798 |
| `compiler_builtins::mem::memcpy` | /tests/fixtures/programs/fsbench | | 769 |
| `<kernel::cap::cspace::CSpace>::slot_mut` | kernel | 456 | 690 |
| `memset` | fatfs:/ | | 651 |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 360 | 618 |
| `kernel::syscall::pin_checked` | kernel | 343 | 585 |
| `kernel::syscall::dispatch` | kernel | 483 | 147 |
| `kernel::sched::schedule` | kernel | 348 | 464 |
| `<fatfs::session::SessionPages>::va` | fatfs:/ | 436 | 356 |
| `memcpy` | fatfs:/ | 416 | 12 |
| `kernel::syscall::dispatch_in_range` | kernel | 409 | 314 |
| `<kernel::cap::cspace::CSpace>::leaf_ptr` | kernel | 204 | 408 |
| `kernel::arch::current::interrupts::handle_trap` | kernel | | 399 |
| `compiler_builtins::mem::memcpy` | kernel | | 396 |
| `<fatfs_parse::session_pool::SessionPool<fatfs::session::SessionPages>>::find` | fatfs:/ | 341 | 275 |
| `kernel::arch::current::speculation::index_mask` | kernel | 332 | 340 |
| `kernel::arch::nospec::select_ptr::<kernel::cap::cspace::CSpacePage>` | kernel | 272 | 340 |
| 479 functions below 319 each |  | 12939 | 14427 |

#### `fsbench.read size=16384 path=inline cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `memset` | fatfs:/ | 73856 | 227392 |
| `compiler_builtins::mem::memcpy` | fatfs:/ | | 219040 |
| `memcpy` | fatfs:/ | 59392 | 4800 |
| `compiler_builtins::mem::memcpy` | /tests/fixtures/programs/fsbench | | 59136 |
| `fatfs::handle_read` | fatfs:/data | 36864 | 31680 |
| `__copy_user_fault_start` | kernel | 32832 | |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | 29853 |
| `memset` | /tests/fixtures/programs/fsbench | 5568 | 27776 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 19840 | |
| `std::os::seraph::deadline_call` | /tests/fixtures/programs/fsbench | 13984 | 19072 |
| `kernel::sched::schedule` | kernel | 11136 | 14848 |
| `ipc::ipc_reply` | fatfs:/data | 14400 | 14784 |
| `memcpy` | /tests/fixtures/programs/fsbench | 14656 | 512 |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | 12200 |
| `__copy_user_block_start` | kernel | | 10240 |
| `<std::fs::File as alloc::io::read::Read>::read` | /tests/fixtures/programs/fsbench | 6144 | 7936 |
| `kernel::syscall::dispatch` | kernel | 7360 | 2240 |
| `fatfs::service_loop` | fatfs:/ | 7232 | 6656 |
| `<kernel::sync::Spinlock>::lock_raw` | kernel | 6336 | 4369 |
| `kernel::arch::current::interrupts::handle_trap` | kernel | | 6095 |
| `kernel::syscall::dispatch_in_range` | kernel | 6080 | 4800 |
| `<kernel::sched::run_queue::PerCpuScheduler>::dequeue_highest` | kernel | 2048 | 5888 |
| `kernel::arch::current::context::switch` | kernel | 5888 | 4736 |
| `kernel::syscall::pin_checked` | kernel | 5376 | 5760 |
| `<kernel::mm::address_space::AddressSpace>::activate` | kernel | 256 | 5632 |
| `compiler_builtins::mem::memcpy` | kernel | | 5536 |
| `fatfs::fat::read_file_data` | fatfs:/data | 4848 | 5056 |
| `fatfs::fat::chain_next` | fatfs:/ | 4992 | 4800 |
| `kernel::syscall::ipc::sys_ipc_call` | kernel | 4096 | 4736 |
| 282 functions below 4614 each |  | 149581 | 177246 |

#### `fsbench.read size=16384 path=frame cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `<std::fs::File as alloc::io::read::Read>::read` | /tests/fixtures/programs/fsbench | 41628 | 98976 |
| `crypto::keccak::keccak_f1600` | kernel | 50512 | 50120 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | 7812 |
| `compiler_builtins::mem::memcpy` | fatfs:/ | | 7264 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 5208 | |
| `memset` | /tests/fixtures/programs/fsbench | 700 | 3484 |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | 3192 |
| `compiler_builtins::mem::memcpy` | /tests/fixtures/programs/fsbench | | 3076 |
| `<kernel::cap::cspace::CSpace>::slot_mut` | kernel | 1824 | 2760 |
| `memset` | fatfs:/ | | 2604 |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 1440 | 2472 |
| `kernel::syscall::pin_checked` | kernel | 1372 | 2340 |
| `kernel::syscall::dispatch` | kernel | 1932 | 588 |
| `kernel::sched::schedule` | kernel | 1392 | 1856 |
| `<fatfs::session::SessionPages>::va` | fatfs:/ | 1744 | 1424 |
| `memcpy` | fatfs:/ | 1664 | 48 |
| `kernel::syscall::dispatch_in_range` | kernel | 1636 | 1256 |
| `<kernel::cap::cspace::CSpace>::leaf_ptr` | kernel | 816 | 1632 |
| `kernel::arch::current::interrupts::handle_trap` | kernel | | 1596 |
| `compiler_builtins::mem::memcpy` | kernel | | 1584 |
| `<fatfs_parse::session_pool::SessionPool<fatfs::session::SessionPages>>::find` | fatfs:/ | 1364 | 1100 |
| `kernel::arch::current::speculation::index_mask` | kernel | 1328 | 1360 |
| `kernel::arch::nospec::select_ptr::<kernel::cap::cspace::CSpacePage>` | kernel | 1088 | 1360 |
| 487 functions below 1280 each |  | 52240 | 58273 |

#### `fsbench.read size=65536 path=inline cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `memset` | fatfs:/ | 295424 | 909568 |
| `compiler_builtins::mem::memcpy` | fatfs:/ | | 876149 |
| `memcpy` | fatfs:/ | 237568 | 19200 |
| `compiler_builtins::mem::memcpy` | /tests/fixtures/programs/fsbench | | 236544 |
| `fatfs::handle_read` | fatfs:/data | 147456 | 126720 |
| `__copy_user_fault_start` | kernel | 131328 | |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | 119412 |
| `memset` | /tests/fixtures/programs/fsbench | 22272 | 111104 |
| `fatfs::fat::chain_next` | fatfs:/ | 99840 | 96000 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 79360 | |
| `fatfs::alloc::read_fat_entry` | fatfs:/ | 36480 | 76800 |
| `std::os::seraph::deadline_call` | /tests/fixtures/programs/fsbench | 55936 | 76288 |
| `kernel::sched::schedule` | kernel | 44544 | 59392 |
| `ipc::ipc_reply` | fatfs:/data | 57600 | 59136 |
| `memcpy` | /tests/fixtures/programs/fsbench | 58624 | 2048 |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | 48800 |
| `fatfs::fat::read_file_data` | fatfs:/data | 40944 | 44800 |
| `__copy_user_block_start` | kernel | | 40960 |
| `<fatfs::bpb::FatState>::fat_entry_location` | fatfs:/ | 30712 | 34560 |
| `<std::fs::File as alloc::io::read::Read>::read` | /tests/fixtures/programs/fsbench | 24576 | 31744 |
| `kernel::syscall::dispatch` | kernel | 29440 | 8960 |
| `fatfs::service_loop` | fatfs:/ | 28928 | 26624 |
| `<kernel::sync::Spinlock>::lock_raw` | kernel | 25382 | 17476 |
| `<fatfs::cache::PageCache>::lookup_cached` | fatfs:/ | 24848 | 24848 |
| `kernel::arch::current::interrupts::handle_trap` | kernel | | 24380 |
| `kernel::syscall::dispatch_in_range` | kernel | 24320 | 19200 |
| `<kernel::sched::run_queue::PerCpuScheduler>::dequeue_highest` | kernel | 8192 | 23552 |
| `kernel::arch::current::context::switch` | kernel | 23552 | 18944 |
| `kernel::syscall::pin_checked` | kernel | 21504 | 23040 |
| `<kernel::mm::address_space::AddressSpace>::activate` | kernel | 1024 | 22528 |
| `compiler_builtins::mem::memcpy` | kernel | | 22144 |
| 294 functions below 19526 each |  | 605437 | 704438 |

#### `fsbench.read size=65536 path=frame cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `<std::fs::File as alloc::io::read::Read>::read` | /tests/fixtures/programs/fsbench | 166512 | 395904 |
| `crypto::keccak::keccak_f1600` | kernel | 202048 | 200480 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | 31341 |
| `compiler_builtins::mem::memcpy` | fatfs:/ | | 29056 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 20832 | |
| `memset` | /tests/fixtures/programs/fsbench | 2800 | 13936 |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | 12808 |
| `compiler_builtins::mem::memcpy` | /tests/fixtures/programs/fsbench | | 12304 |
| `<kernel::cap::cspace::CSpace>::slot_mut` | kernel | 7296 | 11040 |
| `memset` | fatfs:/ | | 10416 |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 5760 | 9888 |
| `kernel::syscall::pin_checked` | kernel | 5488 | 9360 |
| `kernel::syscall::dispatch` | kernel | 7728 | 2352 |
| `kernel::sched::schedule` | kernel | 5568 | 7424 |
| `<fatfs::session::SessionPages>::va` | fatfs:/ | 6976 | 5696 |
| `memcpy` | fatfs:/ | 6656 | 192 |
| `kernel::syscall::dispatch_in_range` | kernel | 6544 | 5024 |
| `<kernel::cap::cspace::CSpace>::leaf_ptr` | kernel | 3264 | 6528 |
| `kernel::arch::current::interrupts::handle_trap` | kernel | | 6399 |
| `compiler_builtins::mem::memcpy` | kernel | | 6336 |
| `<fatfs_parse::session_pool::SessionPool<fatfs::session::SessionPages>>::find` | fatfs:/ | 5456 | 4400 |
| `kernel::arch::current::speculation::index_mask` | kernel | 5312 | 5440 |
| `kernel::arch::nospec::select_ptr::<kernel::cap::cspace::CSpacePage>` | kernel | 4352 | 5440 |
| 522 functions below 5139 each |  | 211749 | 236151 |

#### `fsbench.open depth=3 cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `memset` | fatfs:/ | 5009 | 14500 |
| `crypto::keccak::keccak_f1600` | kernel | 12628 | 12530 |
| `compiler_builtins::mem::memcpy` | fatfs:/ | | 8672 |
| `<fatfs::cache::PageCache>::lookup_cached` | fatfs:/ | 4902 | 1185 |
| `<fatfs_parse::LfnAccum>::add_lfn_entry` | fatfs:/ | 4168 | 4350 |
| `fatfs::dir::scan_sector_for_name` | fatfs:/ | 3012 | 3728 |
| `compiler_builtins::mem::memcpy` | /tests/fixtures/programs/fsbench | | 3420 |
| `<fatfs_parse::LfnAccum>::assemble_utf8` | fatfs:/ | 2786 | 2128 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | 2604 |
| `compiler_builtins::mem::memcpy` | vfsd | | 2359 |
| `<kernel::cap::cspace::CSpace>::slot_mut` | kernel | 1248 | 2092 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 1736 | |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 924 | 1520 |
| `memcpy` | fatfs:/ | 1364 | 60 |
| `memset` | /tests/fixtures/programs/fsbench | 260 | 1299 |
| `<kernel::cap::cspace::CSpace>::leaf_ptr` | kernel | 543 | 1086 |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | 1064 |
| `std::sys::fs::seraph::walk_components` | /tests/fixtures/programs/fsbench | 958 | 891 |
| `std::sys::alloc::seraph::alloc` | fatfs:/ | 948 | 666 |
| `kernel::syscall::pin_checked` | kernel | 540 | 945 |
| `kernel::arch::nospec::select_ptr::<kernel::cap::cspace::CSpacePage>` | kernel | 724 | 905 |
| `compiler_builtins::mem::memcpy` | kernel | | 891 |
| `memcpy` | /tests/fixtures/programs/fsbench | 861 | 32 |
| `<fatfs::cache::PageCache>::pages_held` | fatfs:/ | 781 | 775 |
| `<fatfs::cache::PageCache>::pages_held::{closure#0}` | fatfs:/ | 256 | 768 |
| `<kernel::cap::registry::CSpaceRegistry>::entry` | kernel | 595 | 768 |
| `<kernel::cap::registry::CSpaceRegistry>::slot` | kernel | 636 | 747 |
| `<fatfs_parse::LfnAccum>::matches` | fatfs:/ | 716 | |
| `kernel::arch::current::speculation::index_mask` | kernel | 700 | 708 |
| `kernel::sched::schedule` | kernel | 522 | 696 |
| `memset` | vfsd | 88 | 651 |
| `kernel::syscall::dispatch` | kernel | 646 | 198 |
| `<kernel::cap::registry::CSpaceRegistry>::lookup` | kernel | 589 | 549 |
| `memcpy` | vfsd | 584 | 22 |
| `kernel::cap::cspace::load_at::<kernel::cap::cspace::CSpacePage>` | kernel | | 543 |
| `kernel::syscall::dispatch_in_range` | kernel | 539 | 418 |
| `<kernel::sync::Spinlock>::lock_raw` | kernel | 535 | 382 |
| `kernel::arch::current::interrupts::handle_trap` | kernel | | 532 |
| `kernel::cap::derivation::resolve_slot_mut` | kernel | 522 | 143 |
| `kernel::syscall::ipc::transfer_caps` | kernel | 444 | 500 |
| 455 functions below 487 each |  | 19411 | 22112 |

<!-- path-account: end -->

---

## Summarized By

[core/kernel/README.md](../README.md), [Kernel Hot-Path Instruction Account](hot-path-account.md)
