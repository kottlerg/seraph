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
the date, the QEMU version, and the reference it was checked against. The block, and every
figure the prose below draws from it, describe the tree at that head, not `master`'s current
one. Which PRs regenerate this account, and its regeneration at each release, are stated in
[hot-path-account.md](hot-path-account.md) § Regenerating It; a regeneration covers both
architectures. Beside ubench's and fsbench's own code, the windows run the kernel's syscall,
IPC, page-fault and scheduling paths, memmgr, vfsd, both fatfs instances, the framebuffer driver
and the IOMMU driver (the Totals table gives each image's share), so a change to any of them
can move these rows. The commands and their host time are in
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

The figures are release, x86_64 / riscv64, at the head the block's first table names
(§ Regenerating It). Each heading's cut, where one is named, is an Issue
under #1531; the kernel account's list ([hot-path-account.md](hot-path-account.md)
§ Ranked Cuts) records them and says how the next cuts are ranked.

### IPC Round Trip

`ubench.ipc_rt words=0` is 2825 / 5113, 2168 / 2764 of it in the kernel. The kernel copies and
zeroes no whole `Message` on either side: its largest functions are the entries
(`syscall_entry` 186 on x86_64; `trap_entry` and `trap_dispatch`, 279 and 114, on riscv64) and
`schedule` (172 / 228). On riscv64 ubench moves the message through `compiler_builtins`' word
loops (`memcpy` 1448, `memset` 667). Each switch-in makes the incoming thread's floating-point
and vector state live (`fpu::switch_in_restore`, 18 / 32): on riscv64 it loads the F/D and V
files (`restore_fp_from` 68, `restore_v_from` 34) and each switch-out saves the dirty V file
(`save_v_to` 36); x86_64's `XSAVE` and `XRSTOR` fall in the closing row. The kernel finds the
receiver in the CPU's parked-receiver table through the endpoint's slot hint for that CPU, one slot
read, so its cost does not follow the slot the endpoint holds, which the order of earlier parks sets
([hot-path-account.md](hot-path-account.md) § Context Switch and IPC).

### Page Faults

`ubench.fault_fill path=fault pages=16` is 34111 / 57872: memmgr 14069 / 31896, of which its
`memset` zeroing the 16 frames is 8298 / 24812 (x86_64's `rep stos` is about one iteration per 8
bytes, riscv64's loop about one instruction per 2.6 bytes), and the kernel 20028 / 25968, spread
over the page-table walk and install (`level_shift`, `table_index`, `names_table`, `read_entry`,
`install_user_leaf`), the frame map's counters, and `sys_mem_map`. `fault_scaling threads=1` runs
the same path. `path=grant` adds the grant's capability operations, 34012 / 60297. memmgr selects
the run by its size class in the same steps whatever runs the pool holds
([memory-pool.md](../../../services/memmgr/docs/memory-pool.md) § Free-Pool Data Structure), so
these rows do not follow the order of the boot's earlier frees.

### Shared-Memory Ring

`ubench.shmem_ring` runs in ubench alone. The ring copies each write and read as at most two
contiguous segments, so a transfer is almost all `memcpy`: the 4096-byte `wrap=no` row
(1352 / 5399) spends 1152 / 5256 in it, about 0.3 / 1.3 instructions per byte, and
`shmem_ring::transfer` is 186 / 136. `wrap=yes` splits the first write and read in two, and
every ring-full of a larger transfer: on riscv64 the splits add 24 instructions per ring-full of
copy setup (48 at 4096 bytes, 768 at 65536), and on x86_64, whose `memcpy` costs the same
instructions at any length, none. The 64- and 512-byte rows are a few hundred instructions each,
mostly the copies' setup.

### Pipeline

`ubench.pipeline work=0` is 23308 / 28477 per window of 64 items, 6022 / 7826 of it in the
kernel: the notifications that start and end the window and the ring's doorbell waits and wakes
(`sys_notification_wait`, `sys_notification_send`, `schedule`). ubench's part is the copies
through the ring (`memcpy`, 5120 / 9472), `send` and `receive`. At a larger `work` the window is
almost all `spin` (50332162 / 50331969 of 50379199 / 50385809 at 65536), and the kernel's part
grows with the window, to 30023 / 33254 at 65536.

### Console Writes

`ubench.console_write bytes=4096` is 33430807 / 149876635, all but 0.2 % in the framebuffer
driver. Its scroll moves the whole framebuffer up a text row at each line it fills, one
`memmove` of whole pixel words (28673472 / 143361728), and fills the freed row with `memset`
(820544 / 2460720 with the other fills); drawing the glyphs with plain word stores is
3459456 / 3518344.

### File Reads and Opens

A read through the inline path (`fsbench.read path=inline`) is fatfs's copy and zeroing of the reply
and the kernel's copy to and from user memory. A read through granted frames (`path=frame`) spends
12628 / 12530 in the kernel's Keccak permutation (`keccak_f1600`) per 4 KiB frame the grant names,
202048 / 200480 of 678699 / 1028617 at 64 KiB: std draws each request's 8-byte cookie through
`SYS_GETRANDOM`, fresh output with its own squeeze and ratchet
([entropy.md](entropy.md) § Draw API and consumers). `fsbench.open depth=3` is 65227 / 95477, one
such draw (12628 / 12530, the release badge `File::open` allocates) and
fatfs's long-name parsing (`LfnAccum`, 7670 / 6478) among it. fatfs finds each cached page through
its page index, a binary search whose steps the slot ceiling alone sets, rather than a scan of
the slots in the order they were filled, which follows the requests served before the benchmark
([services/fs/fat/docs/storage-layout.md](../../../services/fs/fat/docs/storage-layout.md)).

The fsbench client is pinned to CPU 0 and fatfs runs at an RT level above it, so each call's
wake places fatfs with the client's CPU left out ([scheduler.md](scheduler.md) § Thread
Assignment). On one CPU no other is eligible, and the scans that find none before the wake
returns that CPU (`place_rt_wake`, `place_by_rank_and_load`, `least_loaded_cpu`) are about 65
instructions of each call. A fault's delivery to memmgr and ubench's calls to the framebuffer
driver pay the same.

## Account

<!-- path-account: begin; generated by cargo xtask path-account write -->

| Configuration | Head | Taken | QEMU | Checked against |
|---|---|---|---|---|
| x86_64 release | `99f25027abb4` | 2026-11-27 | QEMU emulator version 11.1.3 | 1 icount boot(s) of the image without debuginfo |
| riscv64 release | `99f25027abb4` | 2026-11-27 | QEMU emulator version 11.1.3 | 1 icount boot(s) of the image without debuginfo |

#### Totals

| Path | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `ubench.ipc_rt words=0 cpus=1` | all | 2825 | 5113 |
| `ubench.ipc_rt words=0 cpus=1` | ubench | 657 | 2349 |
| `ubench.ipc_rt words=0 cpus=1` | kernel | 2168 | 2764 |
| `ubench.ipc_rt words=6 cpus=1` | all | 3071 | 5574 |
| `ubench.ipc_rt words=6 cpus=1` | ubench | 758 | 2568 |
| `ubench.ipc_rt words=6 cpus=1` | kernel | 2313 | 3006 |
| `ubench.ipc_rt words=7 cpus=1` | all | 3318 | 5636 |
| `ubench.ipc_rt words=7 cpus=1` | ubench | 843 | 2557 |
| `ubench.ipc_rt words=7 cpus=1` | kernel | 2475 | 3079 |
| `ubench.ipc_rt words=64 cpus=1` | all | 6296 | 7930 |
| `ubench.ipc_rt words=64 cpus=1` | ubench | 1940 | 4096 |
| `ubench.ipc_rt words=64 cpus=1` | kernel | 4356 | 3834 |
| `ubench.fault_fill path=fault pages=16 cpus=1` | all | 34111 | 57872 |
| `ubench.fault_fill path=fault pages=16 cpus=1` | ubench | 14 | 8 |
| `ubench.fault_fill path=fault pages=16 cpus=1` | memmgr | 14069 | 31896 |
| `ubench.fault_fill path=fault pages=16 cpus=1` | kernel | 20028 | 25968 |
| `ubench.fault_fill path=grant pages=16 cpus=1` | all | 34012 | 60297 |
| `ubench.fault_fill path=grant pages=16 cpus=1` | ubench | 117 | 352 |
| `ubench.fault_fill path=grant pages=16 cpus=1` | memmgr | 11149 | 30365 |
| `ubench.fault_fill path=grant pages=16 cpus=1` | kernel | 22746 | 29580 |
| `ubench.fault_scaling threads=1 pages=16 cpus=1` | all | 34111 | 57881 |
| `ubench.fault_scaling threads=1 pages=16 cpus=1` | ubench | 14 | 8 |
| `ubench.fault_scaling threads=1 pages=16 cpus=1` | memmgr | 14069 | 31896 |
| `ubench.fault_scaling threads=1 pages=16 cpus=1` | kernel | 20028 | 25977 |
| `ubench.shmem_ring bytes=64 wrap=no cpus=1` | all | 189 | 225 |
| `ubench.shmem_ring bytes=64 wrap=no cpus=1` | ubench | 189 | 225 |
| `ubench.shmem_ring bytes=64 wrap=yes cpus=1` | all | 189 | 249 |
| `ubench.shmem_ring bytes=64 wrap=yes cpus=1` | ubench | 189 | 249 |
| `ubench.shmem_ring bytes=512 wrap=no cpus=1` | all | 301 | 785 |
| `ubench.shmem_ring bytes=512 wrap=no cpus=1` | ubench | 301 | 785 |
| `ubench.shmem_ring bytes=512 wrap=yes cpus=1` | all | 301 | 809 |
| `ubench.shmem_ring bytes=512 wrap=yes cpus=1` | ubench | 301 | 809 |
| `ubench.shmem_ring bytes=4096 wrap=no cpus=1` | all | 1352 | 5399 |
| `ubench.shmem_ring bytes=4096 wrap=no cpus=1` | ubench | 1352 | 5399 |
| `ubench.shmem_ring bytes=4096 wrap=yes cpus=1` | all | 1352 | 5447 |
| `ubench.shmem_ring bytes=4096 wrap=yes cpus=1` | ubench | 1352 | 5447 |
| `ubench.shmem_ring bytes=65536 wrap=no cpus=1` | all | 21362 | 86219 |
| `ubench.shmem_ring bytes=65536 wrap=no cpus=1` | ubench | 21362 | 86219 |
| `ubench.shmem_ring bytes=65536 wrap=yes cpus=1` | all | 21362 | 86987 |
| `ubench.shmem_ring bytes=65536 wrap=yes cpus=1` | ubench | 21362 | 86987 |
| `ubench.pipeline work=0 cpus=1` | all | 23308 | 28477 |
| `ubench.pipeline work=0 cpus=1` | ubench | 17286 | 20651 |
| `ubench.pipeline work=0 cpus=1` | kernel | 6022 | 7826 |
| `ubench.pipeline work=1024 cpus=1` | all | 810451 | 815613 |
| `ubench.pipeline work=1024 cpus=1` | ubench | 803974 | 807339 |
| `ubench.pipeline work=1024 cpus=1` | kernel | 6477 | 8274 |
| `ubench.pipeline work=8192 cpus=1` | all | 6318205 | 6323587 |
| `ubench.pipeline work=8192 cpus=1` | ubench | 6308998 | 6312363 |
| `ubench.pipeline work=8192 cpus=1` | kernel | 9207 | 11224 |
| `ubench.pipeline work=65536 cpus=1` | all | 50379199 | 50385809 |
| `ubench.pipeline work=65536 cpus=1` | ubench | 50349113 | 50352555 |
| `ubench.pipeline work=65536 cpus=1` | /services/drivers/iommu-vtd | 63 | 0 |
| `ubench.pipeline work=65536 cpus=1` | kernel | 30023 | 33254 |
| `ubench.console_write bytes=64 cpus=1` | all | 525586 | 2347414 |
| `ubench.console_write bytes=64 cpus=1` | ubench | 1006 | 3129 |
| `ubench.console_write bytes=64 cpus=1` | /services/drivers/framebuffer | 521514 | 2340105 |
| `ubench.console_write bytes=64 cpus=1` | kernel | 3066 | 4180 |
| `ubench.console_write bytes=4096 cpus=1` | all | 33430807 | 149876635 |
| `ubench.console_write bytes=4096 cpus=1` | ubench | 24757 | 59500 |
| `ubench.console_write bytes=4096 cpus=1` | /services/drivers/framebuffer | 33360880 | 149708496 |
| `ubench.console_write bytes=4096 cpus=1` | /services/drivers/iommu-riscv | 0 | 238 |
| `ubench.console_write bytes=4096 cpus=1` | kernel | 45170 | 108401 |
| `ubench.empty_window cpus=1` | all | 13 | 7 |
| `ubench.empty_window cpus=1` | ubench | 13 | 7 |
| `fsbench.read size=16 path=inline cpus=1` | all | 5971 | 11446 |
| `fsbench.read size=16 path=inline cpus=1` | /tests/fixtures/programs/fsbench | 584 | 1547 |
| `fsbench.read size=16 path=inline cpus=1` | fatfs:/ | 2305 | 5939 |
| `fsbench.read size=16 path=inline cpus=1` | fatfs:/data | 209 | 214 |
| `fsbench.read size=16 path=inline cpus=1` | kernel | 2873 | 3746 |
| `fsbench.read size=16 path=frame cpus=1` | all | 42197 | 64041 |
| `fsbench.read size=16 path=frame cpus=1` | /tests/fixtures/programs/fsbench | 11334 | 27048 |
| `fsbench.read size=16 path=frame cpus=1` | fatfs:/ | 4407 | 6200 |
| `fsbench.read size=16 path=frame cpus=1` | kernel | 26456 | 30793 |
| `fsbench.read size=1024 path=inline cpus=1` | all | 31149 | 58027 |
| `fsbench.read size=1024 path=inline cpus=1` | /tests/fixtures/programs/fsbench | 2665 | 7271 |
| `fsbench.read size=1024 path=inline cpus=1` | fatfs:/ | 11440 | 31876 |
| `fsbench.read size=1024 path=inline cpus=1` | fatfs:/data | 3546 | 3324 |
| `fsbench.read size=1024 path=inline cpus=1` | kernel | 13498 | 15556 |
| `fsbench.read size=1024 path=frame cpus=1` | all | 42197 | 64041 |
| `fsbench.read size=1024 path=frame cpus=1` | /tests/fixtures/programs/fsbench | 11334 | 27048 |
| `fsbench.read size=1024 path=frame cpus=1` | fatfs:/ | 4407 | 6200 |
| `fsbench.read size=1024 path=frame cpus=1` | kernel | 26456 | 30793 |
| `fsbench.read size=4096 path=inline cpus=1` | all | 124455 | 231967 |
| `fsbench.read size=4096 path=inline cpus=1` | /tests/fixtures/programs/fsbench | 10519 | 28943 |
| `fsbench.read size=4096 path=inline cpus=1` | fatfs:/ | 45760 | 127504 |
| `fsbench.read size=4096 path=inline cpus=1` | fatfs:/data | 14184 | 13296 |
| `fsbench.read size=4096 path=inline cpus=1` | kernel | 53992 | 62224 |
| `fsbench.read size=4096 path=frame cpus=1` | all | 42197 | 64041 |
| `fsbench.read size=4096 path=frame cpus=1` | /tests/fixtures/programs/fsbench | 11334 | 27048 |
| `fsbench.read size=4096 path=frame cpus=1` | fatfs:/ | 4407 | 6200 |
| `fsbench.read size=4096 path=frame cpus=1` | kernel | 26456 | 30793 |
| `fsbench.read size=16384 path=inline cpus=1` | all | 509464 | 941297 |
| `fsbench.read size=16384 path=inline cpus=1` | /tests/fixtures/programs/fsbench | 41935 | 115631 |
| `fsbench.read size=16384 path=inline cpus=1` | fatfs:/ | 192629 | 521344 |
| `fsbench.read size=16384 path=inline cpus=1` | fatfs:/data | 58475 | 54960 |
| `fsbench.read size=16384 path=inline cpus=1` | kernel | 216425 | 249362 |
| `fsbench.read size=16384 path=frame cpus=1` | all | 169406 | 256864 |
| `fsbench.read size=16384 path=frame cpus=1` | /tests/fixtures/programs/fsbench | 45195 | 108051 |
| `fsbench.read size=16384 path=frame cpus=1` | fatfs:/ | 18387 | 25629 |
| `fsbench.read size=16384 path=frame cpus=1` | fatfs:/data | 0 | 12 |
| `fsbench.read size=16384 path=frame cpus=1` | kernel | 105824 | 123172 |
| `fsbench.read size=65536 path=inline cpus=1` | all | 2212289 | 3969671 |
| `fsbench.read size=65536 path=inline cpus=1` | /tests/fixtures/programs/fsbench | 167599 | 462383 |
| `fsbench.read size=65536 path=inline cpus=1` | fatfs:/ | 924160 | 2266615 |
| `fsbench.read size=65536 path=inline cpus=1` | fatfs:/data | 255744 | 243225 |
| `fsbench.read size=65536 path=inline cpus=1` | kernel | 864786 | 997448 |
| `fsbench.read size=65536 path=frame cpus=1` | all | 678699 | 1028617 |
| `fsbench.read size=65536 path=frame cpus=1` | /tests/fixtures/programs/fsbench | 180639 | 432063 |
| `fsbench.read size=65536 path=frame cpus=1` | fatfs:/ | 74307 | 103389 |
| `fsbench.read size=65536 path=frame cpus=1` | fatfs:/data | 0 | 12 |
| `fsbench.read size=65536 path=frame cpus=1` | kernel | 423753 | 493153 |
| `fsbench.open depth=3 cpus=1` | all | 65227 | 95477 |
| `fsbench.open depth=3 cpus=1` | /tests/fixtures/programs/fsbench | 3451 | 7090 |
| `fsbench.open depth=3 cpus=1` | fatfs:/ | 22722 | 39070 |
| `fsbench.open depth=3 cpus=1` | fatfs:/data | 14 | 19 |
| `fsbench.open depth=3 cpus=1` | vfsd | 1280 | 3775 |
| `fsbench.open depth=3 cpus=1` | kernel | 37760 | 45523 |

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
| `<kernel::sync::Spinlock>::lock_raw` | kernel | 100 | 68 |
| `<kernel::sched::run_queue::PerCpuScheduler>::dequeue_highest` | kernel | 32 | 92 |
| `kernel::arch::current::context::switch` | kernel | 92 | 74 |
| `kernel::syscall::pin_checked` | kernel | 84 | 90 |
| `kernel::syscall::ipc::sys_ipc_call` | kernel | 61 | 74 |
| `kernel::sched::enqueue_and_wake` | kernel | 46 | 72 |
| `kernel::syscall::dispatch` | kernel | 69 | 21 |
| `kernel::arch::current::fpu::restore_fp_from` | kernel | | 68 |
| `ipc::ipc_call_timeout` | ubench | 48 | 59 |
| `kernel::arch::current::interrupts::handle_trap` | kernel | | 57 |
| `kernel::syscall::dispatch_in_range` | kernel | 57 | 45 |
| `ubench::ipc_rt::serve` | ubench | 57 | 52 |
| `kernel::arch::current::cpu::restore_interrupts` | kernel | 34 | 54 |
| `kernel::ipc::endpoint::endpoint_call` | kernel | 37 | 54 |
| `kernel::arch::current::cpu::save_and_disable_interrupts` | kernel | 51 | 26 |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 24 | 50 |
| `ipc::ipc_recv_timeout` | ubench | 36 | 50 |
| `<kernel::sched::run_queue::PerCpuScheduler>::link` | kernel | 44 | 42 |
| `kernel::sched::commit_blocked_under_local_lock` | kernel | 35 | 40 |
| `<kernel::sync::Spinlock>::unlock_raw` | kernel | 14 | 39 |
| `kernel::syscall::ipc::sys_ipc_recv` | kernel | 24 | 39 |
| `kernel::arch::current::fpu::save_v_to` | kernel | | 36 |
| `kernel::syscall::ipc::sys_ipc_reply` | kernel | 22 | 36 |
| `kernel::arch::current::encoding::ticks_to_us` | kernel | | 34 |
| `kernel::arch::current::fpu::restore_v_from` | kernel | | 34 |
| `kernel::arch::current::fpu::set_frame_units` | kernel | | 34 |
| `kernel::ipc::endpoint::bind_next_sender` | kernel | 18 | 34 |
| `kernel::syscall::ipc::deliver_message` | kernel | 32 | 34 |
| `kernel::syscall::pin_checked::{closure#0}` | kernel | 24 | 34 |
| `kernel::arch::current::fpu::switch_in_restore` | kernel | 18 | 32 |
| `memcpy` | kernel | 32 | 4 |
| `<kernel::arch::current::trap_frame::TrapFrame>::arg` | kernel | 30 | 7 |
| `<kernel::ipc::message::Message>::caps` | kernel | 28 | 26 |
| 148 functions below 25 each |  | 878 | 856 |

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
| `<kernel::sync::Spinlock>::lock_raw` | kernel | 100 | 68 |
| `ipc::ipc_call_timeout` | ubench | 72 | 94 |
| `<kernel::sched::run_queue::PerCpuScheduler>::dequeue_highest` | kernel | 32 | 92 |
| `kernel::arch::current::context::switch` | kernel | 92 | 74 |
| `kernel::syscall::pin_checked` | kernel | 84 | 90 |
| `memcpy` | kernel | 82 | 8 |
| `ipc::ipc_recv_timeout` | ubench | 53 | 77 |
| `kernel::syscall::ipc::sys_ipc_call` | kernel | 63 | 74 |
| `kernel::sched::enqueue_and_wake` | kernel | 46 | 72 |
| `kernel::syscall::dispatch` | kernel | 69 | 21 |
| `kernel::arch::current::fpu::restore_fp_from` | kernel | | 68 |
| `ubench::ipc_rt::serve` | ubench | 58 | 53 |
| `kernel::arch::current::interrupts::handle_trap` | kernel | | 57 |
| `kernel::syscall::dispatch_in_range` | kernel | 57 | 45 |
| `kernel::arch::current::cpu::restore_interrupts` | kernel | 34 | 54 |
| `kernel::ipc::endpoint::endpoint_call` | kernel | 37 | 54 |
| `kernel::arch::current::cpu::save_and_disable_interrupts` | kernel | 51 | 26 |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 24 | 50 |
| `<kernel::arch::current::trap_frame::TrapFrame>::set_msg_regs` | kernel | 46 | 46 |
| `<kernel::sched::run_queue::PerCpuScheduler>::link` | kernel | 44 | 42 |
| `kernel::sched::commit_blocked_under_local_lock` | kernel | 35 | 40 |
| `<kernel::sync::Spinlock>::unlock_raw` | kernel | 14 | 39 |
| `kernel::syscall::ipc::sys_ipc_recv` | kernel | 24 | 39 |
| `kernel::arch::current::fpu::save_v_to` | kernel | | 36 |
| `kernel::syscall::ipc::sys_ipc_reply` | kernel | 22 | 36 |
| `kernel::arch::current::encoding::ticks_to_us` | kernel | | 34 |
| `kernel::arch::current::fpu::restore_v_from` | kernel | | 34 |
| `kernel::arch::current::fpu::set_frame_units` | kernel | | 34 |
| `kernel::ipc::endpoint::bind_next_sender` | kernel | 18 | 34 |
| `kernel::syscall::ipc::deliver_message` | kernel | 32 | 34 |
| `kernel::syscall::pin_checked::{closure#0}` | kernel | 24 | 34 |
| `kernel::arch::current::fpu::switch_in_restore` | kernel | 18 | 32 |
| `ipc::ipc_reply` | ubench | 32 | 31 |
| `<kernel::arch::current::trap_frame::TrapFrame>::arg` | kernel | 30 | 7 |
| `<kernel::ipc::message::Message>::caps` | kernel | 28 | 26 |
| 151 functions below 27 each |  | 902 | 863 |

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
| `ipc::ipc_call_timeout` | ubench | 134 | 137 |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | 114 |
| `<kernel::sync::Spinlock>::lock_raw` | kernel | 100 | 68 |
| `<kernel::sched::run_queue::PerCpuScheduler>::dequeue_highest` | kernel | 32 | 92 |
| `kernel::arch::current::context::switch` | kernel | 92 | 74 |
| `kernel::syscall::pin_checked` | kernel | 84 | 90 |
| `ipc::ipc_recv_timeout` | ubench | 77 | 82 |
| `kernel::syscall::ipc::sys_ipc_call` | kernel | 63 | 74 |
| `ipc::ipc_reply` | ubench | 74 | 73 |
| `kernel::sched::enqueue_and_wake` | kernel | 46 | 72 |
| `kernel::syscall::dispatch` | kernel | 69 | 21 |
| `kernel::arch::current::fpu::restore_fp_from` | kernel | | 68 |
| `compiler_builtins::mem::memcpy` | kernel | | 65 |
| `ubench::ipc_rt::serve` | ubench | 58 | 53 |
| `kernel::arch::current::interrupts::handle_trap` | kernel | | 57 |
| `kernel::syscall::dispatch_in_range` | kernel | 57 | 45 |
| `kernel::arch::current::cpu::restore_interrupts` | kernel | 34 | 54 |
| `kernel::ipc::endpoint::endpoint_call` | kernel | 37 | 54 |
| `kernel::arch::current::cpu::save_and_disable_interrupts` | kernel | 51 | 26 |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 24 | 50 |
| `<kernel::sched::run_queue::PerCpuScheduler>::link` | kernel | 44 | 42 |
| `kernel::sched::commit_blocked_under_local_lock` | kernel | 35 | 40 |
| `<kernel::sync::Spinlock>::unlock_raw` | kernel | 14 | 39 |
| `kernel::syscall::ipc::sys_ipc_recv` | kernel | 24 | 39 |
| `memcpy` | kernel | 39 | 4 |
| `kernel::arch::current::fpu::save_v_to` | kernel | | 36 |
| `kernel::syscall::ipc::sys_ipc_reply` | kernel | 22 | 36 |
| `kernel::arch::current::encoding::ticks_to_us` | kernel | | 34 |
| `kernel::arch::current::fpu::restore_v_from` | kernel | | 34 |
| `kernel::arch::current::fpu::set_frame_units` | kernel | | 34 |
| `kernel::ipc::endpoint::bind_next_sender` | kernel | 18 | 34 |
| `kernel::syscall::ipc::deliver_message` | kernel | 32 | 34 |
| `kernel::syscall::pin_checked::{closure#0}` | kernel | 24 | 34 |
| `__copy_user` | kernel | 12 | 32 |
| `kernel::arch::current::fpu::switch_in_restore` | kernel | 18 | 32 |
| `<kernel::arch::current::trap_frame::TrapFrame>::arg` | kernel | 30 | 7 |
| `<kernel::ipc::message::Message>::caps` | kernel | 28 | 26 |
| 155 functions below 28 each |  | 913 | 871 |

#### `ubench.ipc_rt words=64 cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `__copy_user_fault_start` | kernel | 2052 | |
| `compiler_builtins::mem::memcpy` | ubench | | 1780 |
| `ipc::ipc_call_timeout` | ubench | 654 | 764 |
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
| `<kernel::sync::Spinlock>::lock_raw` | kernel | 100 | 68 |
| `memcpy` | kernel | 96 | 4 |
| `<kernel::sched::run_queue::PerCpuScheduler>::dequeue_highest` | kernel | 32 | 92 |
| `kernel::arch::current::context::switch` | kernel | 92 | 74 |
| `kernel::syscall::pin_checked` | kernel | 84 | 90 |
| `kernel::syscall::ipc::sys_ipc_call` | kernel | 63 | 75 |
| `kernel::sched::enqueue_and_wake` | kernel | 46 | 72 |
| `kernel::syscall::dispatch` | kernel | 69 | 21 |
| `kernel::arch::current::fpu::restore_fp_from` | kernel | | 68 |
| `ubench::ipc_rt::serve` | ubench | 58 | 53 |
| `kernel::arch::current::interrupts::handle_trap` | kernel | | 57 |
| `kernel::syscall::dispatch_in_range` | kernel | 57 | 45 |
| `kernel::arch::current::cpu::restore_interrupts` | kernel | 34 | 54 |
| `kernel::ipc::endpoint::endpoint_call` | kernel | 37 | 54 |
| `kernel::arch::current::cpu::save_and_disable_interrupts` | kernel | 51 | 26 |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 24 | 50 |
| `<kernel::sched::run_queue::PerCpuScheduler>::link` | kernel | 44 | 42 |
| `kernel::sched::commit_blocked_under_local_lock` | kernel | 35 | 40 |
| `<kernel::sync::Spinlock>::unlock_raw` | kernel | 14 | 39 |
| `kernel::syscall::ipc::sys_ipc_recv` | kernel | 24 | 39 |
| 168 functions below 39 each |  | 1097 | 1253 |

#### `ubench.fault_fill path=fault pages=16 cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `memset` | memmgr | 8298 | 24812 |
| `boot_protocol::riscv_paging::level_shift` | kernel | | 2136 |
| `<kernel::mm::address_space::AddressSpace>::map_page_pooled` | kernel | 608 | 1344 |
| `kernel::arch::current::paging::install_user_leaf` | kernel | | 1216 |
| `kernel::arch::current::paging::entry` | kernel | 48 | 1161 |
| `<kernel::mm::frame_map::FrameMap>::counter` | kernel | 896 | 1152 |
| `<memmgr::MappedSlots as memmgr_free_pool::arena::SlotStore>::read` | memmgr | 1116 | 1145 |
| `compiler_builtins::mem::memcpy` | memmgr | | 1129 |
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
| 489 functions below 289 each |  | 12081 | 13065 |

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
| `<memmgr::MappedSlots as memmgr_free_pool::arena::SlotStore>::read` | memmgr | 332 | 336 |
| 509 functions below 301 each |  | 13572 | 15005 |

#### `ubench.fault_scaling threads=1 pages=16 cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `memset` | memmgr | 8298 | 24812 |
| `boot_protocol::riscv_paging::level_shift` | kernel | | 2136 |
| `<kernel::mm::address_space::AddressSpace>::map_page_pooled` | kernel | 608 | 1344 |
| `kernel::arch::current::paging::install_user_leaf` | kernel | | 1216 |
| `kernel::arch::current::paging::entry` | kernel | 48 | 1161 |
| `<kernel::mm::frame_map::FrameMap>::counter` | kernel | 896 | 1152 |
| `<memmgr::MappedSlots as memmgr_free_pool::arena::SlotStore>::read` | memmgr | 1116 | 1145 |
| `compiler_builtins::mem::memcpy` | memmgr | | 1129 |
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
| 491 functions below 289 each |  | 12081 | 13074 |

#### `ubench.shmem_ring bytes=64 wrap=no cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `compiler_builtins::mem::memcpy` | ubench | | 140 |
| `ubench::shmem_ring::transfer` | ubench | 95 | 70 |
| `memcpy` | ubench | 80 | 8 |
| `<bench::counters::Counters>::read` | ubench | 7 | 6 |
| `bench::arch::current::cycles` | ubench | 7 | 1 |

#### `ubench.shmem_ring bytes=64 wrap=yes cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `compiler_builtins::mem::memcpy` | ubench | | 164 |
| `ubench::shmem_ring::transfer` | ubench | 95 | 70 |
| `memcpy` | ubench | 80 | 8 |
| `<bench::counters::Counters>::read` | ubench | 7 | 6 |
| `bench::arch::current::cycles` | ubench | 7 | 1 |

#### `ubench.shmem_ring bytes=512 wrap=no cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `compiler_builtins::mem::memcpy` | ubench | | 700 |
| `memcpy` | ubench | 192 | 8 |
| `ubench::shmem_ring::transfer` | ubench | 95 | 70 |
| `<bench::counters::Counters>::read` | ubench | 7 | 6 |
| `bench::arch::current::cycles` | ubench | 7 | 1 |

#### `ubench.shmem_ring bytes=512 wrap=yes cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `compiler_builtins::mem::memcpy` | ubench | | 724 |
| `memcpy` | ubench | 192 | 8 |
| `ubench::shmem_ring::transfer` | ubench | 95 | 70 |
| `<bench::counters::Counters>::read` | ubench | 7 | 6 |
| `bench::arch::current::cycles` | ubench | 7 | 1 |

#### `ubench.shmem_ring bytes=4096 wrap=no cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `compiler_builtins::mem::memcpy` | ubench | | 5240 |
| `memcpy` | ubench | 1152 | 16 |
| `ubench::shmem_ring::transfer` | ubench | 186 | 136 |
| 2 functions below 26 each |  | 14 | 7 |

#### `ubench.shmem_ring bytes=4096 wrap=yes cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `compiler_builtins::mem::memcpy` | ubench | | 5288 |
| `memcpy` | ubench | 1152 | 16 |
| `ubench::shmem_ring::transfer` | ubench | 186 | 136 |
| 2 functions below 27 each |  | 14 | 7 |

#### `ubench.shmem_ring bytes=65536 wrap=no cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `compiler_builtins::mem::memcpy` | ubench | | 83840 |
| `memcpy` | ubench | 18432 | 256 |
| `ubench::shmem_ring::transfer` | ubench | 2916 | 2116 |
| 2 functions below 431 each |  | 14 | 7 |

#### `ubench.shmem_ring bytes=65536 wrap=yes cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `compiler_builtins::mem::memcpy` | ubench | | 84608 |
| `memcpy` | ubench | 18432 | 256 |
| `ubench::shmem_ring::transfer` | ubench | 2916 | 2116 |
| 2 functions below 434 each |  | 14 | 7 |

#### `ubench.pipeline work=0 cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `compiler_builtins::mem::memcpy` | ubench | | 8960 |
| `ubench::pipeline::send` | ubench | 5657 | 5844 |
| `memcpy` | ubench | 5120 | 512 |
| `ubench::pipeline::receive` | ubench | 3814 | 2846 |
| `ubench::pipeline::take_windows` | ubench | 1092 | 1028 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | 930 |
| `ubench::pipeline::send_windows` | ubench | 839 | 776 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 620 | |
| `kernel::sched::schedule` | kernel | 430 | 570 |
| `kernel::syscall::pin_checked` | kernel | 420 | 450 |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | 380 |
| `ubench::pipeline::item` | ubench | 256 | 320 |
| `<kernel::sync::Spinlock>::lock_raw` | kernel | 295 | 200 |
| `ubench::pipeline::spin` | ubench | 258 | 129 |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 120 | 250 |
| `kernel::syscall::ipc::sys_notification_wait` | kernel | 160 | 245 |
| `<kernel::sched::run_queue::PerCpuScheduler>::dequeue_highest` | kernel | 80 | 230 |
| `kernel::arch::current::context::switch` | kernel | 230 | 185 |
| `kernel::syscall::dispatch` | kernel | 230 | 70 |
| `kernel::syscall::dispatch_in_range` | kernel | 195 | 155 |
| `kernel::arch::current::interrupts::handle_trap` | kernel | | 190 |
| `kernel::syscall::ipc::sys_notification_send` | kernel | 175 | 180 |
| `kernel::sched::enqueue_and_wake` | kernel | 115 | 172 |
| `kernel::arch::current::fpu::restore_fp_from` | kernel | | 170 |
| `kernel::syscall::pin_checked::{closure#0}` | kernel | 120 | 170 |
| `kernel::arch::current::cpu::restore_interrupts` | kernel | 105 | 160 |
| `kernel::arch::current::cpu::save_and_disable_interrupts` | kernel | 150 | 80 |
| 126 functions below 142 each |  | 2827 | 3275 |

#### `ubench.pipeline work=1024 cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `ubench::pipeline::spin` | ubench | 786946 | 786753 |
| `compiler_builtins::mem::memcpy` | ubench | | 8960 |
| `ubench::pipeline::send` | ubench | 5657 | 5844 |
| `memcpy` | ubench | 5120 | 512 |
| 190 functions below 4078 each |  | 12728 | 13544 |

#### `ubench.pipeline work=8192 cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `ubench::pipeline::spin` | ubench | 6291970 | 6291777 |
| 196 functions below 31617 each |  | 26235 | 31810 |

#### `ubench.pipeline work=65536 cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `ubench::pipeline::spin` | ubench | 50332162 | 50331969 |
| 255 functions below 251929 each |  | 47037 | 53840 |

#### `ubench.console_write bytes=64 cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `compiler_builtins::mem::memmove` | /services/drivers/framebuffer | | 2240025 |
| `memmove` | /services/drivers/framebuffer | 448023 | 2 |
| `<framebuffer::render::FramebufferWriter>::draw_glyph_bitmap` | /services/drivers/framebuffer | 54054 | 54987 |
| `memset` | /services/drivers/framebuffer | 12821 | 38636 |
| 311 functions below 11737 each |  | 10688 | 13764 |

#### `ubench.console_write bytes=4096 cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `compiler_builtins::mem::memmove` | /services/drivers/framebuffer | | 143361600 |
| `memmove` | /services/drivers/framebuffer | 28673472 | 128 |
| `<framebuffer::render::FramebufferWriter>::draw_glyph_bitmap` | /services/drivers/framebuffer | 3459456 | 3518344 |
| `memset` | /services/drivers/framebuffer | 820544 | 2460720 |
| 353 functions below 749383 each |  | 477335 | 535843 |

#### `ubench.empty_window cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `bench::arch::current::cycles` | ubench | 7 | 1 |
| `<bench::counters::Counters>::read` | ubench | 6 | 6 |

#### `fsbench.read size=16 path=inline cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `memset` | fatfs:/ | 1154 | 3553 |
| `compiler_builtins::mem::memcpy` | fatfs:/ | | 1642 |
| `compiler_builtins::mem::memcpy` | /tests/fixtures/programs/fsbench | | 759 |
| `memset` | /tests/fixtures/programs/fsbench | 87 | 434 |
| `memcpy` | fatfs:/ | 433 | 20 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | 372 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 248 | |
| `kernel::sched::schedule` | kernel | 174 | 232 |
| `memcpy` | /tests/fixtures/programs/fsbench | 199 | 8 |
| `std::os::seraph::deadline_call` | /tests/fixtures/programs/fsbench | 131 | 157 |
| `<fatfs::cache::PageCache>::lookup_cached` | fatfs:/ | 147 | 154 |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | 152 |
| `<std::fs::File as alloc::io::read::Read>::read` | /tests/fixtures/programs/fsbench | 96 | 124 |
| `fatfs::handle_read` | fatfs:/data | 88 | 113 |
| `fatfs::service_loop` | fatfs:/ | 108 | 95 |
| `compiler_builtins::mem::memcpy` | kernel | | 107 |
| `<kernel::sync::Spinlock>::lock_raw` | kernel | 99 | 68 |
| `<kernel::sched::run_queue::PerCpuScheduler>::dequeue_highest` | kernel | 32 | 92 |
| `kernel::arch::current::context::switch` | kernel | 92 | 74 |
| `kernel::syscall::dispatch` | kernel | 92 | 28 |
| `kernel::syscall::pin_checked` | kernel | 84 | 90 |
| `<kernel::mm::address_space::AddressSpace>::activate` | kernel | 4 | 88 |
| `kernel::syscall::dispatch_in_range` | kernel | 82 | 60 |
| `kernel::arch::current::interrupts::handle_trap` | kernel | | 76 |
| `kernel::syscall::ipc::sys_ipc_call` | kernel | 63 | 74 |
| `memcpy` | kernel | 71 | 8 |
| `kernel::arch::current::encoding::ticks_to_us` | kernel | | 70 |
| `kernel::sched::enqueue_and_wake` | kernel | 46 | 70 |
| `kernel::arch::current::fpu::restore_fp_from` | kernel | | 68 |
| `ipc::serve::next_request` | fatfs:/ | 48 | 66 |
| `kernel::syscall::ipc::sys_ipc_reply_recv` | kernel | 41 | 61 |
| 276 functions below 57 each |  | 2352 | 2531 |

#### `fsbench.read size=16 path=frame cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `<std::fs::File as alloc::io::read::Read>::read` | /tests/fixtures/programs/fsbench | 10407 | 24744 |
| `crypto::keccak::keccak_f1600` | kernel | 12628 | 12530 |
| `compiler_builtins::mem::memcpy` | fatfs:/ | | 1908 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | 1767 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 1178 | |
| `memset` | /tests/fixtures/programs/fsbench | 175 | 871 |
| `compiler_builtins::mem::memcpy` | /tests/fixtures/programs/fsbench | | 769 |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | 722 |
| `<kernel::cap::cspace::CSpace>::slot_mut` | kernel | 456 | 690 |
| `memset` | fatfs:/ | | 651 |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 360 | 618 |
| `kernel::syscall::pin_checked` | kernel | 343 | 585 |
| `kernel::sched::schedule` | kernel | 348 | 464 |
| `memcpy` | fatfs:/ | 452 | 16 |
| `kernel::syscall::dispatch` | kernel | 437 | 133 |
| `<fatfs::session::SessionPages>::va` | fatfs:/ | 436 | 356 |
| `<kernel::cap::cspace::CSpace>::leaf_ptr` | kernel | 204 | 408 |
| `compiler_builtins::mem::memcpy` | kernel | | 396 |
| `kernel::syscall::dispatch_in_range` | kernel | 375 | 284 |
| `kernel::arch::current::interrupts::handle_trap` | kernel | | 361 |
| `<fatfs_parse::session_pool::SessionPool<fatfs::session::SessionPages>>::find` | fatfs:/ | 341 | 275 |
| `kernel::arch::nospec::select_ptr::<kernel::cap::cspace::CSpacePage>` | kernel | 272 | 340 |
| `kernel::arch::current::speculation::index_mask` | kernel | 326 | 334 |
| 507 functions below 320 each |  | 13459 | 14819 |

#### `fsbench.read size=1024 path=inline cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `compiler_builtins::mem::memcpy` | fatfs:/ | | 14466 |
| `memset` | fatfs:/ | 4616 | 14212 |
| `memcpy` | fatfs:/ | 3972 | 316 |
| `compiler_builtins::mem::memcpy` | /tests/fixtures/programs/fsbench | | 3696 |
| `fatfs::handle_read` | fatfs:/data | 2272 | 2132 |
| `__copy_user_fault_start` | kernel | 2052 | |
| `memset` | /tests/fixtures/programs/fsbench | 348 | 1736 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | 1488 |
| `std::os::seraph::deadline_call` | /tests/fixtures/programs/fsbench | 874 | 1192 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 992 | |
| `kernel::sched::schedule` | kernel | 696 | 928 |
| `memcpy` | /tests/fixtures/programs/fsbench | 916 | 32 |
| `ipc::reply_recv_delivery` | fatfs:/data | 790 | 786 |
| `__copy_user_block_start` | kernel | | 640 |
| `<fatfs::cache::PageCache>::lookup_cached` | fatfs:/ | 588 | 616 |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | 608 |
| `<std::fs::File as alloc::io::read::Read>::read` | /tests/fixtures/programs/fsbench | 384 | 496 |
| `fatfs::service_loop` | fatfs:/ | 432 | 380 |
| `<kernel::sync::Spinlock>::lock_raw` | kernel | 396 | 272 |
| `<kernel::sched::run_queue::PerCpuScheduler>::dequeue_highest` | kernel | 128 | 368 |
| `kernel::arch::current::context::switch` | kernel | 368 | 296 |
| `kernel::syscall::dispatch` | kernel | 368 | 112 |
| `kernel::syscall::pin_checked` | kernel | 336 | 360 |
| `<kernel::mm::address_space::AddressSpace>::activate` | kernel | 16 | 352 |
| `compiler_builtins::mem::memcpy` | kernel | | 346 |
| `kernel::syscall::dispatch_in_range` | kernel | 328 | 240 |
| `kernel::arch::current::interrupts::handle_trap` | kernel | | 304 |
| `kernel::syscall::ipc::sys_ipc_call` | kernel | 252 | 296 |
| 289 functions below 290 each |  | 10025 | 11357 |

#### `fsbench.read size=1024 path=frame cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `<std::fs::File as alloc::io::read::Read>::read` | /tests/fixtures/programs/fsbench | 10407 | 24744 |
| `crypto::keccak::keccak_f1600` | kernel | 12628 | 12530 |
| `compiler_builtins::mem::memcpy` | fatfs:/ | | 1908 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | 1767 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 1178 | |
| `memset` | /tests/fixtures/programs/fsbench | 175 | 871 |
| `compiler_builtins::mem::memcpy` | /tests/fixtures/programs/fsbench | | 769 |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | 722 |
| `<kernel::cap::cspace::CSpace>::slot_mut` | kernel | 456 | 690 |
| `memset` | fatfs:/ | | 651 |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 360 | 618 |
| `kernel::syscall::pin_checked` | kernel | 343 | 585 |
| `kernel::sched::schedule` | kernel | 348 | 464 |
| `memcpy` | fatfs:/ | 452 | 16 |
| `kernel::syscall::dispatch` | kernel | 437 | 133 |
| `<fatfs::session::SessionPages>::va` | fatfs:/ | 436 | 356 |
| `<kernel::cap::cspace::CSpace>::leaf_ptr` | kernel | 204 | 408 |
| `compiler_builtins::mem::memcpy` | kernel | | 396 |
| `kernel::syscall::dispatch_in_range` | kernel | 375 | 284 |
| `kernel::arch::current::interrupts::handle_trap` | kernel | | 361 |
| `<fatfs_parse::session_pool::SessionPool<fatfs::session::SessionPages>>::find` | fatfs:/ | 341 | 275 |
| `kernel::arch::nospec::select_ptr::<kernel::cap::cspace::CSpacePage>` | kernel | 272 | 340 |
| `kernel::arch::current::speculation::index_mask` | kernel | 326 | 334 |
| 507 functions below 320 each |  | 13459 | 14819 |

#### `fsbench.read size=4096 path=inline cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `compiler_builtins::mem::memcpy` | fatfs:/ | | 57864 |
| `memset` | fatfs:/ | 18464 | 56848 |
| `memcpy` | fatfs:/ | 15888 | 1264 |
| `compiler_builtins::mem::memcpy` | /tests/fixtures/programs/fsbench | | 14784 |
| `fatfs::handle_read` | fatfs:/data | 9088 | 8528 |
| `__copy_user_fault_start` | kernel | 8208 | |
| `memset` | /tests/fixtures/programs/fsbench | 1392 | 6944 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | 5952 |
| `std::os::seraph::deadline_call` | /tests/fixtures/programs/fsbench | 3496 | 4768 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 3968 | |
| `kernel::sched::schedule` | kernel | 2784 | 3712 |
| `memcpy` | /tests/fixtures/programs/fsbench | 3664 | 128 |
| `ipc::reply_recv_delivery` | fatfs:/data | 3160 | 3144 |
| `__copy_user_block_start` | kernel | | 2560 |
| `<fatfs::cache::PageCache>::lookup_cached` | fatfs:/ | 2352 | 2464 |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | 2432 |
| `<std::fs::File as alloc::io::read::Read>::read` | /tests/fixtures/programs/fsbench | 1536 | 1984 |
| `fatfs::service_loop` | fatfs:/ | 1728 | 1520 |
| `<kernel::sync::Spinlock>::lock_raw` | kernel | 1584 | 1088 |
| `<kernel::sched::run_queue::PerCpuScheduler>::dequeue_highest` | kernel | 512 | 1472 |
| `kernel::arch::current::context::switch` | kernel | 1472 | 1184 |
| `kernel::syscall::dispatch` | kernel | 1472 | 448 |
| `kernel::syscall::pin_checked` | kernel | 1344 | 1440 |
| `<kernel::mm::address_space::AddressSpace>::activate` | kernel | 64 | 1408 |
| `compiler_builtins::mem::memcpy` | kernel | | 1384 |
| `kernel::syscall::dispatch_in_range` | kernel | 1312 | 960 |
| `kernel::arch::current::interrupts::handle_trap` | kernel | | 1216 |
| `kernel::syscall::ipc::sys_ipc_call` | kernel | 1008 | 1184 |
| 289 functions below 1159 each |  | 39959 | 45287 |

#### `fsbench.read size=4096 path=frame cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `<std::fs::File as alloc::io::read::Read>::read` | /tests/fixtures/programs/fsbench | 10407 | 24744 |
| `crypto::keccak::keccak_f1600` | kernel | 12628 | 12530 |
| `compiler_builtins::mem::memcpy` | fatfs:/ | | 1908 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | 1767 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 1178 | |
| `memset` | /tests/fixtures/programs/fsbench | 175 | 871 |
| `compiler_builtins::mem::memcpy` | /tests/fixtures/programs/fsbench | | 769 |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | 722 |
| `<kernel::cap::cspace::CSpace>::slot_mut` | kernel | 456 | 690 |
| `memset` | fatfs:/ | | 651 |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 360 | 618 |
| `kernel::syscall::pin_checked` | kernel | 343 | 585 |
| `kernel::sched::schedule` | kernel | 348 | 464 |
| `memcpy` | fatfs:/ | 452 | 16 |
| `kernel::syscall::dispatch` | kernel | 437 | 133 |
| `<fatfs::session::SessionPages>::va` | fatfs:/ | 436 | 356 |
| `<kernel::cap::cspace::CSpace>::leaf_ptr` | kernel | 204 | 408 |
| `compiler_builtins::mem::memcpy` | kernel | | 396 |
| `kernel::syscall::dispatch_in_range` | kernel | 375 | 284 |
| `kernel::arch::current::interrupts::handle_trap` | kernel | | 361 |
| `<fatfs_parse::session_pool::SessionPool<fatfs::session::SessionPages>>::find` | fatfs:/ | 341 | 275 |
| `kernel::arch::nospec::select_ptr::<kernel::cap::cspace::CSpacePage>` | kernel | 272 | 340 |
| `kernel::arch::current::speculation::index_mask` | kernel | 326 | 334 |
| 507 functions below 320 each |  | 13459 | 14819 |

#### `fsbench.read size=16384 path=inline cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `compiler_builtins::mem::memcpy` | fatfs:/ | | 231456 |
| `memset` | fatfs:/ | 73856 | 227392 |
| `memcpy` | fatfs:/ | 63552 | 5056 |
| `compiler_builtins::mem::memcpy` | /tests/fixtures/programs/fsbench | | 59136 |
| `fatfs::handle_read` | fatfs:/data | 36352 | 34112 |
| `__copy_user_fault_start` | kernel | 32832 | |
| `memset` | /tests/fixtures/programs/fsbench | 5568 | 27776 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | 23901 |
| `std::os::seraph::deadline_call` | /tests/fixtures/programs/fsbench | 13984 | 19072 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 15872 | |
| `kernel::sched::schedule` | kernel | 11136 | 14848 |
| `memcpy` | /tests/fixtures/programs/fsbench | 14656 | 512 |
| `ipc::reply_recv_delivery` | fatfs:/data | 12640 | 12576 |
| `__copy_user_block_start` | kernel | | 10240 |
| `<fatfs::cache::PageCache>::lookup_cached` | fatfs:/ | 9408 | 9856 |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | 9768 |
| `<std::fs::File as alloc::io::read::Read>::read` | /tests/fixtures/programs/fsbench | 6144 | 7936 |
| `fatfs::service_loop` | fatfs:/ | 6912 | 6080 |
| `<kernel::sync::Spinlock>::lock_raw` | kernel | 6355 | 4370 |
| `<kernel::sched::run_queue::PerCpuScheduler>::dequeue_highest` | kernel | 2048 | 5888 |
| `kernel::arch::current::context::switch` | kernel | 5888 | 4736 |
| `kernel::syscall::dispatch` | kernel | 5888 | 1792 |
| `kernel::syscall::pin_checked` | kernel | 5376 | 5760 |
| `<kernel::mm::address_space::AddressSpace>::activate` | kernel | 256 | 5632 |
| `compiler_builtins::mem::memcpy` | kernel | | 5536 |
| `kernel::syscall::dispatch_in_range` | kernel | 5248 | 3840 |
| `fatfs::fat::chain_next` | fatfs:/ | 5184 | 4992 |
| `kernel::arch::current::interrupts::handle_trap` | kernel | | 4879 |
| `fatfs::fat::read_file_data` | fatfs:/data | 4784 | 4320 |
| `kernel::syscall::ipc::sys_ipc_call` | kernel | 4032 | 4736 |
| 338 functions below 4706 each |  | 161493 | 185099 |

#### `fsbench.read size=16384 path=frame cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `<std::fs::File as alloc::io::read::Read>::read` | /tests/fixtures/programs/fsbench | 41628 | 98976 |
| `crypto::keccak::keccak_f1600` | kernel | 50512 | 50120 |
| `compiler_builtins::mem::memcpy` | fatfs:/ | | 7632 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | 7068 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 4712 | |
| `memset` | /tests/fixtures/programs/fsbench | 700 | 3484 |
| `compiler_builtins::mem::memcpy` | /tests/fixtures/programs/fsbench | | 3076 |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | 2888 |
| `<kernel::cap::cspace::CSpace>::slot_mut` | kernel | 1824 | 2760 |
| `memset` | fatfs:/ | | 2604 |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 1440 | 2472 |
| `kernel::syscall::pin_checked` | kernel | 1372 | 2340 |
| `kernel::sched::schedule` | kernel | 1392 | 1856 |
| `memcpy` | fatfs:/ | 1808 | 64 |
| `kernel::syscall::dispatch` | kernel | 1748 | 532 |
| `<fatfs::session::SessionPages>::va` | fatfs:/ | 1744 | 1424 |
| `<kernel::cap::cspace::CSpace>::leaf_ptr` | kernel | 816 | 1632 |
| `compiler_builtins::mem::memcpy` | kernel | | 1584 |
| `kernel::syscall::dispatch_in_range` | kernel | 1500 | 1136 |
| `kernel::arch::current::interrupts::handle_trap` | kernel | | 1444 |
| `<fatfs_parse::session_pool::SessionPool<fatfs::session::SessionPages>>::find` | fatfs:/ | 1364 | 1100 |
| `kernel::arch::nospec::select_ptr::<kernel::cap::cspace::CSpacePage>` | kernel | 1088 | 1360 |
| `kernel::arch::current::speculation::index_mask` | kernel | 1304 | 1336 |
| 517 functions below 1284 each |  | 54454 | 59976 |

#### `fsbench.read size=65536 path=inline cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `compiler_builtins::mem::memcpy` | fatfs:/ | | 925819 |
| `memset` | fatfs:/ | 295424 | 909564 |
| `memcpy` | fatfs:/ | 254208 | 20224 |
| `compiler_builtins::mem::memcpy` | /tests/fixtures/programs/fsbench | | 236544 |
| `fatfs::handle_read` | fatfs:/data | 145408 | 136448 |
| `__copy_user_fault_start` | kernel | 131328 | |
| `memset` | /tests/fixtures/programs/fsbench | 22272 | 111104 |
| `fatfs::fat::chain_next` | fatfs:/ | 103680 | 99840 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | 95604 |
| `fatfs::alloc::read_fat_entry` | fatfs:/ | 36480 | 76800 |
| `std::os::seraph::deadline_call` | /tests/fixtures/programs/fsbench | 55936 | 76288 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 63488 | |
| `kernel::sched::schedule` | kernel | 44544 | 59392 |
| `memcpy` | /tests/fixtures/programs/fsbench | 58624 | 2048 |
| `ipc::reply_recv_delivery` | fatfs:/data | 50560 | 50304 |
| `__copy_user_block_start` | kernel | | 40960 |
| `fatfs::fat::read_file_data` | fatfs:/data | 40688 | 40320 |
| `<fatfs::cache::PageCache>::lookup_cached` | fatfs:/ | 37632 | 39424 |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | 39072 |
| `<fatfs::bpb::FatState>::fat_entry_location` | fatfs:/ | 30720 | 34560 |
| `<std::fs::File as alloc::io::read::Read>::read` | /tests/fixtures/programs/fsbench | 24576 | 31744 |
| `fatfs::service_loop` | fatfs:/ | 27648 | 24320 |
| `<kernel::sync::Spinlock>::lock_raw` | kernel | 25382 | 17480 |
| `<kernel::sched::run_queue::PerCpuScheduler>::dequeue_highest` | kernel | 8192 | 23552 |
| `kernel::arch::current::context::switch` | kernel | 23552 | 18944 |
| `kernel::syscall::dispatch` | kernel | 23552 | 7168 |
| `kernel::syscall::pin_checked` | kernel | 21504 | 23040 |
| `<kernel::mm::address_space::AddressSpace>::activate` | kernel | 1024 | 22528 |
| `compiler_builtins::mem::memcpy` | kernel | | 22144 |
| `kernel::syscall::dispatch_in_range` | kernel | 20992 | 15360 |
| 337 functions below 19848 each |  | 664875 | 769076 |

#### `fsbench.read size=65536 path=frame cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `<std::fs::File as alloc::io::read::Read>::read` | /tests/fixtures/programs/fsbench | 166512 | 395904 |
| `crypto::keccak::keccak_f1600` | kernel | 202048 | 200480 |
| `compiler_builtins::mem::memcpy` | fatfs:/ | | 30528 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | 28365 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 18848 | |
| `memset` | /tests/fixtures/programs/fsbench | 2800 | 13936 |
| `compiler_builtins::mem::memcpy` | /tests/fixtures/programs/fsbench | | 12304 |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | 11592 |
| `<kernel::cap::cspace::CSpace>::slot_mut` | kernel | 7296 | 11040 |
| `memset` | fatfs:/ | | 10416 |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 5760 | 9888 |
| `kernel::syscall::pin_checked` | kernel | 5488 | 9360 |
| `kernel::sched::schedule` | kernel | 5568 | 7424 |
| `memcpy` | fatfs:/ | 7232 | 256 |
| `kernel::syscall::dispatch` | kernel | 6992 | 2128 |
| `<fatfs::session::SessionPages>::va` | fatfs:/ | 6976 | 5696 |
| `<kernel::cap::cspace::CSpace>::leaf_ptr` | kernel | 3264 | 6528 |
| `compiler_builtins::mem::memcpy` | kernel | | 6336 |
| `kernel::syscall::dispatch_in_range` | kernel | 6000 | 4544 |
| `kernel::arch::current::interrupts::handle_trap` | kernel | | 5791 |
| `<fatfs_parse::session_pool::SessionPool<fatfs::session::SessionPages>>::find` | fatfs:/ | 5456 | 4400 |
| `kernel::arch::nospec::select_ptr::<kernel::cap::cspace::CSpacePage>` | kernel | 4352 | 5440 |
| `kernel::arch::current::speculation::index_mask` | kernel | 5216 | 5344 |
| 559 functions below 5143 each |  | 218891 | 240917 |

#### `fsbench.open depth=3 cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `memset` | fatfs:/ | 5009 | 14500 |
| `crypto::keccak::keccak_f1600` | kernel | 12628 | 12530 |
| `compiler_builtins::mem::memcpy` | fatfs:/ | | 8764 |
| `<fatfs_parse::LfnAccum>::add_lfn_entry` | fatfs:/ | 4168 | 4350 |
| `fatfs::dir::scan_sector_for_name` | fatfs:/ | 3012 | 3728 |
| `compiler_builtins::mem::memcpy` | /tests/fixtures/programs/fsbench | | 3420 |
| `<fatfs_parse::LfnAccum>::assemble_utf8` | fatfs:/ | 2786 | 2128 |
| `compiler_builtins::mem::memcpy` | vfsd | | 2466 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | 2418 |
| `<kernel::cap::cspace::CSpace>::slot_mut` | kernel | 1248 | 2092 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 1612 | |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 924 | 1520 |
| `memcpy` | fatfs:/ | 1400 | 64 |
| `memset` | /tests/fixtures/programs/fsbench | 260 | 1299 |
| `<kernel::cap::cspace::CSpace>::leaf_ptr` | kernel | 543 | 1086 |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | 988 |
| `std::sys::fs::seraph::walk_components` | /tests/fixtures/programs/fsbench | 958 | 891 |
| `std::sys::alloc::seraph::alloc` | fatfs:/ | 948 | 666 |
| `kernel::syscall::pin_checked` | kernel | 540 | 945 |
| `kernel::arch::nospec::select_ptr::<kernel::cap::cspace::CSpacePage>` | kernel | 724 | 905 |
| `compiler_builtins::mem::memcpy` | kernel | | 891 |
| `memcpy` | /tests/fixtures/programs/fsbench | 861 | 32 |
| `<kernel::cap::registry::CSpaceRegistry>::entry` | kernel | 595 | 768 |
| `<kernel::cap::registry::CSpaceRegistry>::slot` | kernel | 636 | 747 |
| `<fatfs_parse::LfnAccum>::matches` | fatfs:/ | 716 | |
| `kernel::arch::current::speculation::index_mask` | kernel | 694 | 702 |
| `kernel::sched::schedule` | kernel | 522 | 696 |
| `memset` | vfsd | 88 | 651 |
| `memcpy` | vfsd | 627 | 26 |
| `kernel::syscall::dispatch` | kernel | 600 | 184 |
| `<kernel::cap::registry::CSpaceRegistry>::lookup` | kernel | 589 | 549 |
| `kernel::cap::cspace::load_at::<kernel::cap::cspace::CSpacePage>` | kernel | | 543 |
| `<kernel::sync::Spinlock>::lock_raw` | kernel | 536 | 381 |
| `kernel::cap::derivation::resolve_slot_mut` | kernel | 522 | 143 |
| `kernel::syscall::dispatch_in_range` | kernel | 515 | 388 |
| `kernel::syscall::ipc::transfer_caps` | kernel | 444 | 501 |
| `kernel::arch::current::interrupts::handle_trap` | kernel | | 494 |
| 492 functions below 477 each |  | 20522 | 23021 |

<!-- path-account: end -->

---

## Summarized By

[core/kernel/README.md](../README.md), [Kernel Hot-Path Instruction Account](hot-path-account.md)
