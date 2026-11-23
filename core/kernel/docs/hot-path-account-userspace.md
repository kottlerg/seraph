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
  the firmware (OpenSBI, from `0x80000000`) the kernel calls through the SBI. No x86_64 path
  runs outside a placed image.
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

`ubench.ipc_rt words=0` is 5636 / 7444, 4980 / 4740 of it in the kernel. The kernel's
`memset`, four calls per round trip, is 2268 on x86_64, against 1223 in ktest's round trip; the
zeroing of the whole 576-byte `Message` each way, which #1541 removes, is among it. On riscv64 the message moves through `compiler_builtins`' word loops in
both ubench and the kernel (`memcpy` 1448 and 762, `memset` 667 and 452, `memmove` 385). On
x86_64 each round trip also takes the lazy FPU switch's `#NM` trap once a thread is switched
back in (`isr_nm` and its handler, 132).

### Page Faults

`ubench.fault_fill path=fault pages=16` is 37247 / 60773: memmgr 13990 / 31684, of which its
`memset` zeroing the 16 frames is 8298 / 24812 (x86_64's `rep stos` is about one iteration per
8 bytes, riscv64's loop about one instruction per 2.6), and the kernel 23246 / 29081, spread over
the page-table walk and install (`level_shift`, `table_index`, `names_table`, `read_entry`,
`install_user_leaf`), the frame map's counters, and `sys_mem_map`. `fault_scaling threads=1`
runs the same path. `path=grant` adds the grant's capability operations, 37685 / 64884.

### Shared-Memory Ring

`ubench.shmem_ring` runs in ubench alone: `shmem_ring::transfer` is 49342 / 57448 of the
4096-byte transfer, about 12 / 14 instructions per byte.

### Console Writes

`ubench.console_write bytes=4096` is 48965716 / 177130783, all but 0.2 % in the framebuffer
driver. Its scroll moves the whole framebuffer up a text row at each line it fills
(`memmove` 28673472 / 143361600 and `FramebufferWriter::scroll` 9013440 / 19662656), and
drawing the glyphs is 7156800 / 12820888.

### File Reads and Opens

A read through the inline path (`fsbench.read path=inline`) is fatfs's copy and zeroing of the
reply and the kernel's copy to and from user memory. A read through granted frames
(`path=frame`) spends 12628 / 12530 in the kernel's Keccak permutation (`keccak_f1600`, a kernel entropy
draw) per 4 KiB frame the grant names, 202048 / 200480 of 787886 / 1154116 at 64 KiB; #1550
serves such small draws from one squeezed block. `fsbench.open depth=3` is 77364 / 110805,
one such draw (12628 / 12530) and fatfs's long-name parsing (`LfnAccum`, about 7600) among
it.

## Account

<!-- path-account: begin; generated by cargo xtask path-account write -->
<!-- path-account: end -->

---

## Summarized By

[core/kernel/README.md](../README.md), [Kernel Hot-Path Instruction Account](hot-path-account.md)
