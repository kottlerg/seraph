# Core Format

The ELF core crashd writes for a process that died on a fault, and the directory it writes cores
to: the contract host `gdb` and any other reader of `/crash` rely on. When crashd writes a core
is in [operation.md](operation.md) § Core Dump.

---

## Directory

Cores are files in `/crash` on the root filesystem. crashd's recipe grants it that directory as
its namespace root with `LOOKUP`, `READDIR`, `STAT`, `WRITE` and `MUTATE_DIR`, and not
`READ`: a core holds the process's memory, secrets included, so reading one takes a cap to
`/crash` that crashd does not hand out. The build creates the directory on every image
([rootfs/README.md](../../../rootfs/README.md)).

A core is named `<seq>-<label>.core`:

- `<seq>` is ten decimal digits, one more than the highest sequence number of a core or a partial
  core in the directory, so the lowest is the oldest. FAT keeps no modification time crashd can
  read, so the order is the name's.
- `<label>` is the last `/`-separated component of the process's name, the first string of its
  argv, with every byte outside `A-Z`, `a-z`, `0-9`, `_`, `.` and `-` replaced by `_`, cut to
  48 bytes, and `process` when that leaves it empty.

crashd writes a core as `<seq>-<label>.core.part` and renames it to its name once every byte is
written, so a file named `.core` is complete. A `.part` that a dump left, cancelled or failed, is
deleted by the next dump.

Two byte budgets bound what the directory holds:

| Budget | Value | When it is reached |
|---|---|---|
| Per core (`CORE_BYTES_MAX`) | 2 MiB, the head included | Page runs that do not fit are left out ([Page runs](#page-runs)) |
| Directory (`CORE_DIR_BYTES_MAX`) | 64 MiB of complete cores | The oldest cores are deleted until the new one fits |

Both are constants of `services/crashd/src/dump.rs`; [operation.md](operation.md) § Bounds says
how the per-core budget follows from the dump's bound.

---

## File

A core is a 64-bit little-endian ELF file of type `ET_CORE`, machine `EM_X86_64` or `EM_RISCV`,
with no sections. Its program headers are one `PT_NOTE`, first, then one `PT_LOAD` per page run.
The file is laid out as:

1. the ELF header and the program headers;
2. the notes, padded to a page;
3. the bytes of each kept page run, in program-header order.

### Page runs

The runs are the mapped user pages of the process's address space as `SYS_THREAD_LIST_PAGES`
reports them ([core/kernel/docs/syscalls.md](../../../core/kernel/docs/syscalls.md)), adjacent
pages of one protection joined into one run, in address order, at most 65 533 (`e_phnum` is 16
bits and the `PN_XNUM` extension is not written). Each `PT_LOAD` carries:

| Field | Value |
|---|---|
| `p_vaddr` | The run's first address |
| `p_memsz` | The run's bytes |
| `p_filesz` | `p_memsz` when the run is kept, `0` when it is left out |
| `p_flags` | `PF_R`, `PF_W`, `PF_X` as the run's protection grants |
| `p_align` | 4096 |

A run left out keeps its `PT_LOAD`, so the core still shows the mapping. A run is left out when
the kernel reports it cannot be copied (`PAGE_RUN_NO_COPY`: device memory and the like), or when
it does not fit the budget. The budget keeps the runs that hold the fault's instruction pointer,
then those holding each recorded thread's stack pointer, in thread order, then the others in
address order; each is kept whole when it fits what the budget leaves. A page of a kept run that
the kernel refuses to copy when crashd reads it is written as zeros.

### Notes

The notes use the Linux layouts `gdb` reads: it takes a thread's state from the notes that follow
its `NT_PRSTATUS`, and the first thread as the one the process stopped in. In order:

| Note | Owner | Content |
|---|---|---|
| `NT_PRPSINFO` | `CORE` | The process's name: `pr_fname` its last path component, `pr_psargs` all of it, each cut to its field; `pr_pid` |
| `NT_AUXV` | `CORE` | `AT_PHDR`, `AT_PHENT`, `AT_PHNUM`, `AT_ENTRY` of the image as loaded, from its ELF header read at the load bias, so `gdb` relocates the position-independent executable; absent when the header could not be read |

Then, for each recorded thread, the faulting one first:

| Note | Owner | Content |
|---|---|---|
| `NT_PRSTATUS` | `CORE` | `elf_prstatus`: the signal (the faulting thread's alone, 0 for the others), `pr_pid` the thread's id, `pr_pgrp` and `pr_sid` the process's, the general registers as `pr_reg`, and `pr_fpvalid` |
| `NT_FPREGSET` | `CORE` | The floating-point state: the `FXSAVE` image on x86-64, `f0`-`f31` and `fcsr` on riscv64; absent when the extended state could not be read |
| `NT_X86_XSTATE` (x86-64) | `LINUX` | The `XSAVE` area, with the components saved in its software-reserved `XCR0` word |
| `NT_RISCV_VECTOR` (riscv64) | `LINUX` | `vstart`, `vl`, `vtype`, `vcsr`, `vlenb`, then `v0`-`v31`; absent on a hart without the vector extension |

`pr_reg` holds the register file `SYS_THREAD_READ_REGS` returns in Linux's order: on x86-64,
`user_regs_struct` (`r15` first, `orig_rax` all ones, `gs_base` and the segment selectors other
than `cs` and `ss` zero, since the file lacks them); on riscv64, `pc` then `x1`-`x31`. The
extended state is what `SYS_THREAD_READ_EXT_REGS` returns.

The process id is the low 32 bits of the process's badge. The thread ids number the recorded
threads from 1, the faulting thread's 1, and are unique within the core only.

The signal is the one Linux delivers for the fault, which `gdb` reports the core as terminated by:

| Fault | Signal |
|---|---|
| A page fault the pager forwarded | `SIGSEGV` |
| Illegal instruction | `SIGILL` |
| Breakpoint, debug | `SIGTRAP` |
| Divide, overflow, floating point | `SIGFPE` |
| Alignment | `SIGBUS` |
| Any other exception | `SIGSEGV` |

---

## Reading a Core

Copy the core off the root partition, or read it in the system with a cap to `/crash`, and give
`gdb` the binary the process ran:

```
gdb <binary> <core>
```

The binary is the symbols-store file of the build id of the image at the path the core's `pr_psargs`
names (`symbols/manifest` lists `/programs/crashme <file>`); on riscv64, a `gdb` built for x86-64
hosts needs `set architecture riscv:rv64` before it loads the binary. `gdb` lists every recorded
thread, the faulting one current, and its stack, registers and floating-point and vector state.

The code is `services/crashd/core-file`, host-tested: the notes, the layout and the budget's
choice of runs, the policy, and the directory's names and eviction. crashd reads the process and
writes the file.

---

## Summarized By

[Fault Handling](../../../docs/fault-handling.md),
[programs/crashme/README.md](../../../programs/crashme/README.md),
[services/crashd/README.md](../README.md), [crashd Operation](operation.md)
