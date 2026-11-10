# Crash Block Format

The format of the block crashd logs for each faulting process: the contract the host-side
symbolizer and `cargo xtask test-crash-report` read.

---

## Lines

A crash report is one block of lines in the system log. logd prefixes each with crashd's log name,
so on the serial console a line reads `[<seconds>] [crashd] <line>`; a reader finds a line by its
tag wherever it starts on a log line. Three kinds of line make a block, each carrying the block's
`id`, sixteen lowercase hexadecimal digits:

```
CRASH-BEGIN id=<id> version=<version>
CRASH id=<id> <key>=<value>
CRASH-END id=<id> lines=<count>
```

- The begin marker opens the block and names the format's `version`, today `1`. A change that
  renames or removes a field or changes a value's encoding bumps it; a new field does not.
- Each field line carries one field. A reader keys the line to the open block whose `id` it
  carries, so the lines of two blocks, and lines of other senders, may interleave.
- The end marker closes the block; `count` is the number of field lines. A block whose end marker
  is missing, or whose count is not the number of field lines read, is incomplete. A field line
  that repeats one already read, key and value alike, is read once: crashd writes a line again
  when the watchdog cancelled its first write, which may have landed.

The `id` is drawn from the kernel's entropy per block (from the time since crashd started when the
draw fails, which still tells a boot's blocks apart). crashd also gives it as the reason of the
decline that ends the thread, so the kernel's `fault unhandled: tid=<n> handler declined,
reason=<id>` line on the serial console belongs to the block with that `id`.

---

## Fields

In the order crashd writes them. Hexadecimal words are `0x` and sixteen digits; a key a reader does
not know is skipped.

| Key | Value | Present |
|---|---|---|
| `badge` | The process badge, decimal: the key logd's `reclaim: badge=<badge> exit_reason=<reason> name=<log name>` line names the process by at its death | always |
| `arch` | `x86_64` or `riscv64` | always |
| `thread` | `main`, the process's main thread, whose registers the block carries; or `unidentified`, another thread ([operation.md](operation.md) § Per Fault, § Limits) | always |
| `status` | `complete`; `unattached`, the attach failed: procmgr refused it (the process had exited, or declared itself undebuggable) or the call failed; or `timeout`, the watchdog cancelled the attach ([operation.md](operation.md) § Bounds) | always |
| `kind` | `vm`, a page fault the pager forwarded; or `exception` | always |
| `access` | `read`, `write`, or `fetch` | `vm` |
| `addr` | The faulting address, hexadecimal | `vm` |
| `pager_reason` | The pager's decline reason, hexadecimal ([memmgr's table](../../memmgr/docs/ipc-interface.md#kernel-origin-fault-message-fault_label)) | `vm`, when the pager sent one |
| `exception` | The normalized class: `illegal-instruction`, `breakpoint`, `debug`, `divide`, `overflow`, `bound-range`, `alignment`, `access`, `protection`, `fp`, or `unknown` | `exception` |
| `aux` | The architecture's auxiliary code: the x86-64 error code, or the riscv64 `stval`, hexadecimal | `exception` |
| `ip` | The faulting instruction pointer from the fault message, hexadecimal | always |
| `load_bias` | The bias the loader added to every ELF address of the image, hexadecimal | `complete` |
| `text` | The biased bounds of the image's executable segments, `0x<start>-0x<end>`, the end exclusive | `complete` |
| `reg.<name>` | One line per register of the register file, hexadecimal: on x86-64 `rax` to `r15`, `rip`, `rflags`, `rsp`, `cs`, `ss`, `fs_base`; on riscv64 `ra` to `t6` by ABI name, then `sepc`, `scause`, `stval`, `sstatus` | `complete` and `main` |
| `code` | The bytes at `ip`, up to sixteen, two hexadecimal digits each; fewer at the end of a page whose successor is not present | when `ip`'s page is present |
| `walk` | `scan`: the frames are the stack scan below | `complete` and `main` |
| `frame.<n>` | Frame `n`, hexadecimal, from `0`: `frame.0` is `ip`, and each later frame an aligned stack word, read from the stack pointer up, that lies inside `text`; at most 32 | `complete` and `main` |

---

## Stack Walk

Userspace is built without frame pointers, so the walk is a scan: crashd reads up to 8 KiB of the
stack from the stack pointer up, stopping at the first page that is not present, and keeps each
aligned word that lies inside the image's text, in stack order. A frame past `frame.0` is a
candidate return address: a word a returned call left behind, or a function pointer held on the
stack, is one too. A walk by frame pointers, for a build that keeps them, is design intent; not yet
implemented.

---

## Symbolizing

An address `a` in `text` is the ELF address `a - load_bias` of the image the process ran. The block
names the process by its badge only: the image is found through logd's `reclaim:` line for that
badge, whose name is the log name the process registered
([logd IPC interface](../../logd/docs/ipc-interface.md) § Death-notification cascade).

The emitter and the parser are `shared/crash-report`
([shared/crash-report/README.md](../../../shared/crash-report/README.md)), which crashd and xtask
share.

---

## Summarized By

[services/crashd/README.md](../README.md),
[shared/crash-report/README.md](../../../shared/crash-report/README.md)
