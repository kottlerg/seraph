# Kernel Log

The kernel log: the ring the kernel appends its console lines to while a userspace reader is
attached, the classes of print site, the reader protocol, and the flushes on the failure paths.

---

## Purpose

A kernel line written straight to the serial port while a userspace program writes the same port
can land inside one of that program's lines, and tear it. While a reader is attached, the kernel
does not write the port for its routine lines: it appends each as a record to the kernel log, and
the reader writes the records on the port among its own lines, whole. Before a reader attaches,
and after one stalls (§ Readers), the kernel writes every line directly, as a kernel with no log
reader does.

The log holds only lines a reader may see: no kernel virtual address, no physical address and no
value derived from the KASLR slide
([cross-boundary-disclosure.md](cross-boundary-disclosure.md) § Kernel console diagnostics). A
line that carries one is written to the serial port only and is never a record
(§ Print classes).

---

## The ring

The log is one ring of `KLOG_RING_BYTES` (16 KiB), a static array of 64-bit atomic words in the
kernel image (`klog::ring::Ring`). Every access to a word is atomic, so a reader that takes no
lock races no plain access.

- **Record.** A 24-byte header (`KLOG_HEADER_BYTES`) of three words, then the text, padded with
  zero bytes to a whole word. The first word holds the sequence number, tagged with `0xFF` in its
  top byte; the second the kernel's time when the line was formed, in microseconds; the third the
  level in its low byte, the flags in the next, and the text length in bits 16-31. The sequence
  number is 1 for the first record and one more for each after it, and is never reused. No UTF-8
  text word holds a `0xFF` byte, so a text word is never taken for a header.
- **Text.** A line is formed in place, under `KLOG_LOCK`, through a `fmt::Write` that stores
  straight into the ring's words. A line longer than `KLOG_LINE_MAX` (512 bytes) is cut at a
  character boundary and carries `KLOG_FLAG_TRUNCATED`. Since the line is formed under the lock,
  a `Display` implementation that a print formats MUST NOT print.
- **Positions.** The ring keeps the byte positions of its oldest record and one past its newest.
  Positions only grow; a position names word `(pos / 8) % words`, so a record can wrap past the
  array's end.
- **Overwrite.** Before a record is formed, the appender drops the oldest records until a record
  of the longest line fits. It clears the sequence word of each record it drops, issues a release
  fence, and only then writes the new record's words. It stores the new sequence word last, with
  release ordering.
- **Drops.** A record is dropped when the ring is full, whether or not a reader has read it. The
  kernel keeps no drop count: a reader learns of a drop from a gap in the sequence numbers it is
  given. Since records exist only while a reader is attached, every gap is a lost line.
- **Lock-free read.** `Ring::read_unlocked` reads a record as a sequence-lock reader does: the
  sequence word with acquire ordering, the header and the text, an acquire fence, and the
  sequence word again. It accepts the record only when both reads give the sequence number the
  walk expects and the length is at most `KLOG_LINE_MAX`; otherwise the appender is overwriting
  it. The flushes (§ Flush) read the ring this way, without `KLOG_LOCK`.

---

## Print classes

Every kernel print site takes one of five classes, by what its line carries and when it is
printed. The class decides the macro.

| Class | Line | Macro | No reader attached | Reader attached |
|---|---|---|---|---|
| R | An address-free line, a warning after which the system goes on included | `kprintln!` | Written to the console (serial port and framebuffer) | A record |
| U | A userspace fault's diagnostic | `kprintln_fault!` | Written to the serial port | A record |
| D | A line that carries a kernel virtual address, a physical address, a KASLR-derived value, or a kernel-half fault's raw error code | `kprintln_serial!` | Written to the serial port | Written to the serial port; never a record |
| W | The softlockup watchdog's own reports | `kprintln_direct!` | Written to the console | Written to the console, after a flush |
| F | A line on a path that ends in `fatal` or a panic | `kprintln_direct!`, the panic handler, `kprintln_nmi!` | Written to the console, after a flush | The same |

- A U line carries only what the fault message the kernel delivers to a fault handler carries:
  the thread id, the cause, the user address and the faulting thread's own registers. On x86-64
  the `USERSPACE FAULT` line's error code has its present bit cleared for a page fault at or
  above the user half's top, as the fault message's has. The register dump shared by user and
  kernel traps (`dump_x86_regs`, `dump_riscv_regs`) takes the print function as an argument:
  `klog::print_fault` for a user trap, `console::print_serial` for a kernel trap.
- A warning that lets the system go on (a lock held past a bound, a tripwire) is R: it fires on
  healthy, contended boots, and written directly while a reader is attached it would tear that
  reader's lines.
- Every line is written to the serial port under one hold of the console lock, its timestamp and
  text together, so two kernel lines never interleave.
- Every record takes the informational level (6).

---

## Readers

A reader holds a `KernelLog` capability with `Read`
([capability-model.md](../../../docs/capability-model.md) § `KernelLog`) and reads with
`SYS_KERNEL_LOG_READ` ([syscalls.md](syscalls.md) § `SYS_KERNEL_LOG_READ` (75)). The kernel
keeps one reader cursor, not one per capability: whoever reads is the reader.

- **Attach.** A read that completes attaches the reader. From then on an R or U line is a record.
  A line is a record or a direct write, never both and never neither: an unattached print holds
  `KLOG_LOCK` across its direct write, and the attach takes the same lock.
- **Acknowledgement.** A read carries `ack_seq`, the last record the reader has written or given
  up. The kernel raises its committed mark to it, never past the newest record and never down,
  before it chooses where the read starts, so a read with `from_seq` 0 returns the records after
  the mark. A reader acknowledges what it has written on its next read; an empty buffer only
  acknowledges.
- **Stall.** On each timer tick the bootstrap CPU checks whether records exist past the last one
  a read returned and the bound of `KLOG_STALL_MS` (1000 ms) has passed (`ring::Cursor::stalled`).
  The bound is measured from the append of the oldest of them, or from the reader's last read
  that attached it or returned a record it had not read, whichever came later: a read that
  returns no new record, an acknowledgement alone among them, does not restart it, and a quiet
  period with nothing unread does not count against the next record. The check is a few loads,
  and takes the lock only when they find a stall. A stalled reader is detached and the kernel
  writes its lines directly again, after one R line naming the record the reader stalled at. The
  records already in the ring stay there: the next read attaches the reader again and returns
  them.
- **ktest.** ktest, loaded as init, holds the root capability and is a reader: it attaches at its
  start and drains the log before each line it writes and in its waits
  ([core/ktest/README.md](../../ktest/README.md)).

---

## Reader notification

A reader binds a notification with `SYS_KERNEL_LOG_BIND` ([syscalls.md](syscalls.md)
§ `SYS_KERNEL_LOG_BIND` (76)). An append sets a pending flag; the next timer tick, on whichever
CPU takes it, clears the flag and signals the bound notification with the bound bits. A print
therefore wakes no thread: the signal is at most a tick behind the append, and a burst of lines
costs one signal.

- One binding exists. A bind replaces it, whoever made it; a bind of no notification clears it.
- The binding holds no reference on the notification. The notification's deallocation clears
  the binding (`klog::forget_notification`) before it frees the state, under `BINDING_LOCK`, the
  lock the tick's signal holds, so the tick never signals freed memory. It reads the binding
  first without the lock and takes the lock only when the binding names this notification, so
  the deallocation of any other notification costs one load.

---

## Flush

Before the panic handler's first line, before each F line, and before each W line, the kernel
writes to the serial port every record past the committed mark, oldest first, each as a direct
kernel line with its own timestamp, and raises the mark past them (`klog::flush`). The lines
that led to the failure then come out before its report.

- The flush takes no lock to read the ring (§ The ring, lock-free read), so a CPU that panicked
  or wedged holding `KLOG_LOCK` cannot stop it. It stops at the first record it cannot read
  whole, and says so in one line.
- The panic handler's flush writes through `console::panic_write_fmt`, which takes no lock; the
  others write through the console lock, as their own lines do.
- A reader still running after a W flush, and two CPUs flushing at once, can write a record twice.
  The flush raises the mark with an atomic maximum, so a reader that reads with `from_seq` 0
  afterwards does not.
- The NMI path does not flush: it returns to the interrupted code.

---

## Lock order

- `KLOG_LOCK` serialises appends, reads under the capability, and every change to the reader
  cursor. It is taken with interrupts disabled. The one lock taken under it is the console lock,
  by a line written directly while no reader is attached. No holder of the console lock takes
  `KLOG_LOCK`.
- `BINDING_LOCK` serialises the binding's change, its clearing and the tick's signal. The send
  takes, under it, the notification's own lock and, when the notification is a member of a wait
  set, the wait set's lock and then, waking the wait set's waiter, that thread's `sched_lock` and
  a CPU's scheduler lock; the waiter the send releases directly is enqueued after
  `BINDING_LOCK` is released. `BINDING_LOCK` is never taken while any of those locks is held:
  the bind syscall and a notification's deallocation take it holding none of them, and the tick
  holding no lock.
- `SYS_KERNEL_LOG_READ` copies to the caller's buffer with neither lock held: it copies records
  into a kernel buffer under `KLOG_LOCK`, releases it, then copies to the user buffer.

---

## Summarized By

[core/kernel/README.md](../README.md),
[Kernel Cross-Boundary Disclosure Inventory](cross-boundary-disclosure.md),
[Syscall Interface Specification](syscalls.md), [core/ktest/README.md](../../ktest/README.md),
[Capability Model](../../../docs/capability-model.md),
[Console Model](../../../docs/console-model.md)
