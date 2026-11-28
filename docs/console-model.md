# Console Model

Defines which component owns serial/console byte output and framebuffer
text output across the system lifecycle, and how userspace output is
mediated by per-device drivers.

---

## Ownership across the boot lifecycle

Console output passes through a sequence of owners as the system comes up.
Each owner is authoritative for its window. The bootloader console's window ends at the
kernel handoff, and init-logd's ends at the real-logd handover (item 3); only the kernel's
direct console paths remain as fallbacks for the life of the system.

1. **Bootloader early console** — `core/boot/src/console.rs` drives the UART
   and framebuffer directly during UEFI boot, before the kernel exists. On
   RISC-V the UART base is discovered via ACPI SPCR
   (`core/boot/src/arch/riscv64/serial.rs`), then the Device Tree, falling back to the QEMU
   `virt` default `0x10000000` (discovery order per
   [Early Console § Serial Backend](../core/boot/docs/console.md#serial-backend)); on x86-64 it
   is COM1 at I/O port `0x3F8`. The framebuffer base is discovered via UEFI GOP and captured
   into `BootInfo.framebuffer` before `ExitBootServices` — GOP's active framebuffer identity is
   unreachable from any later component, so the bootloader is the only entity that can carry the
   geometry forward.

2. **Kernel early console** — `core/kernel/src/console.rs` (plus
   `core/kernel/src/framebuffer.rs`) owns the kernel's print macros and the panic
   path. It writes the UART directly and **retains** that direct access for the
   life of the system: panics, the softlockup watchdog's reports and pre-userspace diagnostics
   must not depend on userspace IPC. While a userspace reader is attached to the kernel log, the
   kernel's address-free lines (`kprintln!`) and userspace-fault diagnostics
   (`kprintln_fault!`) are records that reader writes on its console instead, so a kernel line
   does not land inside one of the reader's; with no reader attached, or after one leaves a record
   unread (neither read nor printed by a flush) for `KLOG_STALL_MS`, measured from the record's
   append, the kernel writes them directly again, and before a failure report it writes the
   records no reader has written
   ([core/kernel/docs/kernel-log.md](../core/kernel/docs/kernel-log.md)). In a normally-composed
   boot the reader is init-logd and then real-logd (items 3 and 4), which write each record as a
   `[kernel]` line between whole userspace lines; in a ktest boot it is ktest. The kernel
   framebuffer renderer is similarly **retained**: it carries the console lines the kernel writes
   directly (`kprintln!` with no reader attached, and `kprintln_direct!`), including the
   address-free header line of a fatal `KERNEL EXCEPTION` dump, while the panic path itself is
   serial-only (`console::panic_write_fmt`). The dump's kernel-address lines are serial-only.
   The kernel never becomes a client of the userspace serial or framebuffer driver.

   A **serial-only class** of kernel output writes the UART but skips the
   framebuffer and is never a kernel log record: the spin-locking `kprintln_serial!` /
   `console::print_serial` and the lock-bypassing `console::panic_write_fmt` and
   `kprintln_nmi!` / `console::nmi_write_fmt` for the panic and NMI paths. It
   exists because `kprintln!` *mirrors* to the framebuffer, and although the
   kernel writes that framebuffer directly rather than as a driver client, the
   framebuffer memory is later handed to the userspace framebuffer driver — so
   anything `kprintln!` draws can be read back by userspace, as can anything that is a kernel
   log record. Which kernel output must use the serial-only class is specified in
   [core/kernel/docs/cross-boundary-disclosure.md](../core/kernel/docs/cross-boundary-disclosure.md)
   § Kernel console diagnostics.

3. **init-logd direct-UART fallback** — during early userspace boot, the
   init-logd thread (a second thread of the init process,
   `services/init/src/logging.rs`) drains the master log endpoint and writes
   lines to the UART directly. It owns console output from the moment init
   spawns it through the entire init → svcmgr handover and svcmgr's reconcile,
   until the svcmgr-launched [real-logd](../services/logd/README.md) assumes the
   endpoint's RECV, pulls init-logd's captured history via
   `log_labels::HANDOVER_PULL`, then releases it with
   `log_labels::HANDOVER_RELEASE` — at which point init-logd self-terminates (see
   [logd handover protocol](../services/logd/docs/handover-protocol.md)). This direct path is a
   fixed part of the boot design, not a stopgap: together with init's main thread, which writes
   the UART directly until init-logd is spawned, it is the only userspace writer until real-logd
   takes the endpoint. real-logd starts before that and holds its own diagnostics until init-logd
   has acknowledged the release, since the two writers share no lock and their lines would
   interleave on the UART byte by byte; init-logd writes its last line before that
   acknowledgement ([logd handover protocol](../services/logd/docs/handover-protocol.md)
   § Startup ordering).

   init-logd is also the kernel log's first reader. It binds a notification the kernel signals
   when it appends a line, waits on it and the master log endpoint together, writes each record
   to the UART as a `[<t>] LEVEL  [kernel] <text>` line between the senders' lines, stamped with the
   record's own time, and keeps it in its history under the kernel's slot (`LOG_BADGE_KERNEL`).
   It stops reading at real-logd's first `HANDOVER_PULL`, once it has written and acknowledged
   what the kernel holds, so the history that pull drains holds every kernel line it wrote; the
   kernel's later lines wait as records for real-logd (item 4). Before init-logd is spawned no
   reader is attached, and the kernel writes its lines directly beside init's main thread's.

   The handover is unconditional: while devmgr serves no serial driver
   (its start has not finished, or failed), real-logd retains the lines after the handover in
   its history, and its serial sink writes them once the driver comes up, counting those the
   history's bound drops first; if it never does, that output never reaches the UART (real-logd
   keeps what its history bound allows). init-logd has no direct-framebuffer path; before
   the framebuffer driver is up, userspace output reaches only the UART, and the screen keeps what
   the kernel's console drew there. Neither console driver is in the bootstrap bundle
   ([boot-media.md](boot-media.md) § The Bootstrap Closure): devmgr starts both from the root
   filesystem, so a boot whose root does not mount ends with init-logd's lines on the UART and the
   kernel's console on the screen.
   devmgr retries a console driver's start whose create procmgr refuses with an error a later
   create can outlive, within a bound
   ([devmgr responsibilities](../services/devmgr/docs/responsibilities.md#create-retry)): the
   serial driver comes up once a retry's create succeeds, and never comes up only when its retries
   are given up or its start fails otherwise.

4. **Serial-driver-mediated path** — devmgr spawns the serial driver (`services/drivers/serial/`)
   from the root filesystem, in the drivers-directory pass that svcmgr's `SET_DRIVERS_DIR` posts
   after the root mount;
   once init-logd has released the master log endpoint to real-logd, every userspace UART writer
   routes bytes to it via `serial_labels::SERIAL_WRITE_BYTES`. real-logd
   (`services/logd/src/main.rs`) is the primary client: svcmgr launches and supervises it, it
   resolves the driver's write endpoint through `devmgr_labels::QUERY_DEVICE` sent on its serial
   class SEND, registering a `WATCH_CLASS` watch on the class and resolving again only when devmgr
   signals it, and it emits both received log lines and its own diagnostics through it — including
   its own panic / alloc-error output, routed here via a `std::os::seraph::set_panic_sink` sink
   rather than the log endpoint logd serves (logd deletes its seeded `log_send_cap` at startup so a
   fault cannot self-IPC into it). A log call returns once logd has retained its line in its
   history, the journal every sink writes from, not once the line is written. The serial sink is a
   cursor into the journal and one writer thread, the only logd thread that waits on the driver.
   The writer writes each line's bytes, then a zero-length `serial_labels::SERIAL_WRITE_SENT`
   write, which the driver answers once the line's bytes have left the UART, and moves its cursor
   only then, so a line counts as written when it is on the wire; a write without the flag, such
   as the terminal's, is answered once its bytes are in the driver's transmit ring. A sender that
   must know its lines are on the wire before it goes on, a power-off or a reset included, waits on
   logd's flush barrier (`LOG_FLUSH`). A sender holding a full window of lines the serial sink has
   not written is refused `WINDOW_FULL` and sends again after a hint, within its call's bound, so a
   flood paces its own sender only; a driver that is stopped or dead stalls the sink after
   `SINK_STALL_MS`, and a stalled sink holds no sender. A sink whose writer logd could not spawn is
   written by the thread that retains each line instead, and a stopped driver then costs every line
   up to that bound. The panic sink's direct calls are bounded the same way
   ([services/logd/docs/ipc-interface.md](../services/logd/docs/ipc-interface.md#output-sinks)
   § Output sinks, § Hold window, § Flush barrier).

   real-logd reads the kernel log from the release on, through the `KernelLog` capability svcmgr
   gives it ([logd handover protocol](../services/logd/docs/handover-protocol.md) § Kernel log): a
   thread of its own waits on a notification the kernel signals and retains each record as the
   kernel's `[kernel]` line in the kernel's slot, which the sinks write as any line and every
   `logd.query` or `logd.follow` holder can read. A record is acknowledged on the
   reader's next read once its line is written or its sink stalled, so a record a failure report
   flushes is one no sink took.

   Outside the serial driver, UART hardware authority is held only
   by init, whose init-logd thread uses it (on riscv64 until init-logd exits after the handover and
   deletes init's UART Mmio capability), and by devmgr, whose I/O-port and MMIO caps it carves the
   driver's cap from.

   real-logd is restartable (`restart = on_failure`; see
   [services/logd/README.md](../services/logd/README.md)). svcmgr holds the master-log endpoint
   source for the system's life, so a restarted logd
   re-attaches a fresh RECV to the same endpoint object every sender already targets; the log
   senders are uninterrupted across the restart and need no re-derivation of their `log_send_cap`. A
   restarted logd re-resolves the serial driver via `QUERY_DEVICE` on the serial class SEND (under a
   new `WATCH_CLASS` watch) and resumes serial-mediated output. While logd is down, a sender's
   `STREAM_BYTES` call waits at the kernel endpoint for at most its bound (`LOG_CALL_TIMEOUT_MS`,
   then `LOG_CALL_UNANSWERED_TIMEOUT_MS` once one of the process's calls has gone unanswered, per
   [shared/log](../shared/log/README.md)), and a line no logd takes within it is dropped; the kernel
   panic console remains the guaranteed output path for any fault in that window, and the
   kernel's own lines wait as records only until one has gone unread for `KLOG_STALL_MS`, after
   which the kernel writes them directly until the restarted logd reads again. svcmgr writes no
   line of logd's death before the respawn, so none of its own waits on those bounds (but for a
   first launch's death before its bootstrap request, which init-logd, still serving, receives),
   and procmgr
   takes a restarted logd's `REGISTER_DEATH_EQ` in place of the dead instance's, per [svcmgr
   restart protocol](../services/svcmgr/docs/restart-protocol.md) § Supervision hierarchy.

5. **Framebuffer-driver-mediated path** — once devmgr has spawned the
   framebuffer driver (`services/drivers/framebuffer/`), userspace
   framebuffer writers route bytes to it via `fb_labels::FB_WRITE_BYTES`.
   Consumers:
   - **real-logd** (`services/logd/src/main.rs`) resolves the framebuffer
     write cap via `devmgr_labels::QUERY_DEVICE` sent on its framebuffer class SEND, under a
     `WATCH_CLASS` watch handled as the serial driver's, and writes the log lines at or above
     the framebuffer sink's level to it: critical and more severe by default, so a healthy boot
     shows no log line on the screen, and on an emergency line the sink first writes the
     informational and more severe lines before it that it did not show, up to its `backlog`
     (64 by default), so the screen of a dead machine carries its context. The level, the
     backlog and the tag's colour are settings of logd's recipe
     ([services/logd/docs/sinks.md](../services/logd/docs/sinks.md) § Settings), which a
     `SINK_SET` on `logd.control` changes for the life of the logd instance
     ([services/logd/docs/ipc-interface.md](../services/logd/docs/ipc-interface.md) § Sink
     control). The sink has its own cursor into the journal and its own writer, and it never holds
     a sender, so a framebuffer driver that is stopped or dead holds neither the serial output nor
     the log stream; what the journal drops before the sink reaches it, of the lines it shows, is
     counted in a notice line.
     The framebuffer driver, when present, is spawned from the root filesystem in devmgr's
     drivers-directory pass, which svcmgr posts with `SET_DRIVERS_DIR` before it launches logd, and
     a `QUERY_DEVICE` of logd's that would find no driver waits for that pass; logd's emit path
     never calls devmgr and, while no framebuffer driver is resolved (headless boot), writes the
     sink nowhere: a driver resolved later starts at the newest `backlog` lines and counts the ones
     before them that the sink shows as dropped, so serial stays the authoritative channel. The
     driver clears the screen when it starts (`FramebufferWriter::new`), so the kernel's console
     stays on it until then.
   - **[`programs/terminal`](../programs/terminal/README.md)** (#111) resolves the
     framebuffer write cap via `QUERY_DEVICE` on its framebuffer class SEND, again on the class
     watch when devmgr restarts the driver, and renders the
     stdout of its session's leader — the shell (#112) and anything the shell runs — to the
     screen, mirrored to serial.
     This is the production console path: ordinary programs do not resolve the
     framebuffer themselves; they write stdout and the terminal relays it.
     [programs/fb-charset/README.md](../programs/fb-charset/README.md) describes one such
     program — a manual demo (a step above
     "hello world") that prints a sample of every glyph class (ASCII, CP437
     high half, box-drawing, font-extension, ASCII fallback, and one ill-formed
     sequence so the U+FFFD glyph is reachable) to stdout for eyeballing the
     driver's rendering. It is run from the shell and is not auto-started.

   A compositor / display broker ([#153](https://github.com/kottlerg/seraph/issues/153)) is to
   resolve the cap through the same name (design intent; not yet implemented). v1 exposes two
   verbs, specified in
   [services/drivers/framebuffer/README.md](../services/drivers/framebuffer/README.md)
   § Messages — `FB_WRITE_BYTES`
   (UTF-8 payloads, `\n`/`\r`/`\x08` short-circuited) and `FB_SET_ATTRS` (sticky
   24-bit foreground/background colour). The terminal owns ANSI SGR parsing
   (`ESC[…m` → `FB_SET_ATTRS`); the driver never interprets control sequences,
   so replacing the terminal does not touch the driver. The colour state is a
   single global, shared by the terminal and logd's framebuffer sink like
   the single cursor: the sink sets its level tag's colour and then the default colour back, so a
   colour the terminal had set is reset by a log line; per-client attribute state arrives with the
   compositor (#153). Graphical primitives are listed in
   [services/drivers/framebuffer/README.md](../services/drivers/framebuffer/README.md)
   § Planned future surface.

## The serial driver as sole userspace UART owner

The serial driver owns the platform UART authority cap end-to-end — an
`IoPort` for COM1 on x86-64, an `Mmio` for the NS16550 on RISC-V, plus the
UART interrupt cap — delegated by devmgr at spawn. It is a device driver, not a
console daemon: no name registry, no log routing, no VT/ANSI. With the interrupt it moves bytes
through a transmit ring and a receive ring: a write is answered once its bytes are in the
transmit ring, or with `SERIAL_WRITE_SENT` once they have left the UART, and a read, the
terminal's serial input source, takes what the receive ring holds without waiting on a write
([services/drivers/serial/README.md](../services/drivers/serial/README.md#transmit-and-receive)
§ Transmit and receive). It has no line editing or cooked-mode processing — those live in the
terminal. Clients
obtain a read/write capability through devmgr (a device authority), not through
svcmgr (a service registry): a UART is a device, not a service. The driver's IPC
contract is specified in [services/drivers/serial/README.md](../services/drivers/serial/README.md).

The debug port is outside the console model. It is a second byte transport, apart from the UART,
which a boot attaches only on request: a debugger stub, the GDB stub
([services/gdbstub/README.md](../services/gdbstub/README.md)), owns it to speak to a host
debugger, and no
console output reaches it, so the UART stays the console and the authoritative marker channel.
Its driver
([services/drivers/virtio/console/README.md](../services/drivers/virtio/console/README.md))
serves the same serial protocol, and devmgr hands it only to the service whose definition seeds
`devmgr.class.debug-port`
([device-management.md](device-management.md#relationship-to-other-services)
§ Relationship to Other Services).

## The framebuffer driver as sole userspace framebuffer owner

The framebuffer driver owns the bootloader-discovered GOP linear
framebuffer end-to-end — an `Mmio` carved from a bootloader-
synthesised aperture that covers
`[physical_base, physical_base + stride * height)` (page-aligned),
delegated by devmgr at spawn. The driver queries devmgr for its geometry via the generic
`QUERY_DEVICE_INFO` path (kind `FRAMEBUFFER`), maps the entire region into its own address
space, and serves `FB_WRITE_BYTES` and `FB_SET_ATTRS`. Like the serial driver it is a device
driver, not a console daemon: no name registry, no log routing, no graphical
primitives, no input. The driver's IPC contract is specified in
[services/drivers/framebuffer/README.md](../services/drivers/framebuffer/README.md).

## Logging constraint on the serial and framebuffer drivers

The serial driver and the framebuffer driver MUST NOT emit `std::os::seraph::log!`. logd writes
log lines to both, each at its sink's level, so a line either driver logged would be written back
through it: a
diagnostic on its write path would feed itself, one more line per line written. Both drivers
therefore drop diagnostics, and fatal bootstrap failures end the driver's thread without output.
Neither driver's service thread waits on logd, and no thread of logd's but a sink's writer waits
on a driver for longer than `SINK_STALL_MS`, so both drivers can be stopped by a debugger and
are covered by the crash service like any other driver
([fault-handling.md](fault-handling.md)). The pre-driver boot window is
covered by init-logd's direct-UART path (see § Why the direct paths remain), and the kernel
renderer is the early-boot and panic fallback for the framebuffer. The other userspace drivers
are not under this constraint.

## Why the direct paths remain

The kernel panic console (UART) and the kernel framebuffer renderer bypass the serial and
framebuffer drivers for the life of the system, and neither can depend on the IPC machinery
that the drivers require. The UART path is kept so a panic can still produce output; the
framebuffer renderer is kept so the mirrored `kprintln!` console, including the address-free
header line of a fatal `KERNEL EXCEPTION` dump, reaches the screen (the dump's kernel-address
lines are serial-only). The bootloader console (UART and
framebuffer) and init-logd's direct-UART path are fixed parts of the boot design that bypass the
drivers only within their windows, which end at the kernel handoff and the real-logd handover
respectively; they carry output before the drivers are reachable. All of these paths share the
hardware with the drivers — an accepted physical aliasing, since the drivers are the
steady-state writers and the direct paths fire only in early boot and failure windows. The
kernel's routine lines are not among them while a reader is attached: init-logd and then
real-logd write them as whole lines among the userspace lines (items 2 to 4), so a kernel line
can still meet a userspace line on the UART only before init-logd attaches, in a failure window
(a panic, a fatal exception, an NMI or watchdog report, and the flush before each), for the
serial-only class, and while the reader is stalled.

## Test-harness output

ktest sends its markers and diagnostics to the framebuffer as well as serial, matching the
early-kernel console; svctest's and usertest's reach serial only:

- **ktest** (`core/ktest/`) is a monolithic init replacement: its bundle
  carries no devmgr and no framebuffer driver, so it renders directly,
  mapping the framebuffer from `InitInfo.framebuffer` and carving the
  pixel span out of the MMIO aperture it holds (`core/ktest/src/framebuffer.rs`).
  This is the harness analogue of the kernel's direct renderer — there is
  no driver in its bundle to route through — so it does not contradict the
  framebuffer driver's sole ownership in a normally-composed boot.
- **svctest / usertest** are std-built services whose output flows through
  the system log stream at informational, below the framebuffer sink's default level of critical
  (path 5 above), so it reaches the screen only through that sink's emergency walk, or when a
  recipe, or a `SINK_SET` on `logd.control`, lowers its level. No harness-specific framebuffer
  path exists.

Serial is the authoritative marker channel: CI scrapes serial and
runs the harnesses headless, where logd's framebuffer sink writes nothing, but for the release
svctest cells, which attach a framebuffer for svctest's framebuffer cases, and the `bench` cell's
ubench boots, which attach one for ubench's framebuffer measurements (see
[docs/testing.md](testing.md#coverage-tiers) § Coverage tiers).

Every framebuffer renderer — the bootloader, kernel, and ktest direct
renderers and the userspace driver — shares one byte→glyph chain
([shared/text/README.md](../shared/text/README.md)): an incremental UTF-8 decoder feeding the
CP437-reverse → font-extension → ASCII-fallback → `U+FFFD` resolver, so every framebuffer
surface prints the identical glyph set.

---

## Summarized By

[Kernel Cross-Boundary Disclosure Inventory](../core/kernel/docs/cross-boundary-disclosure.md),
[Kernel Log](../core/kernel/docs/kernel-log.md),
[Coding Standards](coding-standards.md),
[services/drivers/framebuffer/README.md](../services/drivers/framebuffer/README.md),
[services/drivers/serial/README.md](../services/drivers/serial/README.md),
[services/logd/README.md](../services/logd/README.md),
[shared/ansi/README.md](../shared/ansi/README.md)
