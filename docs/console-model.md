# Console Model

Defines which component owns serial/console byte output and framebuffer
text output across the system lifecycle, and how userspace output is
mediated by per-device drivers.

---

## Ownership across the boot lifecycle

Console output passes through a sequence of owners as the system comes up.
Each owner is authoritative for its window; later owners do not retract the
earlier ones, which remain as fallbacks.

1. **Bootloader early console** — `core/boot/src/console.rs` drives the UART
   and framebuffer directly during UEFI boot, before the kernel exists. On
   RISC-V the UART base is discovered via ACPI SPCR
   (`core/boot/src/arch/riscv64/acpi_spcr.rs`), then the Device Tree, falling back to the QEMU
   `virt` default `0x10000000`; on x86-64 it is COM1 at I/O port `0x3F8`. The framebuffer
   base is discovered via UEFI GOP and captured into `BootInfo.framebuffer` before
   `ExitBootServices` — GOP's active framebuffer identity is unreachable from any later
   component, so the bootloader is the only entity that can carry the geometry forward.

2. **Kernel early console** — `core/kernel/src/console.rs` (plus
   `core/kernel/src/framebuffer.rs`) owns `kprint!`/`kprintln!` and the panic
   path. It writes the UART directly and **retains** that direct access for the
   life of the system: panics and pre-userspace diagnostics must not depend on
   userspace IPC. The kernel framebuffer renderer is similarly **retained**: it carries the
   mirrored `kprintln!` console and the fatal `KERNEL EXCEPTION` dumps, while the panic path
   itself is serial-only (`console::panic_write_fmt`). The kernel never becomes a client of
   the userspace serial or framebuffer driver.

   A **serial-only class** of kernel output writes the UART but skips the
   framebuffer: the spin-locking `kprintln_serial!` / `console::serial_write_fmt`
   and the lock-bypassing `console::panic_write_fmt` and `kprintln_nmi!` /
   `console::nmi_write_fmt` for the panic and NMI paths. It
   exists because `kprintln!` *mirrors* to the framebuffer, and although the
   kernel writes that framebuffer directly rather than as a driver client, the
   framebuffer memory is later handed to the userspace framebuffer driver — so
   anything `kprintln!` draws can be read back by userspace. Which kernel output must use the
   serial-only class, and the paths that still print kernel addresses through `kprintln!`
   ([#440](https://github.com/kottlerg/seraph/issues/440)), are specified in
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
   `log_labels::HANDOVER_RELEASE` — at which point init-logd self-terminates.
   This direct path is **permanent**, not transitional: together with init's main thread, which
   writes the UART directly until init-logd is spawned, it is the only userspace writer until
   real-logd takes the endpoint. The handover is unconditional, so if the serial driver never
   comes up, userspace serial output after the handover is dropped (real-logd keeps the lines in
   its history ring). init-logd has no direct-framebuffer path; before the framebuffer driver is
   up, userspace output reaches only the UART.

4. **Serial-driver-mediated path** — devmgr spawns the serial driver
   (`services/drivers/serial/`); once init-logd has released the master log endpoint to
   real-logd, every userspace UART writer routes bytes to it via
   `serial_labels::SERIAL_WRITE_BYTES`. real-logd
   (`services/logd/src/main.rs`) is the primary client: svcmgr launches and
   supervises it, it resolves the driver's write endpoint through devmgr's
   `devmgr_labels::QUERY_SERIAL_DEVICE`, and it emits both received log lines
   and its own diagnostics through it — including its own panic / alloc-error
   output, routed here via a `std::os::seraph::set_panic_sink` sink rather than
   the log endpoint logd serves (logd deletes its seeded `log_send_cap` at
   startup so a fault cannot self-IPC into it). Outside the serial driver,
   UART hardware authority is held only by init, whose init-logd thread uses it, and by
   devmgr, whose root I/O-port and MMIO authority it carves the driver's cap from.

   real-logd is restartable (`restart = on_failure`; see
   [services/logd/README.md](../services/logd/README.md)). svcmgr holds the
   master-log endpoint source for the system's life, so a restarted logd
   re-attaches a fresh RECV to the same endpoint object every sender already
   targets; the log senders are uninterrupted across the restart and need no
   re-derivation of their `log_send_cap`. A restarted logd re-resolves the
   serial driver via `QUERY_SERIAL_DEVICE` and resumes serial-mediated output.
   While logd is down, a sender's `STREAM_BYTES` queues at the kernel endpoint
   until the restarted logd drains it; the kernel panic console remains the
   guaranteed output path for any fault in that window.

5. **Framebuffer-driver-mediated path** — once devmgr has spawned the
   framebuffer driver (`services/drivers/framebuffer/`), userspace
   framebuffer writers route bytes to it via `fb_labels::FB_WRITE_BYTES`.
   Consumers:
   - **real-logd** (`services/logd/src/main.rs`) resolves the framebuffer
     write cap via `devmgr_labels::QUERY_FRAMEBUFFER_DEVICE` — the same
     registry cap it already holds for the serial driver — and mirrors
     every log line it writes to serial onto the framebuffer too, so the
     steady-state userspace log stream reaches the screen as well as the
     UART. The framebuffer driver, when present, is spawned before svcmgr launches logd;
     logd resolves the mirror once and, when devmgr reports no framebuffer driver (headless
     boot), latches it off for its lifetime, so serial stays the authoritative channel.
   - **`programs/terminal`** (#111) resolves the framebuffer write cap via
     `QUERY_FRAMEBUFFER_DEVICE` and renders its child's stdout — the shell
     (#112) and anything the shell runs — to the screen, mirrored to serial.
     This is the production console path: ordinary programs do not resolve the
     framebuffer themselves; they write stdout and the terminal relays it.
     [programs/fb-charset/README.md](../programs/fb-charset/README.md) describes one such
     program — a manual demo (a step above
     "hello world") that prints a sample of every glyph class (ASCII, CP437
     high half, box-drawing, font-extension, ASCII fallback, and one ill-formed
     sequence so the U+FFFD glyph is reachable) to stdout for eyeballing the
     driver's rendering. It is run from the shell and is not auto-started.

   A compositor / display broker ([#153](https://github.com/kottlerg/seraph/issues/153)) is to
   resolve the cap through the same name. v1 exposes two verbs, specified in
   [services/drivers/framebuffer/README.md](../services/drivers/framebuffer/README.md)
   § Messages — `FB_WRITE_BYTES`
   (UTF-8 payloads, `\n`/`\r`/`\x08` short-circuited) and `FB_SET_ATTRS` (sticky
   24-bit foreground/background colour). The terminal owns ANSI SGR parsing
   (`ESC[…m` → `FB_SET_ATTRS`); the driver never interprets control sequences,
   so replacing the terminal does not touch the driver. The colour state is a
   single global, shared by the terminal and logd's concurrent log mirror like
   the single cursor — a log line written while the terminal holds a non-default
   colour inherits it; per-client attribute state arrives with the compositor
   (#153). Graphical primitives are listed in
   [services/drivers/framebuffer/README.md](../services/drivers/framebuffer/README.md)
   § Planned future surface.

## The serial driver as sole userspace UART owner

The serial driver owns the platform UART authority cap end-to-end — an
`IoPort` for COM1 on x86-64, an `Mmio` for the NS16550 on RISC-V, plus the
UART interrupt cap — delegated by devmgr at spawn. It is a device driver, not a
console daemon: no name registry, no log routing, no VT/ANSI. It carries a
minimal interrupt-driven read path (the terminal's serial input source) but no
line editing or cooked-mode processing — those live in the terminal. Clients
obtain a read/write capability through devmgr (a device authority), not through
svcmgr (a service registry): a UART is a device, not a service. The driver's IPC
contract is specified in [services/drivers/serial/README.md](../services/drivers/serial/README.md).

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

## Why four permanent direct paths remain

The kernel panic console (UART) and init-logd's direct-UART path both
bypass the serial driver permanently and by design; the bootloader
framebuffer renderer and the kernel framebuffer renderer both bypass
the framebuffer driver in the same way. A panic, or a userspace failure
before the driver is reachable, must still produce output; none of
these can depend on the IPC machinery that the drivers require. They
share the hardware with the drivers — an accepted physical aliasing,
since the drivers are the steady-state writers and the direct paths
fire only in early boot and failure windows.

## Test-harness output

The in-tree harnesses send their markers and diagnostics to the
framebuffer as well as serial, matching the early-kernel console — by two
different routes:

- **ktest** (`core/ktest/`) is a monolithic init replacement: its bundle
  carries no devmgr and no framebuffer driver, so it renders directly,
  mapping the framebuffer from `InitInfo.framebuffer` and carving the
  pixel span out of the MMIO aperture it holds (`core/ktest/src/framebuffer.rs`).
  This is the harness analogue of the kernel's direct renderer — there is
  no driver in its bundle to route through — so it does not contradict the
  framebuffer driver's sole ownership in a normally-composed boot.
- **svctest / usertest** are std-built services whose output flows through
  the system log stream, so they reach the framebuffer through real-logd's
  driver-mediated mirror (path 5 above) once logd is up. No
  harness-specific framebuffer path exists.

Serial remains the authoritative marker channel: CI scrapes serial and
runs the harnesses headless, where the framebuffer mirrors are no-ops (see
[docs/testing.md](testing.md)).

Every framebuffer renderer — the bootloader, kernel, and ktest direct
renderers and the userspace driver — shares one byte→glyph chain
([shared/text/README.md](../shared/text/README.md)): an incremental UTF-8 decoder feeding the
CP437-reverse → font-extension → ASCII-fallback → `U+FFFD` resolver, so every framebuffer
surface prints the identical glyph set.

---

## Summarized By

[Kernel Cross-Boundary Disclosure Inventory](../core/kernel/docs/cross-boundary-disclosure.md),
[Coding Standards](coding-standards.md),
[services/drivers/framebuffer/README.md](../services/drivers/framebuffer/README.md),
[services/drivers/serial/README.md](../services/drivers/serial/README.md),
[services/logd/README.md](../services/logd/README.md)
