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
   (`core/boot/src/arch/riscv64/acpi_spcr.rs`); on x86-64 it is COM1 at I/O
   port `0x3F8`. The framebuffer base is discovered via UEFI GOP and
   captured into `BootInfo.framebuffer` before `ExitBootServices` — GOP's
   active framebuffer identity is unreachable from any later component, so
   the bootloader is the only entity that can carry the geometry forward.

2. **Kernel early console** — `core/kernel/src/console.rs` (plus
   `core/kernel/src/framebuffer.rs`) owns `kprint!`/`kprintln!` and the panic
   path. It writes the UART directly and **retains** that direct access for the
   life of the system: panics and pre-userspace diagnostics must not depend on
   userspace IPC. The kernel framebuffer renderer is similarly **retained**
   as the panic console. The kernel never becomes a client of the userspace
   serial or framebuffer driver.

3. **init-logd direct-UART fallback** — during early userspace boot, the
   init-logd thread (a second thread of the init process,
   `services/init/src/logging.rs`) drains the master log endpoint and writes
   lines to the UART directly. It owns console output from the moment init
   spawns it through the entire init → svcmgr handover and svcmgr's reconcile,
   until the svcmgr-launched real-logd assumes the endpoint's RECV, pulls
   init-logd's captured history via `log_labels::HANDOVER_PULL`, then releases
   it with `log_labels::HANDOVER_RELEASE` — at which point init-logd
   self-terminates. This direct path is **permanent**, not
   transitional: it is the only writer before the serial driver is up, and the
   fallback if the driver fails to come up. There is no parallel init-logd
   direct-framebuffer path today; pre-driver framebuffer writes are deferred
   to a future surface (see "Planned future surface" in the framebuffer driver
   README).

4. **Serial-driver-mediated path** — once devmgr has spawned the serial driver
   (`services/drivers/serial/`), every userspace UART writer routes bytes to it
   via `serial_labels::SERIAL_WRITE_BYTES`. real-logd
   (`services/logd/src/main.rs`) is the primary client: svcmgr launches and
   supervises it, it resolves the driver's write endpoint through devmgr's
   `devmgr_labels::QUERY_SERIAL_DEVICE`, and it emits both received log lines
   and its own diagnostics through it. No userspace process other than the
   serial driver and init-logd holds UART hardware authority.

   real-logd is restartable (`restart = on_failure`). svcmgr holds the
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
   v1 has one consumer: `programs/fb-charset`, a small demo program
   (a step above "hello world") launched once per default boot by
   svcmgr via `/config/svcmgr/services/fb-charset.svc` (`seed =
   devmgr.registry`). It resolves the framebuffer write cap via
   `devmgr_labels::QUERY_FRAMEBUFFER_DEVICE` and emits a structured
   UTF-8 sequence covering every glyph class (ASCII, CP437 high half,
   box-drawing, font-extension, ASCII fallback, and one ill-formed
   sequence so the U+FFFD glyph is reachable on screen), then exits.
   Production consumers (terminal, shell, compositor) arrive in
   follow-up issues and resolve the cap through the same name. v1
   exposes one verb only — `FB_WRITE_BYTES` — interpreting payloads as
   UTF-8 with `\n`/`\r` short-circuited; graphical primitives are
   listed under the driver README's "Planned future surface".

## The serial driver as sole userspace UART owner

The serial driver owns the platform UART authority cap end-to-end — an
`IoPort` for COM1 on x86-64, an `Mmio` for the NS16550 on RISC-V —
delegated by devmgr at spawn. It is a device driver, not a console daemon:
no name registry, no log routing, no VT/ANSI, no read path. Clients obtain a
write capability through devmgr (a device authority), not through svcmgr (a
service registry): a UART is a device, not a service. The driver's IPC
contract is specified in [services/drivers/serial/README.md](../services/drivers/serial/README.md).

## The framebuffer driver as sole userspace framebuffer owner

The framebuffer driver owns the bootloader-discovered GOP linear
framebuffer end-to-end — an `Mmio` carved from a bootloader-
synthesised aperture that covers
`[physical_base, physical_base + stride * height)` (page-aligned),
delegated by devmgr at spawn. The driver maps the entire region into its
own address space, queries devmgr for its geometry via the generic
`QUERY_DEVICE_INFO` path (kind `FRAMEBUFFER`), and serves
`FB_WRITE_BYTES`. Like the serial driver it is a device driver, not a
console daemon: no name registry, no log routing, no graphical
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

---

## Summarized By

[README.md](../README.md),
[services/drivers/README.md](../services/drivers/README.md),
[services/drivers/serial/README.md](../services/drivers/serial/README.md),
[services/drivers/framebuffer/README.md](../services/drivers/framebuffer/README.md),
[services/logd/README.md](../services/logd/README.md)
