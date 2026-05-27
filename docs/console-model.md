# Console Model

Defines which component owns serial/console byte output across the system
lifecycle, and how userspace serial output is mediated by a single device
driver.

---

## Ownership across the boot lifecycle

Console output passes through a sequence of owners as the system comes up.
Each owner is authoritative for its window; later owners do not retract the
earlier ones, which remain as fallbacks.

1. **Bootloader early console** — `core/boot/src/console.rs` drives the UART
   and framebuffer directly during UEFI boot, before the kernel exists. On
   RISC-V the UART base is discovered via ACPI SPCR
   (`core/boot/src/arch/riscv64/acpi_spcr.rs`); on x86-64 it is COM1 at I/O
   port `0x3F8`.

2. **Kernel early console** — `core/kernel/src/console.rs` (plus
   `core/kernel/src/framebuffer.rs`) owns `kprint!`/`kprintln!` and the panic
   path. It writes the UART directly and **retains** that direct access for the
   life of the system: panics and pre-userspace diagnostics must not depend on
   userspace IPC. The kernel never becomes a client of the userspace serial
   driver.

3. **init-logd direct-UART fallback** — during early userspace boot, before a
   log daemon exists, init drains the master log endpoint and writes lines to
   the UART directly (`services/init/src/logging.rs`). This path is
   **permanent**, not transitional: it is the only writer before the serial
   driver is up, and the fallback if the driver fails to come up.

4. **Serial-driver-mediated path** — once devmgr has spawned the serial driver
   (`services/drivers/serial/`), every userspace UART writer routes bytes to it
   via `serial_labels::SERIAL_WRITE_BYTES`. real-logd
   (`services/logd/src/main.rs`) is the primary client: it resolves the
   driver's write endpoint through devmgr's
   `devmgr_labels::QUERY_SERIAL_DEVICE` and emits both received log lines and
   its own diagnostics through it. No userspace process other than the serial
   driver and init-logd holds UART hardware authority.

## The serial driver as sole userspace UART owner

The serial driver owns the platform UART authority cap end-to-end — an
`IoPortRange` for COM1 on x86-64, an `MmioRegion` for the NS16550 on RISC-V —
delegated by devmgr at spawn. It is a device driver, not a console daemon:
no name registry, no log routing, no VT/ANSI, no read path. Clients obtain a
write capability through devmgr (a device authority), not through svcmgr (a
service registry): a UART is a device, not a service. The driver's IPC
contract is specified in [services/drivers/serial/README.md](../services/drivers/serial/README.md).

## Why two permanent direct paths remain

The kernel panic console and init-logd's direct-UART path both bypass the
driver permanently and by design. A panic, or a userspace failure before the
driver is reachable, must still produce output; neither can depend on the IPC
machinery that the driver requires. They share the UART hardware with the
driver — an accepted physical aliasing, since the driver is the steady-state
writer and the direct paths fire only in early boot and failure windows.

---

## Summarized By

[services/drivers/serial/README.md](../services/drivers/serial/README.md),
[services/logd/README.md](../services/logd/README.md)
