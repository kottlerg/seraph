# serial

Userspace serial (UART) device driver. Owns the platform UART hardware
authority end-to-end and exposes byte write, byte read, and RX-notify
registration; it is the sole driver-mediated path for userspace serial bytes in
both directions (real-logd and every other writer reach the UART through it;
the terminal reads typed input through it), per
[console-model.md](../../../docs/console-model.md#the-serial-driver-as-sole-userspace-uart-owner).

---

## Source Layout

```
serial/
├── Cargo.toml
├── README.md
└── src/
    ├── main.rs                   # Driver entry, bootstrap, write/read/notify service loop
    └── arch/
        ├── mod.rs                # #[cfg(target_arch)] dispatch
        ├── x86_64/mod.rs         # COM1 IoPort (0x3F8): enable IER, poll LSR, write THR / read RBR
        └── riscv64/mod.rs        # NS16550 Mmio (QEMU virt 0x1000_0000):
                                  # enable IER, poll LSR, write THR / read RBR
```

---

## Endpoint

[Devmgr](../../devmgr/docs/responsibilities.md#responsibilities) binds the driver to the
platform device record of the console UART (the ACPI namespace's `PNP0501` device or the SPCR's
console UART, merged into one record; COM1 at I/O port `0x3F8` on x86-64, the QEMU `virt`
NS16550 at `0x1000_0000` on RISC-V). The driver carries a declaration in the ELF note section
`.note.seraph.driver` (SPCR interface types `0x00` and `0x12` and ACPI `PNP0501`) and is a boot
module, bound in the boot pass. devmgr spawns it via procmgr and delegates the record's
resources — an `IoPort` on x86-64, an `Mmio` on RISC-V — plus the UART interrupt cap, carved
exclusive (COM1 is ISA IRQ 4; the QEMU `virt` NS16550 is APLIC source 10). The driver owns those
caps end-to-end. Outside the driver, UART authority
is held only by init (used by its init-logd thread, the direct-UART path until the real-logd
handover) and by devmgr (the `IoPort` / `Mmio` caps it carves the driver's cap
from), per [console-model.md](../../../docs/console-model.md#ownership-across-the-boot-lifecycle).
The interrupt cap is optional: without it the driver still answers reads (RX then relies on
the client's bounded poll) but `SERIAL_REGISTER_RX_NOTIFY` reports `REGISTER_FAILED`.

Before its bootstrap the driver declares itself undebuggable to procmgr
(`procmgr_labels::DECLARE_NO_DEBUG`): logd writes every log line through it, so a debug-authority
holder that stopped it would wait on its own log output
([crashd Operation](../../crashd/docs/operation.md) § Limits).

The bootstrap is the resource list (`driver_binding::resources`), decoded with
`PlatformDelivery`: the register resource, the wired line when present, and in the end round the
service endpoint and the driver's devmgr query cap.
Once the UART is set up the driver reports `devmgr_labels::DRIVER_READY` on that cap,
immediately before its service loop, and exits when devmgr refuses it: devmgr serves the
driver's endpoint only after the report, and withdraws it when the driver dies.

Clients obtain a read/write cap through devmgr, not svcmgr: a UART is a device,
not a service
([console-model.md](../../../docs/console-model.md#the-serial-driver-as-sole-userspace-uart-owner)).
devmgr answers `devmgr_labels::QUERY_DEVICE` by minting
a `SEND_GRANT` cap on the driver's service endpoint badged with
`serial_labels::WRITE_AUTHORITY` | `serial_labels::READ_AUTHORITY`. The caller sends it on the
`serial` class SEND, whose badge carries those verbs.

The boot-phase ownership of console output (bootloader → kernel early console →
init-logd direct-UART fallback → this driver) is described in
[docs/console-model.md](../../../docs/console-model.md).

---

## Messages

Three synchronous operations. Labels are defined in `shared/ipc::serial_labels`;
error codes in `shared/ipc::serial_errors`. This driver's service loop never blocks — reads
drain whatever is buffered and return at once — so a pending read never starves writers sharing
the endpoint (logd, the terminal's output). The debug port's
[virtio-console driver](../virtio/console/README.md) serves the same three operations with the
same wire shapes; its README states where its behaviour differs (a write waits for the device,
and a registration takes any notification cap, since its interrupt-service thread signals it
where this driver binds it through `SYS_IRQ_REGISTER`).
The driver deletes every cap a request carries that it does not keep, before it replies; it keeps
only the notification of an accepted `SERIAL_REGISTER_RX_NOTIFY`.

### Label 1: `SERIAL_WRITE_BYTES`

Write a run of bytes to the UART. The label carries the payload byte length in
its high bits, mirroring `stream_labels::STREAM_BYTES`; the bytes are packed
into the data words. The driver writes each byte to the transmit register after
polling the line status register, then replies empty. Gated by
`WRITE_AUTHORITY`.

**Request:**

| Field | Value |
|---|---|
| label | `1 \| (byte_len << 16)` — opcode in bits 0-15, payload byte length in bits 16-31 (`0..=512`) |
| data[0..] | `byte_len` payload bytes, packed contiguously (`.bytes(0, …)`) |

**Reply:**

| Field | Value |
|---|---|
| label | `0` (`SUCCESS`), `5` (`UNAUTHORIZED` — badge lacks `WRITE_AUTHORITY`), or `2` (`UNKNOWN_OPCODE`) |

### Label 2: `SERIAL_READ_BYTES`

Drain the bytes currently in the receive FIFO. Non-blocking: the driver reads
the receive register while the line-status data-ready bit is set (up to 512
bytes), re-arms the receive interrupt, and replies at once — a zero-byte reply
is normal. The reply mirrors the write wire shape in reverse: the byte count
rides the label's high bits, the bytes are packed in the data words. Gated by
`READ_AUTHORITY`.

**Request:**

| Field | Value |
|---|---|
| label | `2` — `SERIAL_READ_BYTES` |

**Reply:**

| Field | Value |
|---|---|
| label | `0 \| (n << 16)` — `SUCCESS` in bits 0-15, byte count `n` in bits 16-31 (`0..=512`); or `5` (`UNAUTHORIZED` — badge lacks `READ_AUTHORITY`) |
| data[0..] | `n` received bytes, packed contiguously (`.bytes(0, …)`) |

### Label 3: `SERIAL_REGISTER_RX_NOTIFY`

Register a notification the driver kicks when receive data becomes ready. The
driver binds the UART interrupt to the supplied notification and arms it; the
client then loops (drain with `SERIAL_READ_BYTES`, wait on its notification
with a bounded timeout). An accepted registration replaces the one before it, whose notification
the driver deletes; a refused one deletes the supplied notification and leaves the earlier
binding in place. Gated by `READ_AUTHORITY`.

**Request:**

| Field | Value |
|---|---|
| label | `3` — `SERIAL_REGISTER_RX_NOTIFY` |
| caps[0] | the client's notification cap (needs the `NOTIFY` right) |

**Reply:**

| Field | Value |
|---|---|
| label | `0` (`SUCCESS`), `4` (`REGISTER_FAILED` — no IRQ cap held, no notification supplied, or a cap `SYS_IRQ_REGISTER` rejects), or `5` (`UNAUTHORIZED` — badge lacks `READ_AUTHORITY`) |

---

## Interrupts

RX is interrupt-driven. When the driver holds the UART's IRQ cap,
`serial_enable_rx_interrupt` enables the receive-data interrupt in the UART's IER
(every earlier boot stage left `IER = 0`), and the driver routes the
UART interrupt to a client notification via `SERIAL_REGISTER_RX_NOTIFY`. The
kernel masks the line on each fire; the next `SERIAL_READ_BYTES` re-arms it
after draining, via
[`SYS_IRQ_ACK`](../../../core/kernel/docs/syscalls.md#sys_irq_ack-29). The
driver registers the line with the mode devmgr gives the SPCR record. On x86-64
that is mode 0, edge-triggered and active-high (COM1 is ISA IRQ 4, which no
MADT override reroutes). Because the x86 IOAPIC then delivers edge-triggered, a
client must wait with a bounded timeout (the terminal uses 20 ms) so a byte
racing the re-arm is recovered on the next drain; this also degrades gracefully
to polling when no IRQ cap was delivered. On riscv64 the SPCR names an APLIC
source, which devmgr gives level-triggered and active-high: the kernel programs
the source Level1 and pends it again at the re-arm while the UART still
asserts it, so a byte racing the re-arm is delivered, and the bounded wait
remains the fallback for a boot without an IRQ cap.

---

## Planned future surface

Not implemented; named so the intended shape is visible. No wire tables until
implemented.

- `SERIAL_SET_LINE_CONTROL` — configure baud rate, parity, and stop bits.
- `SERIAL_SET_FLOW_CONTROL` — configure hardware/software flow control.

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/console-model.md](../../../docs/console-model.md) | Console output phase ownership; where this driver sits |
| [services/drivers/docs/driver-model.md](../docs/driver-model.md) | Driver lifecycle and capability delegation |
| [docs/device-management.md](../../../docs/device-management.md) | Driver discovery, spawning, security boundary |
| [docs/ipc-design.md](../../../docs/ipc-design.md) | IPC semantics, endpoints, message format |
| [docs/capability-model.md](../../../docs/capability-model.md) | Capability types, rights, delegation, badges |

---

## Summarized By

[Console Model](../../../docs/console-model.md),
[Device Management](../../../docs/device-management.md),
[programs/terminal/README.md](../../../programs/terminal/README.md),
[devmgr Responsibilities and Capabilities](../../devmgr/docs/responsibilities.md),
[Driver Model](../docs/driver-model.md),
[services/drivers/virtio/console/README.md](../virtio/console/README.md)
