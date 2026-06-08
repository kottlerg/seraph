# serial

Userspace serial (UART) device driver. Owns the platform UART hardware
authority end-to-end and exposes byte write, byte read, and RX-notify
registration; it is the sole driver-mediated path for userspace serial bytes in
both directions (real-logd and every other writer reach the UART through it;
the terminal reads typed input through it).

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
        └── riscv64/mod.rs        # NS16550 Mmio (ACPI SPCR base): enable IER, poll LSR, write THR / read RBR
```

---

## Endpoint

Devmgr discovers the platform UART (ACPI SPCR; COM1 at I/O port `0x3F8` on
x86-64, a memory-mapped NS16550 at the SPCR-reported base on RISC-V), spawns
the driver via procmgr, and delegates the per-device arch authority cap — an
`IoPort` on x86-64, an `Mmio` on RISC-V — plus the UART interrupt cap (COM1 is
ISA IRQ 4; the QEMU `virt` NS16550 is PLIC source 10). The driver owns those
caps end-to-end; no other userspace process except init-logd (the permanent
pre-driver boot fallback) holds UART authority. The interrupt cap is optional:
without it the driver still answers reads (RX then relies on the client's
bounded poll) but `SERIAL_REGISTER_RX_NOTIFY` reports `REGISTER_FAILED`.

Clients obtain a read/write cap through devmgr, not svcmgr: a UART is a device,
not a service. devmgr answers [`devmgr_labels::QUERY_SERIAL_DEVICE`] by minting
a `SEND_GRANT` cap on the driver's service endpoint badged with
[`serial_labels::WRITE_AUTHORITY`] | [`serial_labels::READ_AUTHORITY`],
mirroring the `QUERY_BLOCK_DEVICE` flow. The caller's devmgr-registry badge
must carry `REGISTRY_QUERY_AUTHORITY`.

The boot-phase ownership of console output (bootloader → kernel early console →
init-logd direct-UART fallback → this driver) is described in
[docs/console-model.md](../../../docs/console-model.md).

---

## Messages

Three synchronous operations. Labels are defined in `shared/ipc::serial_labels`;
error codes in `shared/ipc::serial_errors`. The service loop never blocks —
reads drain whatever is buffered and return at once — so a pending read never
starves writers sharing the endpoint (logd, the terminal's output).

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
| label | `0` (`SUCCESS`) or `2` (`UNKNOWN_OPCODE`) |

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
| label | `0 \| (n << 16)` — `SUCCESS` in bits 0-15, byte count `n` in bits 16-31 (`0..=512`) |
| data[0..] | `n` received bytes, packed contiguously (`.bytes(0, …)`) |

### Label 3: `SERIAL_REGISTER_RX_NOTIFY`

Register a notification the driver kicks when receive data becomes ready. The
driver binds the UART interrupt to the supplied notification and arms it; the
client then loops (drain with `SERIAL_READ_BYTES`, wait on its notification
with a bounded timeout). Gated by `READ_AUTHORITY`.

**Request:**

| Field | Value |
|---|---|
| label | `3` — `SERIAL_REGISTER_RX_NOTIFY` |
| caps[0] | the client's notification cap (needs the `NOTIFY` right) |

**Reply:**

| Field | Value |
|---|---|
| label | `0` (`SUCCESS`) or `4` (`REGISTER_FAILED` — no IRQ cap held, or no notification supplied) |

---

## Interrupts

RX is interrupt-driven. `serial_init` enables the receive-data interrupt in the
UART's IER (every earlier boot stage left `IER = 0`), and the driver routes the
UART interrupt to a client notification via `SERIAL_REGISTER_RX_NOTIFY`. The
kernel masks the line on each fire; the next `SERIAL_READ_BYTES` re-arms it
after draining. Because the x86 IOAPIC delivers edge-triggered, a client must
wait with a bounded timeout (the terminal uses 20 ms) so a byte racing the
re-arm is recovered on the next drain; this also degrades gracefully to polling
when no IRQ cap was delivered. The riscv PLIC is level-sensitive and re-asserts
on its own, but clients use the same bounded wait for uniformity.

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

[docs/console-model.md](../../../docs/console-model.md)
