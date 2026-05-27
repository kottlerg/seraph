# serial

Userspace serial (UART) device driver. Owns the platform UART hardware
authority end-to-end and exposes a single byte-write IPC; it is the sole
driver-mediated sink for userspace serial output (real-logd and every other
writer reach the UART through it).

---

## Source Layout

```
serial/
├── Cargo.toml
├── README.md
└── src/
    ├── main.rs                   # Driver entry, bootstrap, write service loop
    └── arch/
        ├── mod.rs                # #[cfg(target_arch)] dispatch
        ├── x86_64/mod.rs         # COM1 IoPortRange (0x3F8): poll LSR, write THR
        └── riscv64/mod.rs        # NS16550 MmioRegion (ACPI SPCR base): poll LSR, write THR
```

---

## Endpoint

Devmgr discovers the platform UART (ACPI SPCR; COM1 at I/O port `0x3F8` on
x86-64, a memory-mapped NS16550 at the SPCR-reported base on RISC-V), spawns
the driver via procmgr, and delegates the per-device arch authority cap — an
`IoPortRange` on x86-64, an `MmioRegion` on RISC-V. The driver owns that cap
end-to-end; no other userspace process except init-logd (the permanent
pre-driver boot fallback) holds UART authority.

Clients obtain a write cap through devmgr, not svcmgr: a UART is a device, not
a service. devmgr answers [`devmgr_labels::QUERY_SERIAL_DEVICE`] by minting a
[`serial_labels::WRITE_AUTHORITY`]-tokened `SEND_GRANT` cap on the driver's
service endpoint, mirroring the `QUERY_BLOCK_DEVICE` flow. The caller's
devmgr-registry token must carry `REGISTRY_QUERY_AUTHORITY`.

The boot-phase ownership of console output (bootloader → kernel early console →
init-logd direct-UART fallback → this driver) is described in
[docs/console-model.md](../../../docs/console-model.md).

---

## Messages

One synchronous operation. Labels are defined in `shared/ipc::serial_labels`;
error codes in `shared/ipc::serial_errors`.

### Label 1: `SERIAL_WRITE_BYTES`

Write a run of bytes to the UART. The label carries the payload byte length in
its high bits, mirroring `stream_labels::STREAM_BYTES`; the bytes are packed
into the data words. The driver writes each byte to the transmit register after
polling the line status register, then replies empty.

**Request:**

| Field | Value |
|---|---|
| label | `1 \| (byte_len << 16)` — opcode in bits 0-15, payload byte length in bits 16-31 (`0..=512`) |
| data[0..] | `byte_len` payload bytes, packed contiguously (`.bytes(0, …)`) |

**Reply:**

| Field | Value |
|---|---|
| label | `0` (`SUCCESS`) or `2` (`UNKNOWN_OPCODE`) |

---

## Planned future surface

Not implemented; named so the intended shape is visible. No wire tables until
implemented.

- `SERIAL_READ_BYTES` — read available input bytes from the UART receive path.
- `SERIAL_SET_LINE_CONTROL` — configure baud rate, parity, and stop bits.
- `SERIAL_SET_FLOW_CONTROL` — configure hardware/software flow control.
- `SERIAL_REGISTER_RX_NOTIFY` — register a signal cap kicked on receive-data-ready.

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/console-model.md](../../../docs/console-model.md) | Console output phase ownership; where this driver sits |
| [services/drivers/docs/driver-model.md](../docs/driver-model.md) | Driver lifecycle and capability delegation |
| [docs/device-management.md](../../../docs/device-management.md) | Driver discovery, spawning, security boundary |
| [docs/ipc-design.md](../../../docs/ipc-design.md) | IPC semantics, endpoints, message format |
| [docs/capability-model.md](../../../docs/capability-model.md) | Capability types, rights, delegation, tokens |

---

## Summarized By

[docs/console-model.md](../../../docs/console-model.md)
