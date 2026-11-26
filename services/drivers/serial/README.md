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
    ├── main.rs                   # Driver entry, bootstrap, the transmitter, the service
    │                             # threads, and the polled loop
    ├── lib.rs                    # Host-tested library: the modules below
    ├── ring.rs                   # Single-producer, single-consumer byte ring: TX_RING_BYTES,
    │                             # RX_RING_BYTES
    ├── uart.rs                   # 16550 register offsets and bits, IIR decoding, the IER value
    ├── wait.rs                   # TX_STALL_MS and the stall watch of a write's wait
    └── arch/
        ├── mod.rs                # #[cfg(target_arch)] dispatch
        ├── x86_64/mod.rs         # COM1 IoPort (0x3F8): bind the range, read and write a register
        └── riscv64/mod.rs        # NS16550 Mmio (QEMU virt 0x1000_0000): map the window,
                                  # read and write a register
```

---

## Endpoint

[Devmgr](../../devmgr/docs/responsibilities.md#responsibilities) binds the driver to the
platform device record of the console UART (the ACPI namespace's `PNP0501` device or the SPCR's
console UART, merged into one record; COM1 at I/O port `0x3F8` on x86-64, the QEMU `virt`
NS16550 at `0x1000_0000` on RISC-V). The driver carries a declaration in the ELF note section
`.note.seraph.driver` (SPCR interface types `0x00` and `0x12` and ACPI `PNP0501`) and is a
drivers-directory driver, bound in the drivers-directory pass at the auxiliary tier. devmgr spawns
it via procmgr and delegates the record's
resources — an `IoPort` on x86-64, an `Mmio` on RISC-V — plus the UART interrupt cap, carved
exclusive (COM1 is ISA IRQ 4; the QEMU `virt` NS16550 is APLIC source 10). The driver owns those
caps end-to-end. Outside the driver, UART authority
is held only by init (used by its init-logd thread, the direct-UART path until the real-logd
handover) and by devmgr (the `IoPort` / `Mmio` caps it carves the driver's cap
from), per [console-model.md](../../../docs/console-model.md#ownership-across-the-boot-lifecycle).
The interrupt cap is optional: without it the driver is polled (§ Transmit and receive), still
answers reads and writes, and reports `REGISTER_FAILED` to `SERIAL_REGISTER_RX_NOTIFY`, so the
client's bounded wait polls.

The driver is debuggable, and a fault of it reaches the crash service like any driver's. logd
writes every log line to it with `SERIAL_WRITE_SENT` from its serial sink's writer thread, the
only logd thread that waits on the driver; a debug-authority holder that stops it holds the log
stream for at most logd's
`SINK_STALL_MS` once, after which logd queues and then drops and counts the lines meant for
serial until the driver writes again, and keeps writing them to the framebuffer and retaining
them in its history. Should logd fail to spawn that writer, each line's producer writes it, and a
stopped driver then costs every line up to that bound
([logd IPC Interface](../../logd/docs/ipc-interface.md#output-sinks) § Output sinks). A stopped
transmitter alone, the driver's main thread, holds no read and no write its transmit ring has room
for, and answers a write that waits on it `STALLED` after `TX_STALL_MS` (§ Transmit and
receive).
devmgr creates it with its install path `/services/drivers/serial` as its
`argv[0]`, under which procmgr's
`LIST_PROCESSES` names it to a debugger.

The bootstrap is the resource list (`driver_binding::resources`), decoded with
`PlatformDelivery`: the register resource, the wired line when present, and in the end round the
service endpoint and the driver's devmgr query cap.
Once the UART is set up, and with the line the service threads started, the driver reports
`devmgr_labels::DRIVER_READY` on that cap, immediately before it serves the UART, and exits when
devmgr refuses it: devmgr serves the
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
error codes in `shared/ipc::serial_errors`. A read never waits, and a write waits only for room
in the transmit ring or, when it asks, for its bytes to leave the UART, so a client of the
endpoint (logd, the terminal's output) is not held by another's write: with the line, several
service threads serve the endpoint, and a read is answered while a write waits (§ Transmit and
receive). The debug port's
[virtio-console driver](../virtio/console/README.md) serves the same three operations with the
same wire shapes; its README states where its behaviour differs (a write waits for the device,
and a registration takes any notification cap, where this driver refuses a cap that is not a
notification with the `NOTIFY` right).
The driver deletes every cap a request carries that it does not keep, before it replies; it keeps
only the notification of an accepted `SERIAL_REGISTER_RX_NOTIFY`.

### Label 1: `SERIAL_WRITE_BYTES`

Write a run of bytes to the UART. The label carries the payload byte length in bits 16-31,
mirroring `stream_labels::STREAM_BYTES`, and the flag `SERIAL_WRITE_SENT` in bit 32; the bytes
are packed into the data words. Gated by `WRITE_AUTHORITY`.

- **Plain.** With the line, the driver appends the bytes to its transmit ring, whole and after
  the bytes of every write answered before, and replies; the transmitter drains the ring into the
  UART (§ Transmit and receive). A write that finds too little room in the ring waits for room.
  Without the line, the driver writes each byte to the transmit holding register itself, once
  the line status register reports it empty, and replies once the last is in it.
- **`SERIAL_WRITE_SENT`.** The reply waits until the write's bytes, and every byte written
  before them, have left the UART: the line status register reports the transmitter empty
  (`TEMT`), its FIFO and its shift register both. A zero-length write with the flag is a barrier
  for every write before it.
- **Stall.** Either wait ends with `STALLED` once the transmitter has taken no byte for
  `TX_STALL_MS` (1000 ms, [docs/limits.md](../../../docs/limits.md) § Drivers): a UART that takes
  none, or a transmitter thread a debugger stopped. A write refused while it waited for room
  appended nothing; one refused while it waited for `TEMT` is in the ring and leaves when the
  transmitter moves again; a polled write stops at the byte the UART did not take.

**Request:**

| Field | Value |
|---|---|
| label | `1 \| (byte_len << 16) \| sent` — opcode in bits 0-15, payload byte length in bits 16-31 (`0..=512`), `sent` either `0` or `SERIAL_WRITE_SENT` (`1 << 32`) |
| data[0..] | `byte_len` payload bytes, packed contiguously (`.bytes(0, …)`) |

**Reply:**

| Field | Value |
|---|---|
| label | `0` (`SUCCESS`), `6` (`STALLED` — the transmitter took no byte for `TX_STALL_MS`), `5` (`UNAUTHORIZED` — badge lacks `WRITE_AUTHORITY`), or `2` (`UNKNOWN_OPCODE`) |

### Label 2: `SERIAL_READ_BYTES`

Take the bytes received and not yet read, up to 512. Non-blocking: with the line, the driver
takes them from its receive ring, which the transmitter fills from the UART on the receive
interrupt; without, it reads the receive register while the line-status data-ready bit is set.
It replies at once, and a zero-byte reply is normal. The reply mirrors the write wire shape in
reverse: the byte count rides the label's high bits, the bytes are packed in the data words.
Gated by `READ_AUTHORITY`.

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

Register a notification the driver signals when received bytes arrive: the transmitter signals
it each time it moves bytes from the UART into the receive ring. The
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
| label | `0` (`SUCCESS`), `4` (`REGISTER_FAILED` — the driver is polled, no cap supplied, or a cap that is not a notification with the `NOTIFY` right), or `5` (`UNAUTHORIZED` — badge lacks `READ_AUTHORITY`) |

---

## Interrupts

The driver registers the UART's line to its transmitter's notification, with the mode devmgr
gives the SPCR record. The kernel masks the line on each fire; the transmitter services the UART
and then acknowledges the line
([`SYS_IRQ_ACK`](../../../core/kernel/docs/syscalls.md#sys_irq_ack-29)), whether or not a
client has a request in flight, and reads the UART again before it sleeps. On x86-64 the mode is
0, edge-triggered and active-high (COM1 is ISA IRQ 4, which no MADT override reroutes): a cause
the UART raises while the line is masked brings no new edge, and the read after the
acknowledgement finds it. On riscv64 the SPCR names an APLIC source, which devmgr gives
level-triggered and active-high: the kernel programs the source Level1 and pends it again at the
acknowledgement while the UART still asserts it.

A client of `SERIAL_REGISTER_RX_NOTIFY` waits on its notification with a bounded timeout (the
terminal uses 20 ms), which is also how it polls a driver without the line.

---

## Transmit and receive

### Threads

With the line, the driver's main thread is the transmitter, the only thread that touches the UART
(on x86-64 its I/O port range is bound to that thread), and `SERVICE_THREADS` (3) service
threads serve the endpoint. They share two rings
([`src/ring.rs`](src/ring.rs)), each with one producer and one consumer that meet only in
atomics: the transmit ring (`TX_RING_BYTES`, 4 KiB), which the service threads append to and the
transmitter drains, and the receive ring (`RX_RING_BYTES`, 1 KiB), which the transmitter fills
and the service threads take from. The service threads take turns at their side of each ring
under a lock of its own, which the transmitter never takes, so a transmitter a debugger stopped
holds no read, and no write but one that waits on it and the writes behind that write's lock.

### Transmit

A write appends its bytes whole, so two writes' bytes never interleave, and kicks the
transmitter. Each time the line status register reports the transmit holding register empty
(`THRE`), the transmitter loads the UART from the ring: `FIFO_LOAD` (16) bytes when the
interrupt identification register reports the FIFOs enabled, one byte otherwise. It enables the
transmit interrupt only while it has bytes to load or a `SERIAL_WRITE_SENT` write waits, so an
idle UART raises none. While it has such work it also wakes every `TX_WATCHDOG_MS` (10 ms)
without an interrupt and looks at the line status register, so a transmit interrupt the UART did
not raise, or that was lost, delays the output by that bound at most.

A `SERIAL_WRITE_SENT` write marks the ring position of its last byte and waits until the
transmitter has seen every byte up to the mark leave the UART. Once it has loaded every byte up
to the mark, the transmitter loads nothing more until the UART is empty, whatever other writes
have appended behind the mark (`ring::hold_for_drain`): when the transmit holding register is
empty it spins on the line status register for up to `DRAIN_SPIN` (2 ms) until it reports the
transmitter empty (`TEMT`), with only the shift register's last character left, 87 µs at 115200
baud. It then settles the write and loads again. A UART not empty by then is looked at again at
the next watchdog wake. So a waiting write waits for the bytes ahead of its mark and one FIFO load
past it, and each such write pauses the output for about one character time.

### Receive

On the received-data and receive-timeout interrupts the transmitter moves the bytes the UART holds
into the receive ring and signals the registered RX notification. When the ring is full it turns
the receive interrupt off: the UART's FIFO keeps the next bytes, and overruns only once the client
stops reading. A read that takes bytes kicks the transmitter, which turns the interrupt on again.

### Waits and stalls

A write waits on the transmitter in two places: for room in the transmit ring, and for `TEMT` when
it carries `SERIAL_WRITE_SENT`. Each wait ends `STALLED` once the transmitter has made no
progress for `TX_STALL_MS` (1000 ms): it loaded no byte and saw none leave
([`src/wait.rs`](src/wait.rs)). A transmitter that moves slowly holds the writer as long as it
keeps moving. A read waits on nothing.

### The UART

The driver assumes a 16550-compatible UART that an earlier boot stage programmed (baud rate, line
control, FIFO control) and leaves those registers as they are. It writes only the transmit holding
register and the interrupt enable register (every earlier stage left it 0), and never the FIFO
control register, whose write clears the FIFOs and with them an earlier stage's last bytes. A
pass over the UART reads the interrupt identification register up to `IIR_READS` (32) times,
clearing each cause it names: a line-status cause by reading the line status register, a
modem-status cause by reading the modem status register, a transmit cause by the read that named
it. An identification no 16550 defines ends the pass's reads, and the pass then looks at the line
status register whatever the identification register said.

### Polled

Without the line, or when the interrupt-driven set-up fails before a service thread runs (a
notification, a thread, or the line's registration), the main thread alone serves the endpoint
and drives the UART itself: a write polls the line status register for each byte, and a read
drains the UART's receive FIFO. A read then waits behind a write in flight, since one thread
serves both, and an RX-notify registration is refused.

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
