# terminal

Userspace terminal: relays a byte stream between hardware drivers and the
standard streams of an operator session's leader, with a minimal line
discipline. This is the durable terminal
abstraction; v0.0.1 (#111) ships an intentionally tiny feature surface that
grows in later releases.

The terminal owns its driver endpoint caps directly because no input/display
broker exists yet. When a broker/compositor lands (a separate v0.2.0+ design
issue), the terminal becomes a subscriber and the stdio contract to the leader
does not change.

---

## Source Layout

```
terminal/
├── Cargo.toml
├── README.md
└── src/
    ├── main.rs            # Device resolution, the session loop, line discipline
    ├── session.rs         # sessiond client: registration, open, stream handover
    ├── input.rs           # Keyboard and serial RX producer threads
    └── output.rs          # Output sink: framebuffer (SGR-parsed) and serial mirror
```

---

## Scope

- **Input**: two sources feeding one channel — the virtio-input keyboard
  ([#110], key-down events decoded to a byte stream, key-up and modifier-key
  events dropped) and serial RX ([#291], received UART bytes forwarded
  verbatim). The keyboard is required: the terminal waits, without a bound, on a `WATCH_CLASS`
  watch on the `input` class until devmgr serves the class's first live driver, so a boot with no
  input device has no terminal.
  `cargo xtask run` attaches a virtio keyboard on every boot (see
  [xtask/README.md](../../xtask/README.md#attached-devices)), so a headless run still has a
  terminal, interactive over serial.
- **Output**: framebuffer text ([#67], primary) mirrored to serial TX ([#66],
  debug). Both share one wire format, specified in the
  [serial](../../services/drivers/serial/README.md) and
  [framebuffer](../../services/drivers/framebuffer/README.md) driver READMEs
  (`*_WRITE_BYTES`, length in the label's high bits, payload chunked at 512
  bytes). The two paths diverge on ANSI: the framebuffer path parses SGR
  (`ESC[…m`) through [shared/ansi](../../shared/ansi/README.md) into
  `FB_SET_ATTRS` colour changes, so the driver never sees `ESC`, while the
  serial mirror receives the raw bytes. The framebuffer is optional: a headless
  boot has none, and the terminal then mirrors to serial only, until devmgr
  serves one.
- **Driver restart**: devmgr restarts a served driver that dies and serves the
  new instance at the class's next ordinal
  ([Driver Restart](../../services/devmgr/docs/responsibilities.md#driver-restart)).
  Each class the terminal uses (input, framebuffer, serial) is followed by a
  [`device_tracker::Device`](../../shared/device-tracker/README.md), whose
  crate states the contract: the class's watch registered before the first
  resolve, a tracker thread that looks at the class again on each signal, and
  a generation per driver it resolves. A thread whose call on a
  driver fails waits up to a second for a newer one, then calls again; the
  serial receive thread registers its notification with each new instance, and
  the sink starts its SGR parser again with a new framebuffer instance, which
  starts at the driver's default attributes. The terminal logs each driver it
  holds (`<class> driver at ordinal <n>`, under its `[terminal]` tag) and the first write that
  reaches a framebuffer instance after the first.
- **Line discipline**:
  - local echo of each typed character to the output,
  - single-line backspace (`BS` erases the last byte of the current line and
    emits `BS SP BS` to the display),
  - CR→LF translation (Enter sends `\n` to the leader).
- **Session**: the terminal is an interface of
  [sessiond](../../services/sessiond/README.md)
  ([docs/session-supervision.md](../../docs/session-supervision.md)). It
  registers an end queue on itself with procmgr once, and registers with
  sessiond under a random nonce, handing it the queue's receive right, so
  sessiond ends the terminal's sessions whatever ends the terminal. For each
  session it makes the leader's three pipes and death relay with
  `std::os::seraph::process::SessionStdio`, opens the session through its
  `sessiond.operator` seed, hands over the pipes, and starts it
  ([sessiond IPC Interface](../../services/sessiond/docs/ipc-interface.md)).
  sessiond creates the leader, the shell its own recipe names, so the terminal
  holds no process handle and no namespace. When the relay gives the leader's
  end, the terminal opens a new session. It registers again when a new
  sessiond instance answers `UNKNOWN_INTERFACE`, waits for the pressure level
  to change while sessiond answers `MEMORY_CRITICAL`, and asks again after a
  second on any other refusal.
- **Supervision**: a non-bootstrap svcmgr service
  (`/config/svcmgr/services/terminal.svc`), `critical = no`,
  `restart = on_failure`, `namespace = none`, seeded with the input,
  framebuffer and serial class SENDs and `sessiond.operator`. It autostarts on
  a normal `cargo xtask run`. It is never bundled into the ESP and init never
  loads it.

## Architecture

One producer thread per input source feeds an `mpsc` channel: the keyboard
thread blocks on the keysym stream and decodes key-downs to bytes; the serial
thread wakes on the UART receive interrupt (`SERIAL_REGISTER_RX_NOTIFY`, with a
bounded-timeout fallback) and forwards received bytes. Per-session relay threads
forward the leader's stdout/stderr down the same channel, and a watcher thread
posts the leader's end, read from the session's relay. The single consumer
thread owns the output sink and the leader's stdin, applies the line discipline,
and opens a new session when the leader ends. Sole ownership of the sink by one thread is why
no locking is needed; each thread issues driver IPC on its own per-thread IPC
buffer (`std::os::seraph::current_ipc_buf`).

Decoding to bytes lives in each input source, so the consumer is
source-agnostic: keyboard and serial bytes flow through one line discipline,
and a further source would be just another producer.

## Deferred

- **Signals** (`^C`→SIGINT, `^D`→EOF, `^Z`→SIGTSTP), **cooked/raw mode
  toggle**, **job control**, **multi-session / multi-terminal**, **pty
  equivalents**, **cross-process line buffering** — line-discipline maturity,
  tracked under [#29].
- **Any input/display broker layer** — separate future design issue.

## Known limitations

- Framebuffer and serial are shared, unbrokered sinks: terminal output
  interleaves with logd on both (serial, and logd's framebuffer mirror).
  Cosmetic until a broker exists.
- Non-printable named keys (arrows, Home/End/Delete, Tab, Escape) are ignored.
- Backspace is byte-wise: it erases one byte of the current line, so
  backspacing a multi-byte UTF-8 character is incorrect. Grapheme-aware editing
  is part of line-discipline maturity ([#29]).

## Testing

Driven host-side by `cargo xtask test-terminal`, which boots with a QMP control
socket and the GDB stub staged on the virtio-input driver, waits for the
`terminal: READY for injection` marker, then exercises both input sources and a
restart of the input driver in one boot: a keyboard round (key sequence
injected through the real virtio-input driver over QMP), a serial round (the same
sequence written to the guest UART via QEMU's bidirectional `-serial stdio`), and
an input restart round (the host kills the virtio-input driver through the stub,
the terminal must hold devmgr's restarted instance at ordinal 1, and the key
sequence is injected again). Each round asserts the echoed input and the relayed
leader output appear on the serial stream. It runs as a boot in the `usertest` cell. See
[xtask/README.md](../../xtask/README.md#cargo-xtask-test-terminal) for the command and
[docs/testing.md](../../docs/testing.md#interactive-input-test-terminal) for the test.

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/console-model.md](../../docs/console-model.md) | Console output ownership; the terminal as the production console path |
| [docs/session-supervision.md](../../docs/session-supervision.md) | Sessions, sessiond, the terminal as an interface |
| [services/sessiond/docs/ipc-interface.md](../../services/sessiond/docs/ipc-interface.md) | The labels the terminal opens its sessions with |
| [docs/testing.md](../../docs/testing.md) | The `test-terminal` interactive input test |
| [xtask/README.md](../../xtask/README.md) | `cargo xtask test-terminal` and the devices `run` attaches |
| [serial driver](../../services/drivers/serial/README.md) | `SERIAL_WRITE_BYTES`, `SERIAL_READ_BYTES`, `SERIAL_REGISTER_RX_NOTIFY` |
| [framebuffer driver](../../services/drivers/framebuffer/README.md) | `FB_WRITE_BYTES` and `FB_SET_ATTRS` |
| [shared/ansi/README.md](../../shared/ansi/README.md) | SGR parser for the framebuffer path |

[#29]: https://github.com/kottlerg/seraph/issues/29
[#66]: https://github.com/kottlerg/seraph/issues/66
[#67]: https://github.com/kottlerg/seraph/issues/67
[#110]: https://github.com/kottlerg/seraph/issues/110
[#291]: https://github.com/kottlerg/seraph/issues/291

---

## Summarized By

[Console Model](../../docs/console-model.md),
[Session Supervision](../../docs/session-supervision.md), [Testing](../../docs/testing.md),
[programs/fb-charset/README.md](../fb-charset/README.md),
[programs/shell/README.md](../shell/README.md),
[services/drivers/framebuffer/README.md](../../services/drivers/framebuffer/README.md),
[shared/ansi/README.md](../../shared/ansi/README.md), [xtask/README.md](../../xtask/README.md)
