# terminal

Userspace terminal: relays a byte stream between hardware drivers and a child
process's stdio, with a minimal line discipline. This is the durable terminal
abstraction; v0.0.1 (#111) ships an intentionally tiny feature surface that
grows in later releases.

The terminal owns its driver endpoint caps directly because no input/display
broker exists yet. When a broker/compositor lands (a separate v0.2.0+ design
issue), the terminal becomes a subscriber and the stdio contract to its child
does not change.

---

## v0.0.1 scope

- **Input**: virtio-input keyboard ([#110]). Key-down events are decoded to a
  byte stream; the matching key-up and modifier-key events are dropped.
- **Output**: framebuffer text ([#67], primary) mirrored to serial TX ([#66],
  debug). Both share one wire format (`*_WRITE_BYTES`, length in the label's
  high bits, payload chunked at 512 bytes). The framebuffer is optional: a
  headless boot has none, and the terminal then mirrors to serial only — so a
  headless `cargo xtask run` still gives a usable terminal over serial.
- **Line discipline**:
  - local echo of each typed character to the output,
  - single-line backspace (`BS` erases the last byte of the current line and
    emits `BS SP BS` to the display),
  - CR→LF translation (Enter sends `\n` to the child).
- **Child**: spawned with piped stdin/stdout/stderr over the `ProcessInfo`
  stdio contract via `std::process::Command`. The child path defaults to
  `/programs/echosh` and is overridable through `argv[1]` (set in the recipe).
  On child exit the terminal respawns it.
- **Supervision**: a non-bootstrap svcmgr service
  (`/config/svcmgr/services/terminal.svc`), `critical = no`, `restart = never`.
  It autostarts on a normal `cargo xtask run`. It is never bundled into the ESP
  and init never loads it.

## Architecture

A persistent keyboard thread blocks on the keysym stream, decodes key-downs to
bytes, and sends them down an `mpsc` channel. Per-child relay threads forward
the child's stdout/stderr down the same channel. The single consumer thread
owns the output sink and the child's stdin, applies the line discipline, and
respawns the child on exit. Sole ownership of the sink by one thread is why no
locking is needed; each thread issues driver IPC on its own per-thread IPC
buffer (`std::os::seraph::current_ipc_buf`).

Decoding to bytes lives in the keyboard source, so the consumer is
source-agnostic: a future serial-RX input source becomes another producer
feeding the same channel with raw bytes (see deferrals).

## Deferred

- **Serial RX as a second input source** — the serial driver ([#66]) is
  TX-only today (`SERIAL_READ_BYTES` is unimplemented). Tracked for a future
  release; the input layer is already source-generic to accommodate it.
- **Signals** (`^C`→SIGINT, `^D`→EOF, `^Z`→SIGTSTP), **cooked/raw mode
  toggle**, **job control**, **multi-session / multi-terminal**, **pty
  equivalents**, **cross-process line buffering** — line-discipline maturity,
  tracked under [#29].
- **A real interactive shell** — `echosh` is a placeholder; the shell lands as
  `programs/shell` under [#112], at which point this terminal's `argv` retargets
  to it.
- **Any input/display broker layer** — separate future design issue.

## Known limitations

- Framebuffer and serial are shared, unbrokered sinks: terminal output
  interleaves with logd (serial) and the boot-time `fb-charset` dump
  (framebuffer). Cosmetic until a broker exists.
- Non-printable named keys (arrows, Home/End/Delete, Tab, Escape) are ignored.
- Backspace is byte-wise: it erases one byte of the current line, so
  backspacing a multi-byte UTF-8 character is incorrect. Grapheme-aware editing
  is part of line-discipline maturity ([#29]).

## Testing

Driven host-side by `cargo xtask test-terminal`, which boots with a QMP control
socket, waits for the `terminal: READY for injection` marker, injects a known
key sequence through the real virtio-input driver, and asserts the echoed input
and the relayed child output appear on the serial stream. It runs as a boot in
the `usertest` cell. See [docs/testing.md](../../docs/testing.md).

[#29]: https://github.com/kottlerg/seraph/issues/29
[#66]: https://github.com/kottlerg/seraph/issues/66
[#67]: https://github.com/kottlerg/seraph/issues/67
[#110]: https://github.com/kottlerg/seraph/issues/110
[#112]: https://github.com/kottlerg/seraph/issues/112

---

## Summarized By

[Testing](../../docs/testing.md)
