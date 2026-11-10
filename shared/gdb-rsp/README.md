# shared/gdb-rsp

The GDB remote serial protocol: packet framing, the parse and encode of the packet set a stub
serves, and the target descriptions of both architectures.

---

## Source Layout

```
gdb-rsp/
├── Cargo.toml
├── README.md
└── src/
    ├── lib.rs              # PACKET_SIZE, Error
    ├── frame.rs            # PacketReader, Event, AckMode, PacketWriter and its reply bodies,
    │                       #   escape and checksum
    ├── command.rs          # Command::parse and the types its variants carry
    ├── hex.rs              # hex numbers and data
    └── target.rs           # Arch: target description XML and register layout
```

`no_std`, no allocation, no dependencies. Pure logic, host-tested by `cargo xtask test`.

---

## Surface

| Item | Purpose |
|---|---|
| `frame::PacketReader<N>` | Splits a received byte stream into `Event`s one byte at a time: a packet's body (checksum checked), `+`, `-`, the interrupt byte `0x03`, a bad checksum, or a packet past its `N`-byte buffer. |
| `frame::AckMode` | The acknowledgement a stub sends for each event, until it accepts `QStartNoAckMode`. |
| `frame::PacketWriter` | Writes one packet (`$`, escaped body, `#`, checksum) into a caller's buffer, with the reply bodies a stub sends: `OK`, `E`, stop replies, exit replies, thread lists, `qOffsets`, `qSupported`, `vCont?`, and `qXfer` chunks. |
| `frame::unescape`, `frame::unescaped_len` | Undo the binary escaping of `X` data. |
| `command::Command::parse` | Parses a packet body into a `Command`: `?`, `g`, `G`, `p`, `P`, `m`, `M`, `X`, `c`, `C`, `s`, `S`, `vCont?`, `vCont`, `Z`, `z`, `H`, `T`, `qfThreadInfo`, `qsThreadInfo`, `qC`, `qSupported`, `qAttached`, `qOffsets`, `QStartNoAckMode`, `qXfer:features:read`, `vAttach`, `D`, `k`; any other body is `Unknown`, answered with an empty reply. |
| `target::Arch` | Each architecture's target description XML (`TARGET_XML_ANNEX`), its registers in protocol order, the program counter's number, and each register's place in the `g` block. |
| `PACKET_SIZE` | The packet size a stub advertises and reads packets into. |

## Scope

A stub reads bytes from its transport into a `PacketReader`, acknowledges per `AckMode`, parses
each packet with `Command::parse`, maps the command onto the system's debugging mechanism
([docs/fault-handling.md](../../docs/fault-handling.md) § Debugging), and writes its reply with a
`PacketWriter`. The crate holds the protocol only: it depends on no Seraph service, and the mapping
from a command to syscalls, and from the kernel's register file to the `g` block, is the stub's.
The target descriptions use GDB's standard feature names (`org.gnu.gdb.i386.core` and
`org.gnu.gdb.i386.sse` on x86-64, `org.gnu.gdb.riscv.cpu` and `org.gnu.gdb.riscv.fpu` on riscv64),
and GDB 18.1 loads both and lays out the `g` block as `target::Arch` does.

The multiprocess thread-id form, conditional breakpoints, and run-length encoding are not part of
the packet set: a stub using this crate advertises none of them, and parses no packet that
carries them.

Consumers: the `debug-echo` fixture ([services/debug-echo/README.md](../../services/debug-echo/README.md))
in the guest, and `cargo xtask test-debug-port` ([xtask/README.md](../../xtask/README.md)) on the
host.

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/fault-handling.md](../../docs/fault-handling.md) | § Debugging: the mechanism a stub maps the commands onto |

---

## Summarized By

None
