# shared/ansi

Incremental ANSI SGR colour parser for the Seraph terminal output path.

---

## Source Layout

```
ansi/
├── Cargo.toml
├── README.md
└── src/
    └── lib.rs              # AnsiParser state machine, Event, ANSI_RGB palette
```

`no_std`, no allocation, no dependencies.

---

## Surface

| Item | Purpose |
|---|---|
| `AnsiParser` | Stateful `Ground → Esc → Csi` machine. One per output stream; carries partial-sequence and colour state across `feed` calls so a sequence may straddle payload boundaries. |
| `AnsiParser::feed(bytes, sink)` | Drives the bytes, invoking `sink` with each `Event` in stream order. |
| `Event::Text(&[u8])` | A run of literal output bytes (no escapes), borrowing the input slice — no allocation. |
| `Event::Attrs([u8;3], [u8;3])` | A foreground/background 24-bit RGB change, resolved at an `ESC[…m` boundary and emitted only when it differs from the last pair. |

## Scope (issue #175)

Recognised SGR codes: foreground `30..=37` / `90..=97`, background
`40..=47` / `100..=107`, `0` reset, `1` bold (promotes a base colour to its
bright variant), `22` normal intensity, `39` / `49` default fg / bg. Every
other SGR code — italic, underline, blink, reverse — is silently ignored,
as are the `38` / `48` 256-colour / truecolour introducers together with
their `5;<n>` / `2;<r>;<g>;<b>` operands. Non-`m` CSI
sequences (cursor movement, erase) and non-CSI escapes are swallowed, not
rendered as literal glyphs.

The 16 → RGB mapping (Windows 10 console / Campbell palette; index 0 and 15
pinned to pure black / white so unstyled text matches the pre-colour default)
lives here, not in the framebuffer driver. The driver renders whatever 24-bit colour it is handed
via `fb_labels::FB_SET_ATTRS` and holds no palette, so a future direct-RGB
client reuses the same wire without inheriting ANSI's colour vocabulary.

## Consumers

| Consumer | Use |
|---|---|
| `programs/terminal` | Holds one `AnsiParser` in its output sink; the framebuffer path emits `FB_SET_ATTRS` on `Event::Attrs` and `FB_WRITE_BYTES` on `Event::Text`. The serial mirror is fed the raw bytes (ANSI passes through unchanged). |

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/console-model.md](../../docs/console-model.md) | Console output phase ownership; the terminal owns SGR parsing, the driver never sees `ESC` |
| [services/drivers/framebuffer/README.md](../../services/drivers/framebuffer/README.md) | `FB_SET_ATTRS` wire contract this parser drives |

---

## Summarized By

None
