# shared/text

Byte-stream → glyph primitives shared by every Seraph framebuffer console.

---

## Source Layout

```
text/
├── Cargo.toml
├── README.md
└── src/
    ├── lib.rs              # public re-exports
    ├── utf8.rs             # Utf8Decoder, DecodeOutcome
    ├── cp437.rs            # unicode_to_cp437 reverse table
    ├── ext.rs              # ext_glyph_index → font::FONT_9X20_EXT_MAP
    ├── fallback.rs         # ascii_fallback substitute table
    └── glyphs.rs           # render_codepoint dispatcher
```

`no_std`, no allocation. Depends only on `shared/font`.

---

## Modules

| Module | Purpose |
|---|---|
| `utf8` | Incremental UTF-8 decoder (`Utf8Decoder`, `DecodeOutcome`). Holds partial state across the byte stream so a multi-byte sequence may straddle two IPC payloads. |
| `cp437` | `unicode_to_cp437(cp) -> Option<u8>`. ASCII fast path plus binary search over the standard CP437 high-half. |
| `ext` | `ext_glyph_index(cp) -> Option<usize>`. Lookup into `font::FONT_9X20_EXT_MAP` for codepoints the codebase uses but CP437 lacks. |
| `fallback` | `ascii_fallback(cp) -> Option<&'static [u8]>`. Best-fit ASCII substitutes (`(C)`, `<->`, `(TM)`, …) for the long tail. |
| `glyphs` | `render_codepoint(cp, sink)`. Dispatcher; resolves a codepoint to one or more 9×20 bitmaps. |

## Dispatch order

`render_codepoint` walks the four sources in order; the first hit wins.
For ASCII fallback the sink is invoked once per substitute byte. If
nothing matches, slot 0 of `FONT_9X20_EXT` (`U+FFFD`) is emitted.

## Consumers

| Consumer | Use |
|---|---|
| `services/drivers/framebuffer` | Owns one `Utf8Decoder` in its service loop; dispatches every assembled codepoint via `render_codepoint`. |
| `core/kernel` | Early-boot / panic framebuffer console (`core/kernel/src/framebuffer.rs`). |
| `core/boot` | UEFI bootloader pre-`ExitBootServices` framebuffer console (`core/boot/src/framebuffer.rs`). |
| `core/ktest` | ktest harness direct framebuffer output (`core/ktest/src/framebuffer.rs`). |

Each consumer holds its own `Utf8Decoder` and feeds bytes through the
same `render_codepoint` chain, so every framebuffer surface resolves the
identical glyph set.

## Licensing

GPL-2.0-only for code. The bitmap data the crate resolves into lives in
`shared/font` and is OFL-1.1 (Terminus 10×20 trimmed to 9×20).

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/console-model.md](../../docs/console-model.md) | Console output phase ownership; where the framebuffer-driver path that consumes this crate sits |
| [services/drivers/framebuffer/README.md](../../services/drivers/framebuffer/README.md) | Sole runtime consumer; FB_WRITE_BYTES contract and the resolver chain |

---

## Summarized By

None
