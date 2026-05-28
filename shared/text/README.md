# text

Byte-stream → glyph primitives for the userspace framebuffer driver.

`no_std`, no allocation. Depends only on `shared/font` for the bitmap data.

## Modules

| Module | Purpose |
|---|---|
| `utf8` | Incremental UTF-8 decoder (`Utf8Decoder`, `DecodeOutcome`). Holds partial state across the byte stream so a multi-byte sequence may straddle two IPC payloads. |
| `cp437` | `unicode_to_cp437(cp) -> Option<u8>`. ASCII fast path plus binary search over the standard CP437 high-half. |
| `ext` | `ext_glyph_index(cp) -> Option<usize>`. Lookup into `font::FONT_9X20_EXT_MAP` for codepoints the codebase uses but CP437 lacks. |
| `fallback` | `ascii_fallback(cp) -> Option<&'static [u8]>`. Best-fit ASCII substitutes (`(C)`, `<->`, `(TM)`, …) for the long tail. |
| `glyphs` | `render_codepoint(cp, sink)`. Dispatcher; resolves a codepoint to one or more 9×20 bitmaps. |

## Dispatch order

`render_codepoint` walks the four sources in order; the first hit wins. For
ASCII fallback the sink is invoked once per substitute byte. If nothing
matches, slot 0 of `FONT_9X20_EXT` (`U+FFFD`) is emitted.

## Consumers

* `services/drivers/framebuffer` — owns one `Utf8Decoder` in its service
  loop, dispatches every assembled codepoint via `render_codepoint`.

A follow-up issue tracks back-porting the same chain into the kernel,
bootloader, and ktest renderers so the early-boot consoles can print the
same characters.

## Licensing

GPL-2.0-only for code. The bitmap data the crate resolves into lives in
`shared/font` and is OFL-1.1 (Terminus 10×20 trimmed to 9×20).
