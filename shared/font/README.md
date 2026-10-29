# shared/font

Embedded 9×20 bitmap font shared by every framebuffer console.

---

## Overview

`FONT_9X20` holds 256 glyphs indexed by CP437 byte, stored as a flat `[u16; 5120]`. Each `u16`
encodes one scanline; bits 15–7 are the 9 pixels (MSB = leftmost). Glyph N, row R:
`FONT_9X20[N * 20 + R]`. `GLYPH_WIDTH` and `GLYPH_HEIGHT` give the cell size.

`FONT_9X20_EXT` holds `FONT_9X20_EXT_COUNT` (20) extension glyphs in the same scanline encoding,
for codepoints the codebase uses that CP437 lacks; slot 0 is reserved for U+FFFD and drawn as a
checkerboard. `FONT_9X20_EXT_MAP` maps a Unicode codepoint to its slot; its entries MUST stay in
ascending codepoint order, since `shared/text` binary-searches it. Resolving a byte stream to a
glyph is `shared/text`'s job ([shared/text/README.md](../text/README.md)); this crate holds only
the bitmap data.

`no_std`, no dependencies. Used by the bootloader, kernel, and ktest framebuffer renderers, the
userspace framebuffer driver, and `shared/text`. No stability obligation.

---

## Licensing

Code is GPL-2.0-only. The bitmap data is OFL-1.1, adapted from Terminus 10×20 (Dimitar Toshkov
Zhekov): the rightmost pixel column of each source glyph is dropped to produce the 9×20 cells.
`FONT_9X20_EXT` slot 0 (the U+FFFD checkerboard) is original rather than Terminus-derived.

---

## Source Layout

```
shared/font/
├── Cargo.toml
├── README.md
└── src/
    └── lib.rs      # FONT_9X20, FONT_9X20_EXT, FONT_9X20_EXT_MAP, glyph dimensions
```

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/console-model.md](../../docs/console-model.md) | Console ownership across boot; the framebuffer renderers that draw with this font |
| [core/boot/docs/console.md](../../core/boot/docs/console.md) | Bootloader framebuffer console |
| [shared/text/README.md](../text/README.md) | Byte-stream to glyph resolution over this font |

---

## Summarized By

[Early Console](../../core/boot/docs/console.md), [shared/text/README.md](../text/README.md)
