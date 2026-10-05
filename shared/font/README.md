# shared/font

Embedded 9×20 bitmap font for early console output.

256 glyphs, stored as a flat `[u16; 5120]` array. Each `u16` encodes one
scanline; bits 15–7 are the 9 pixels (MSB = leftmost). Glyph N, row R:
`FONT_9X20[N * 20 + R]`.

`no_std`. Used by the bootloader framebuffer console and the kernel early
console. No stability obligation.

---

## Summarized By

[Early Console](../../core/boot/docs/console.md)
