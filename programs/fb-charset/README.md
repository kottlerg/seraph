# fb-charset

A small demo program — a step above "hello world" — that prints a
representative sample of every glyph class the framebuffer driver can render,
for eyeballing font output the way `tput` / `showcfont` make the VT character
set inspectable elsewhere.

It is **not** a service and does **not** auto-start. Run it from the shell:

```
$ fb-charset
```

The shell's stdout is relayed by `programs/terminal` to the framebuffer (and
serial), so this exercises the driver's glyph rendering through the normal
stdio path — no driver or capability awareness in the program itself.

---

## Output

Pure `std`: the sample is written to stdout in labelled sections —

- 7-bit ASCII printable (`0x20..=0x7E`),
- CP437 high half (accented Latin, math/symbols, Greek, punctuation/currency),
- CP437 box-drawing (single, double, and mixed junction grids),
- block / shading elements,
- the font-extension table (em-dash, ellipsis, `×`, `⇒`, `≠`, `✓`, arrows, …),
- the ASCII multi-byte substitute path (`©` → `(C)`, `™` → `(TM)`, …),
- one deliberately ill-formed UTF-8 sequence so the `U+FFFD` glyph is reachable.

There are no assertions and no PASS/FAIL — the verdict is visual, which is why
there is no automated tester (CI cannot inspect rendered pixels). With no stdout
attached the output silently drops.

## References

- [docs/console-model.md](../../docs/console-model.md) — console/framebuffer
  output ownership across boot.
- [services/drivers/framebuffer/README.md](../../services/drivers/framebuffer/README.md)
  — the driver whose glyph rendering this exercises.

---

## Summarized By

None
