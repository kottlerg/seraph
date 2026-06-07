// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// programs/fb-charset/src/main.rs

//! Framebuffer character-set demo program.
//!
//! Prints a representative sample of every glyph class the framebuffer driver
//! can render — 7-bit ASCII, CP437 high half (math, Greek, accented Latin),
//! CP437 box-drawing, the font-extension table (em-dash, ellipsis, ×, ⇒, ≠, ✓,
//! arrows, …), the ASCII multi-byte substitute path (`©` → `(C)`, `™` → `(TM)`,
//! …), and one deliberately ill-formed UTF-8 sequence (so the `U+FFFD` glyph is
//! reachable) — to stdout.
//!
//! Run it from the shell: the terminal relays the shell's stdout to the
//! framebuffer (and serial), so this exercises the driver's glyph rendering
//! through the normal stdio path. Useful for eyeballing font output the same way
//! `tput` / `showcfont` make the VT character set inspectable elsewhere.
//!
//! Not auto-started — there is no `fb-charset.svc`; it is a plain
//! `/programs/fb-charset` invoked manually. Pure `std`: no driver or cap
//! awareness; with no stdout attached the output silently drops.

use std::io::Write;

fn main()
{
    let mut out = std::io::stdout();
    let _ = emit(&mut out);
}

/// Write the character-set sample to `out`, stopping at the first write error
/// (e.g. the reader went away). The invalid-UTF-8 row is emitted as raw bytes;
/// every other section is valid UTF-8. `write!` is unusable here — the ASCII row
/// contains literal `{`/`}` — so each section is a `write_all` of byte content.
fn emit(out: &mut std::io::Stdout) -> std::io::Result<()>
{
    // 1. Banner.
    out.write_all("fb-charset: framebuffer glyph sample\n".as_bytes())?;

    // 2. 7-bit ASCII printable (0x20..=0x7E).
    out.write_all("---- ascii ----\n".as_bytes())?;
    out.write_all(
        " !\"#$%&'()*+,-./0123456789:;<=>?\n\
         @ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_\n\
         `abcdefghijklmnopqrstuvwxyz{|}~\n"
            .as_bytes(),
    )?;

    // 3. CP437 high-half (0x80..=0xFF) via Unicode codepoints — each resolves
    //    to its CP437 byte index in the driver's reverse table.
    out.write_all("---- cp437 high-half ----\n".as_bytes())?;
    out.write_all(
        "latin lower: à á â ä å ç è é ê ë ì í î ï ñ ò ó ô ö ù ú û ü ÿ\n\
         latin upper: Ä Å Æ Ç É Ñ Ö Ü ß æ\n\
         math/sym:    ± × ÷ ¼ ½ ° µ ² ∙ √ ∞ ∩ ≈ ≡ ≤ ≥ ƒ ⌐ ⌠ ⌡ ⁿ ·\n\
         greek:       α Γ Θ Σ Φ Ω δ π σ τ φ ε\n\
         punct/curr:  ¡ ¿ « » £ ¥ ¢ ₧ ª º ¬ ⌂\n"
            .as_bytes(),
    )?;

    // 4. Box drawing — joined grids so single-↔-double junctions read.
    out.write_all("---- box drawing ----\n".as_bytes())?;
    out.write_all(
        "single        double        mixed (d-h)   mixed (d-v)\n\
         ┌──┬──┐      ╔══╦══╗      ╒══╤══╕      ╓──╥──╖\n\
         │  │  │      ║  ║  ║      │  │  │      ║  ║  ║\n\
         ├──┼──┤      ╠══╬══╣      ╞══╪══╡      ╟──╫──╢\n\
         │  │  │      ║  ║  ║      │  │  │      ║  ║  ║\n\
         └──┴──┘      ╚══╩══╝      ╘══╧══╛      ╙──╨──╜\n"
            .as_bytes(),
    )?;

    // 5. Block / shading elements (CP437 0xB0..=0xB2, 0xDB..=0xDF, 0xFE).
    out.write_all("---- blocks ----\n".as_bytes())?;
    out.write_all("shading: ░ ▒ ▓   blocks: █ ▀ ▄ ▌ ▐   filled-sq: ■\n".as_bytes())?;

    // 6. Font extension (FONT_9X20_EXT slots; slot 0 / U+FFFD is step 8).
    out.write_all("---- font extension ----\n".as_bytes())?;
    out.write_all(
        "em-dash — en-dash – nb-hyphen ‑ apos ’ ellipsis …\n\
         times × minus − dbl-arrows ⇒ ⇔ neq ≠ ≪ ≫ in ∈ check ✓\n\
         arrows ← ↑ → ↓ ↔\n"
            .as_bytes(),
    )?;

    // 7. ASCII fallback: codepoints not in CP437/extension that expand via
    //    shared/text::fallback.
    out.write_all("---- ascii fallback ----\n".as_bytes())?;
    out.write_all(
        "(c)© (r)® (tm)™\n\
         single-quote ‘x’ double-quote “y” bullet • angle ‹z›\n"
            .as_bytes(),
    )?;

    // 8. Invalid UTF-8: a bare 0xC3 lead byte then an ASCII byte; the driver
    //    renders U+FFFD then the trailing 'X'. Emitted as raw bytes.
    out.write_all("---- invalid utf-8 ----\n".as_bytes())?;
    out.write_all(b"lone-lead: \xC3X end\n")?;

    // 9. End marker.
    out.write_all("---- done ----\n".as_bytes())?;
    out.flush()
}
