// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// programs/fb-charset/src/main.rs

//! Framebuffer character-set demo program.
//!
//! Prints a representative sample of every glyph class the framebuffer driver
//! can render — 7-bit ASCII, CP437 high half (math, Greek, accented Latin),
//! CP437 box-drawing, the font-extension table (em-dash, ellipsis, ×, ⇒, ≠, ✓,
//! arrows, …), the ASCII multi-byte substitute path (`©` → `(C)`, `™` → `(TM)`,
//! …), one deliberately ill-formed UTF-8 sequence (so the `U+FFFD` glyph is
//! reachable), and a 16-colour ANSI SGR sample — to stdout. Rows are
//! left-labelled and use the full console width so the sample fits one screen.
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
/// (e.g. the reader went away). The invalid-UTF-8 row is emitted as raw bytes
/// and the colour rows carry `ESC[…m` SGR; every other row is valid UTF-8.
/// `write!` is unusable here — the ASCII row contains literal `{`/`}` — so each
/// row is a `write_all` of byte content. Rows are left-labelled to an 8-column
/// field and use the full 142-column console so the whole sample fits on one
/// 36-row screen (1280×720 GOP) instead of scrolling.
fn emit(out: &mut std::io::Stdout) -> std::io::Result<()>
{
    out.write_all("fb-charset: glyph + colour sample\n".as_bytes())?;

    // 7-bit ASCII printable (0x20..=0x7E) on a single line.
    out.write_all(
        "ascii   :  !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~\n"
            .as_bytes(),
    )?;

    // CP437 high-half (0x80..=0xFF) via Unicode codepoints, grouped one row
    // per class; each resolves to its CP437 byte index in the reverse table.
    out.write_all(
        "latin   : à á â ä å ç è é ê ë ì í î ï ñ ò ó ô ö ù ú û ü ÿ  Ä Å Æ Ç É Ñ Ö Ü ß æ\n"
            .as_bytes(),
    )?;
    out.write_all("math    : ± × ÷ ¼ ½ ° µ ² ∙ √ ∞ ∩ ≈ ≡ ≤ ≥ ƒ ⌐ ⌠ ⌡ ⁿ ·\n".as_bytes())?;
    out.write_all("greek   : α Γ Θ Σ Φ Ω δ π σ τ φ ε\n".as_bytes())?;
    out.write_all("punct   : ¡ ¿ « » £ ¥ ¢ ₧ ª º ¬ ⌂\n".as_bytes())?;

    // Box drawing — joined grids so single-↔-double junctions read. Grid rows
    // are indented to the 10-column content margin to align under the titles.
    out.write_all("box     : single       double       mixed (d-h)  mixed (d-v)\n".as_bytes())?;
    out.write_all("          ┌──┬──┐      ╔══╦══╗      ╒══╤══╕      ╓──╥──╖\n".as_bytes())?;
    out.write_all("          │  │  │      ║  ║  ║      │  │  │      ║  ║  ║\n".as_bytes())?;
    out.write_all("          ├──┼──┤      ╠══╬══╣      ╞══╪══╡      ╟──╫──╢\n".as_bytes())?;
    out.write_all("          │  │  │      ║  ║  ║      │  │  │      ║  ║  ║\n".as_bytes())?;
    out.write_all("          └──┴──┘      ╚══╩══╝      ╘══╧══╛      ╙──╨──╜\n".as_bytes())?;

    // Block / shading elements (CP437 0xB0..=0xB2, 0xDB..=0xDF, 0xFE).
    out.write_all("blocks  : ░ ▒ ▓   █ ▀ ▄ ▌ ▐   ■\n".as_bytes())?;

    // Font extension (FONT_9X20_EXT slots): dashes/punct, math, arrows.
    out.write_all("ext     : — – ‑ ’ …  × − ⇒ ⇔ ≠ ≪ ≫ ∈ ✓  ← ↑ → ↓ ↔\n".as_bytes())?;

    // ASCII fallback: codepoints not in CP437/extension that expand via
    // shared/text::fallback.
    out.write_all("fallback: (c)© (r)® (tm)™  ‘x’ “y” • ‹z›\n".as_bytes())?;

    // Invalid UTF-8: a bare 0xC3 lead byte then an ASCII byte; the driver
    // renders U+FFFD then the trailing 'X'. Emitted as raw bytes.
    out.write_all(b"invalid : lone-lead \xC3X end\n")?;

    // SGR colour (#175). The terminal parses these `ESC[…m` sequences into
    // `FB_SET_ATTRS` colour changes for the framebuffer and passes the raw
    // bytes through to serial; a program not relayed by the terminal sees no
    // colour. Each row ends with `ESC[0m` so the prompt returns to default.
    out.write_all(
        b"fg norm : \x1b[30mblack \x1b[31mred \x1b[32mgreen \x1b[33myellow \x1b[34mblue \x1b[35mmagenta \x1b[36mcyan \x1b[37mwhite\x1b[0m\n",
    )?;
    out.write_all(
        b"fg brt  : \x1b[90mblack \x1b[91mred \x1b[92mgreen \x1b[93myellow \x1b[94mblue \x1b[95mmagenta \x1b[96mcyan \x1b[97mwhite\x1b[0m\n",
    )?;
    // Background rows pick the foreground per swatch: black (30) on light
    // fills, default white (39) on dark ones, so the word stays legible.
    out.write_all(
        b"bg norm : \x1b[39;40mblack \x1b[39;41mred \x1b[39;42mgreen \x1b[30;43myellow \x1b[39;44mblue \x1b[39;45mmagenta \x1b[30;46mcyan \x1b[30;47mwhite\x1b[0m\n",
    )?;
    out.write_all(
        b"bg brt  : \x1b[39;100mblack \x1b[39;101mred \x1b[30;102mgreen \x1b[30;103myellow \x1b[39;104mblue \x1b[39;105mmagenta \x1b[30;106mcyan \x1b[30;107mwhite\x1b[0m\n",
    )?;
    // Bold promotes a base colour to its bright variant: ESC[1;34m → bright blue.
    out.write_all(b"bold    : \x1b[1;34mbright blue via ESC[1;34m\x1b[0m\n")?;
    // ESC[39m / ESC[49m restore the default fg / bg mid-line.
    out.write_all(b"default : \x1b[31;43mred-on-yellow\x1b[39m\x1b[49m back-to-default\x1b[0m\n")?;
    // A non-SGR CSI (cursor-forward) is swallowed on the framebuffer, not
    // rendered as a literal `[5C`; the brackets render adjacent.
    out.write_all(b"swallow : [\x1b[5C] no literal escape\n")?;

    out.flush()
}
