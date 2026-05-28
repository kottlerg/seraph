// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// programs/fb-charset/src/main.rs

//! Framebuffer character-set demo program.
//!
//! A small one-shot program — a step above "hello world" — that prints
//! a representative sample of every glyph class the framebuffer driver
//! can render: 7-bit ASCII, CP437 high half (math, Greek, accented
//! Latin), CP437 box-drawing, the font-extension table (em-dash,
//! ellipsis, ×, ⇒, ≠, ✓, arrows, …), the ASCII multi-byte substitute
//! path (`©` → `(C)`, `™` → `(TM)`, …), and one deliberately ill-formed
//! UTF-8 sequence so the `U+FFFD` glyph is reachable on screen. Useful for
//! eyeballing font output the same way `tput` / `showcfont` make the
//! VT character set inspectable elsewhere.
//!
//! Launched by svcmgr from `/config/svcmgr/services/fb-charset.svc` on
//! every default boot; the recipe declares `seed = devmgr.registry`,
//! so the bootstrap round delivers one cap on devmgr's registry. The
//! program calls `QUERY_FRAMEBUFFER_DEVICE` for a write cap on the
//! framebuffer driver's service endpoint, then submits the structured
//! sequence as `FB_WRITE_BYTES` chunks and exits.
//!
//! No assertions, no PASS/FAIL output — when fb-charset returns
//! `fb-charset: done`, the driver received every chunk and replied
//! `fb_errors::SUCCESS`. Headless boots run the same path; the pixels
//! land in MMIO but are not displayed. The rare no-framebuffer boot
//! (`physical_base == 0`) exits silently. `restart = never`,
//! `critical = no`.

#![feature(restricted_std)]

use std::os::seraph::startup_info;

use ipc::IpcMessage;

const FB_PAYLOAD_MAX: usize = 512;

fn main() -> !
{
    std::os::seraph::log::register_name(b"fb-charset");
    let info = startup_info();

    // cast_ptr_alignment: IPC buffer is page-aligned (4 KiB).
    #[allow(clippy::cast_ptr_alignment)]
    let ipc_buf = info.ipc_buffer.cast::<u64>();

    let Some(devmgr_registry) = bootstrap_devmgr_registry(info.creator_endpoint, ipc_buf)
    else
    {
        std::os::seraph::log!("fb-charset: no devmgr.registry seed; exiting");
        syscall::thread_exit();
    };

    let Some(fb_write) = query_framebuffer(devmgr_registry, ipc_buf)
    else
    {
        std::os::seraph::log!("fb-charset: framebuffer unavailable; skipping");
        let _ = syscall::cap_delete(devmgr_registry);
        syscall::thread_exit();
    };

    emit_sequence(fb_write, ipc_buf);

    std::os::seraph::log!("fb-charset: done");
    let _ = syscall::cap_delete(fb_write);
    let _ = syscall::cap_delete(devmgr_registry);
    syscall::thread_exit();
}

/// Pull a single bootstrap round; expect `caps[0]` from the recipe's
/// `seed = devmgr.registry`.
fn bootstrap_devmgr_registry(creator_ep: u32, ipc_buf: *mut u64) -> Option<u32>
{
    if creator_ep == 0
    {
        return None;
    }
    // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
    let round = unsafe { ipc::bootstrap::request_round(creator_ep, ipc_buf) }.ok()?;
    if round.cap_count < 1
    {
        return None;
    }
    let cap = round.caps[0];
    if cap == 0
    {
        return None;
    }
    Some(cap)
}

/// `QUERY_FRAMEBUFFER_DEVICE` against the seeded `devmgr.registry`
/// cap. Returns the framebuffer driver's write cap on success.
fn query_framebuffer(devmgr_registry: u32, ipc_buf: *mut u64) -> Option<u32>
{
    let request = IpcMessage::builder(ipc::devmgr_labels::QUERY_FRAMEBUFFER_DEVICE)
        .word(0, u64::from(ipc::DEVMGR_LABELS_VERSION))
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer.
    let reply = unsafe { ipc::ipc_call(devmgr_registry, &request, ipc_buf) }.ok()?;
    if reply.label != ipc::devmgr_errors::SUCCESS
    {
        return None;
    }
    let caps = reply.caps();
    if caps.is_empty()
    {
        return None;
    }
    let cap = caps[0];
    if cap == 0
    {
        return None;
    }
    Some(cap)
}

/// Emit one `FB_WRITE_BYTES`, chunking to `FB_PAYLOAD_MAX` if needed.
/// Returns `false` if the driver did not reply `fb_errors::SUCCESS`
/// on any chunk; the caller logs and continues so a single bad chunk
/// does not silence the rest of the demo.
fn write_str(fb_write: u32, ipc_buf: *mut u64, s: &str) -> bool
{
    let mut bytes = s.as_bytes();
    while !bytes.is_empty()
    {
        let n = bytes.len().min(FB_PAYLOAD_MAX);
        let chunk = &bytes[..n];
        let label = ipc::fb_labels::FB_WRITE_BYTES | ((n as u64) << 16);
        let msg = IpcMessage::builder(label).bytes(0, chunk).build();
        // SAFETY: ipc_buf is the registered IPC buffer.
        let Ok(reply) = (unsafe { ipc::ipc_call(fb_write, &msg, ipc_buf) })
        else
        {
            std::os::seraph::log!("fb-charset: ipc_call failed mid-write");
            return false;
        };
        if reply.label != ipc::fb_errors::SUCCESS
        {
            std::os::seraph::log!("fb-charset: driver returned label={:#x}", reply.label);
            return false;
        }
        bytes = &bytes[n..];
    }
    true
}

/// Emit a single chunk of explicit bytes (used for the invalid-UTF-8
/// row, which cannot be expressed as a `&str`). Behaviour otherwise
/// matches `write_str`.
fn write_bytes(fb_write: u32, ipc_buf: *mut u64, bytes: &[u8]) -> bool
{
    let n = bytes.len().min(FB_PAYLOAD_MAX);
    let label = ipc::fb_labels::FB_WRITE_BYTES | ((n as u64) << 16);
    let msg = IpcMessage::builder(label).bytes(0, &bytes[..n]).build();
    // SAFETY: ipc_buf is the registered IPC buffer.
    let Ok(reply) = (unsafe { ipc::ipc_call(fb_write, &msg, ipc_buf) })
    else
    {
        return false;
    };
    reply.label == ipc::fb_errors::SUCCESS
}

fn emit_sequence(fb_write: u32, ipc_buf: *mut u64)
{
    // 1. Banner.
    let _ = write_str(
        fb_write,
        ipc_buf,
        "fb-charset: userspace framebuffer driver up\n",
    );

    // 2. 7-bit ASCII printable (0x20..=0x7E).
    let _ = write_str(fb_write, ipc_buf, "---- ascii ----\n");
    let _ = write_str(
        fb_write,
        ipc_buf,
        " !\"#$%&'()*+,-./0123456789:;<=>?\n\
         @ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_\n\
         `abcdefghijklmnopqrstuvwxyz{|}~\n",
    );

    // 3. CP437 high-half (0x80..=0xFF) via Unicode codepoints — the
    //    reverse table covers all 128 entries. Grouped for readability;
    //    every codepoint here resolves to its CP437 byte index.
    let _ = write_str(fb_write, ipc_buf, "---- cp437 high-half ----\n");
    let _ = write_str(
        fb_write,
        ipc_buf,
        "latin lower: à á â ä å ç è é ê ë ì í î ï ñ ò ó ô ö ù ú û ü ÿ\n\
         latin upper: Ä Å Æ Ç É Ñ Ö Ü ß æ\n\
         math/sym:    ± × ÷ ¼ ½ ° µ ² ∙ √ ∞ ∩ ≈ ≡ ≤ ≥ ƒ ⌐ ⌠ ⌡ ⁿ ·\n\
         greek:       α Γ Θ Σ Φ Ω δ π σ τ φ ε\n\
         punct/curr:  ¡ ¿ « » £ ¥ ¢ ₧ ª º ¬ ⌂\n",
    );

    // 4. Box drawing — every CP437 box-drawing glyph in joined-grid
    //    form so the single-↔-double junctions read correctly.
    //    Single-line: 11 glyphs. Double-line: 11. Mixed (double horiz
    //    × single vert): 9. Mixed (single horiz × double vert): 9.
    let _ = write_str(fb_write, ipc_buf, "---- box drawing ----\n");
    let _ = write_str(
        fb_write,
        ipc_buf,
        "single        double        mixed (d-h)   mixed (d-v)\n\
         ┌──┬──┐      ╔══╦══╗      ╒══╤══╕      ╓──╥──╖\n\
         │  │  │      ║  ║  ║      │  │  │      ║  ║  ║\n\
         ├──┼──┤      ╠══╬══╣      ╞══╪══╡      ╟──╫──╢\n\
         │  │  │      ║  ║  ║      │  │  │      ║  ║  ║\n\
         └──┴──┘      ╚══╩══╝      ╘══╧══╛      ╙──╨──╜\n",
    );

    // 5. Block / shading elements (CP437 0xB0..=0xB2, 0xDB..=0xDF, 0xFE).
    let _ = write_str(fb_write, ipc_buf, "---- blocks ----\n");
    let _ = write_str(
        fb_write,
        ipc_buf,
        "shading: ░ ▒ ▓   blocks: █ ▀ ▄ ▌ ▐   filled-sq: ■\n",
    );

    // 6. Font extension: every slot in FONT_9X20_EXT (slot 0 / U+FFFD
    //    is exercised separately in step 8).
    let _ = write_str(fb_write, ipc_buf, "---- font extension ----\n");
    let _ = write_str(
        fb_write,
        ipc_buf,
        "em-dash — en-dash – nb-hyphen ‑ apos ’ ellipsis …\n\
         times × minus − dbl-arrows ⇒ ⇔ neq ≠ ≪ ≫ in ∈ check ✓\n\
         arrows ← ↑ → ↓ ↔\n",
    );

    // 7. ASCII fallback: codepoints not in CP437 or extension that
    //    expand to multi-char substitutes via shared/text::fallback.
    let _ = write_str(fb_write, ipc_buf, "---- ascii fallback ----\n");
    let _ = write_str(
        fb_write,
        ipc_buf,
        "(c)© (r)® (tm)™\n\
         single-quote ‘x’ double-quote “y” bullet • angle ‹z›\n",
    );

    // 8. Invalid UTF-8: a bare 0xC3 (lead byte of a 2-byte sequence)
    //    followed by an ASCII byte that the decoder will treat as a
    //    bad continuation. The driver renders U+FFFD then continues
    //    with the trailing 'X'.
    let _ = write_str(fb_write, ipc_buf, "---- invalid utf-8 ----\n");
    let _ = write_bytes(fb_write, ipc_buf, b"lone-lead: \xC3X end\n");

    // 9. End marker.
    let _ = write_str(fb_write, ipc_buf, "---- done ----\n");
}
