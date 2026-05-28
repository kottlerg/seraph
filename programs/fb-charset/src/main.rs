// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// programs/fb-charset/src/main.rs

//! Userspace framebuffer character-coverage witness.
//!
//! One-shot test program launched by svcmgr from
//! `/config/svcmgr/services/fb-charset.svc`. Exercises every glyph
//! class served by the framebuffer driver:
//!
//! * 7-bit ASCII (CP437 fast path).
//! * CP437 high half (math, Greek, accented Latin).
//! * CP437 box-drawing.
//! * Font-extension table (em-dash, ellipsis, ×, ⇒, ≠, ✓, …).
//! * ASCII multi-byte fallback (`©` → `(C)`, `↔` → `<->`, …).
//! * Invalid UTF-8 → `U+FFFD` checkerboard.
//!
//! Bootstrap: a single round delivers `caps[0]` = `devmgr.registry`
//! (`REGISTRY_QUERY_AUTHORITY`-tokened SEND on devmgr's registry
//! endpoint), per the recipe's `seed = devmgr.registry`. fb-charset
//! issues `QUERY_FRAMEBUFFER_DEVICE` against it to receive a write cap
//! on the framebuffer driver's service endpoint, then submits a
//! structured sequence of `FB_WRITE_BYTES` payloads.
//!
//! Headless boots write through the full pipeline as on graphical
//! boots; the IPC `SUCCESS` reply per chunk is the indirect oracle
//! that the driver dispatched each payload through its UTF-8 decoder,
//! glyph resolver, and MMIO write loop. The `no framebuffer` boot
//! (rare; `physical_base == 0`) skips silently — `restart = never`,
//! `critical = no`, so svcmgr does not flag the missing run.

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
/// does not silence the rest of the witness.
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

    // 2. 7-bit ASCII sweep.
    let _ = write_str(fb_write, ipc_buf, "---- ascii ----\n");
    let _ = write_str(
        fb_write,
        ipc_buf,
        " !\"#$%&'()*+,-./0123456789:;<=>?\n\
         @ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_\n\
         `abcdefghijklmnopqrstuvwxyz{|}~\n",
    );

    // 3. CP437 high-half: math, Greek, accented Latin.
    let _ = write_str(fb_write, ipc_buf, "---- cp437 high-half ----\n");
    let _ = write_str(
        fb_write,
        ipc_buf,
        "math: ± × ÷ ¼ ½ ° µ ² ∙ √ ∞ ∩ ≈ ≡ ≤ ≥\n\
         greek: α β Γ Δ Θ Σ Φ Ω δ π σ τ φ ε\n\
         latin: à á â ä ç é ê ë ï î ñ ó ö ú ü ÿ Ä Å Æ É Ñ Ö Ü ß\n\
         punct: ¡ ¿ « » £ ¥ ¢ © ®\n",
    );

    // 4. Box-drawing — joined rows depend on adjacent-cell pixels
    //    lining up across the right margin (font is 9-px wide).
    let _ = write_str(fb_write, ipc_buf, "---- box drawing ----\n");
    let _ = write_str(
        fb_write,
        ipc_buf,
        "┌──┬──┐\n\
         │  │  │\n\
         ├──┼──┤\n\
         │  │  │\n\
         └──┴──┘\n",
    );

    // 5. Font extension: every slot in FONT_9X20_EXT.
    let _ = write_str(fb_write, ipc_buf, "---- font extension ----\n");
    let _ = write_str(
        fb_write,
        ipc_buf,
        "em-dash — en-dash – nb-hyphen ‑ apos ’ ellipsis …\n\
         times × minus − arrows ⇒ ⇔ neq ≠ ≪ ≫ in ∈ check ✓\n",
    );

    // 6. ASCII fallback: codepoints not in CP437 or extension.
    let _ = write_str(fb_write, ipc_buf, "---- ascii fallback ----\n");
    let _ = write_str(
        fb_write,
        ipc_buf,
        "(c)© (r)® (tm)™ left-right ↔ left ← up ↑ down ↓ right →\n\
         single-quote ‘x’ double-quote “y” bullet • angle ‹z›\n",
    );

    // 7. Invalid UTF-8: a bare 0xC3 (lead byte of a 2-byte sequence)
    //    followed by an ASCII byte that the decoder will treat as a
    //    bad continuation. The driver renders U+FFFD then continues
    //    with the trailing 'X'.
    let _ = write_str(fb_write, ipc_buf, "---- invalid utf-8 ----\n");
    let _ = write_bytes(fb_write, ipc_buf, b"lone-lead: \xC3X end\n");

    // 8. End marker.
    let _ = write_str(fb_write, ipc_buf, "---- done ----\n");
}
