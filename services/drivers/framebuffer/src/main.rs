// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// drivers/framebuffer/src/main.rs

//! Seraph userspace framebuffer device driver.
//!
//! Spawned by devmgr with the bootloader-discovered GOP linear-
//! framebuffer `Mmio` cap plus a RECV cap on its service
//! endpoint. Owns the framebuffer end-to-end and is the sole
//! driver-mediated sink for userspace framebuffer bytes.
//!
//! Two-round bootstrap (mirrors `services/drivers/virtio/blk`):
//!   Round 1 (non-terminal): `[service_ep, mmio_cap]`
//!   Round 2 (terminal):     `[devmgr_query_ep]` (badged SEND for
//!                            `QUERY_DEVICE_INFO` with this device's
//!                            catalog index in the badge)
//!
//! After bootstrap the driver queries devmgr for its
//! [`boot_protocol::FramebufferInfo`] (geometry: width, height,
//! stride, pixel format) and uses the `byte_len` in the reply to size
//! the MMIO mapping (`stride * height` rounded up to pages).
//!
//! `FB_WRITE_BYTES` payloads are UTF-8. The service loop holds a single
//! `text::Utf8Decoder`; partial multi-byte sequences are buffered across
//! calls. Each assembled codepoint is resolved via the CP437 reverse →
//! font-extension → ASCII-fallback → `U+FFFD` chain in
//! `text::render_codepoint`, which feeds one or more 9×20 bitmaps to
//! the `FramebufferWriter`. `\n`, `\r`, and `\x08` (backspace) short-circuit
//! the decoder.
//!
//! Like the serial driver, this driver MUST NOT call
//! `std::os::seraph::log!`: a future logd fanout that routes its own
//! output here would deadlock (driver → log endpoint → logd → driver).
//! Diagnostics are dropped; fatal bootstrap failures `thread_exit`
//! silently. The kernel framebuffer renderer
//! (`core/kernel/src/framebuffer.rs`) remains the early-boot / panic
//! fallback (see `docs/console-model.md`).

#![allow(clippy::cast_possible_truncation)]

mod arch;
mod render;

use boot_protocol::FramebufferInfo;
use ipc::{IpcMessage, devmgr_labels, fb_errors, fb_labels};
use std::os::seraph::startup_info;
use text::{DecodeOutcome, Utf8Decoder};

const REPLACEMENT_CODEPOINT: u32 = 0xFFFD;

// ── Bootstrap ──────────────────────────────────────────────────────────────

struct BootCaps
{
    service_ep: u32,
    mmio_cap: u32,
    devmgr_query_ep: u32,
}

fn bootstrap_caps(creator_endpoint: u32, ipc_buf: *mut u64) -> Option<BootCaps>
{
    if creator_endpoint == 0
    {
        return None;
    }

    // Round 1: [service_ep, mmio_cap], non-terminal.
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let r1 = unsafe { ipc::bootstrap::request_round(creator_endpoint, ipc_buf) }.ok()?;
    if r1.cap_count < 2 || r1.done
    {
        return None;
    }
    let service_ep = r1.caps[0];
    let mmio_cap = r1.caps[1];

    // Round 2: [devmgr_query_ep], terminal.
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let r2 = unsafe { ipc::bootstrap::request_round(creator_endpoint, ipc_buf) }.ok()?;
    if r2.cap_count < 1 || !r2.done
    {
        return None;
    }
    let devmgr_query_ep = r2.caps[0];

    Some(BootCaps {
        service_ep,
        mmio_cap,
        devmgr_query_ep,
    })
}

/// Query devmgr for this device's [`FramebufferInfo`] via the generic
/// `QUERY_DEVICE_INFO` reply schema. Verifies kind and version before
/// deserialising.
fn query_framebuffer_info(devmgr_ep: u32, ipc_buf: *mut u64) -> Option<FramebufferInfo>
{
    let request = IpcMessage::builder(devmgr_labels::QUERY_DEVICE_INFO)
        .word(0, u64::from(ipc::DEVMGR_LABELS_VERSION))
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer.
    let reply = unsafe { ipc::ipc_call(devmgr_ep, &request, ipc_buf) }.ok()?;
    if reply.label != 0
    {
        return None;
    }
    let words = reply.words();
    if words.len() < 3
    {
        return None;
    }
    let kind = words[0] as u32;
    let version = words[1] as u32;
    let byte_len = words[2] as usize;
    if kind != ipc::device_info_kind::FRAMEBUFFER
        || version != boot_protocol::FRAMEBUFFER_INFO_VERSION
    {
        return None;
    }
    if byte_len != FramebufferInfo::SIZE
    {
        return None;
    }
    let payload_words = byte_len.div_ceil(8);
    if words.len() < 3 + payload_words
    {
        return None;
    }
    let mut buf = [0u8; FramebufferInfo::SIZE];
    for (i, chunk) in buf.chunks_mut(8).enumerate()
    {
        let bytes = words[3 + i].to_le_bytes();
        chunk.copy_from_slice(&bytes[..chunk.len()]);
    }
    FramebufferInfo::from_bytes(&buf)
}

// ── Service loop ───────────────────────────────────────────────────────────

fn handle_request(
    msg: &IpcMessage,
    writer: &mut render::FramebufferWriter,
    decoder: &mut Utf8Decoder,
    ipc_buf: *mut u64,
)
{
    // Label encoding mirrors `serial_labels::SERIAL_WRITE_BYTES` and
    // `stream_labels::STREAM_BYTES`: opcode in bits 0-15, payload byte
    // length in bits 16-31.
    let reply = if msg.label & 0xFFFF == fb_labels::FB_WRITE_BYTES
    {
        let byte_len = ((msg.label >> 16) & 0xFFFF) as usize;
        let bytes = msg.data_bytes();
        let n = byte_len.min(bytes.len());
        for &b in &bytes[..n]
        {
            // SAFETY: writer.base is a valid MMIO mapping for the
            // framebuffer's geometry; the FramebufferWriter advances
            // its own cursor within its declared geometry.
            unsafe {
                match b
                {
                    // `\n` and `\r` short-circuit the decoder, but drop
                    // any in-flight UTF-8 sequence first — a half-
                    // assembled lead byte stranded by a newline would
                    // otherwise eat the next codepoint.
                    b'\n' =>
                    {
                        decoder.reset();
                        writer.newline();
                    }
                    b'\r' =>
                    {
                        decoder.reset();
                        writer.carriage_return();
                    }
                    // Backspace moves the cursor back one column; the terminal
                    // pairs it with an overwriting space for a destructive erase.
                    b'\x08' =>
                    {
                        decoder.reset();
                        writer.backspace();
                    }
                    _ => match decoder.push(b)
                    {
                        DecodeOutcome::Codepoint(cp) => render_at(writer, cp),
                        DecodeOutcome::Invalid => render_at(writer, REPLACEMENT_CODEPOINT),
                        DecodeOutcome::NeedMore =>
                        {}
                    },
                }
            }
        }
        IpcMessage::new(fb_errors::SUCCESS)
    }
    else if msg.label & 0xFFFF == fb_labels::FB_SET_ATTRS
    {
        // Sticky fg/bg for subsequent glyph blits. Payload is six bytes:
        // [fg_r, fg_g, fg_b, bg_r, bg_g, bg_b].
        let bytes = msg.data_bytes();
        if bytes.len() >= 6
        {
            writer.set_attrs(
                [bytes[0], bytes[1], bytes[2]],
                [bytes[3], bytes[4], bytes[5]],
            );
        }
        IpcMessage::new(fb_errors::SUCCESS)
    }
    else
    {
        IpcMessage::new(fb_errors::UNKNOWN_OPCODE)
    };
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
}

/// Render one Unicode codepoint at the writer's cursor. Multi-glyph
/// ASCII fallbacks (e.g. `©` → `(C)`) emit several blits.
///
/// # Safety
/// `writer`'s framebuffer pointer must remain valid and writable.
unsafe fn render_at(writer: &mut render::FramebufferWriter, cp: u32)
{
    text::render_codepoint(cp, &mut |bitmap| {
        // SAFETY: hoisted from the caller's contract.
        unsafe {
            writer.draw_glyph_bitmap(bitmap);
        }
    });
}

fn service_loop(service_ep: u32, mut writer: render::FramebufferWriter, ipc_buf: *mut u64) -> !
{
    let mut decoder = Utf8Decoder::new();
    loop
    {
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let Ok(msg) = (unsafe { ipc::ipc_recv(service_ep, ipc_buf) })
        else
        {
            continue;
        };
        handle_request(&msg, &mut writer, &mut decoder, ipc_buf);
    }
}

// ── Entry ──────────────────────────────────────────────────────────────────

fn main() -> !
{
    let info = startup_info();

    // cast_ptr_alignment: IPC buffer page is 4 KiB-aligned.
    #[allow(clippy::cast_ptr_alignment)]
    let ipc_buf = info.ipc_buffer.cast::<u64>();

    let Some(caps) = bootstrap_caps(info.creator_endpoint, ipc_buf)
    else
    {
        syscall::thread_exit();
    };

    if caps.service_ep == 0 || caps.mmio_cap == 0 || caps.devmgr_query_ep == 0
    {
        syscall::thread_exit();
    }

    // Query devmgr for the framebuffer geometry. The reply size (and
    // therefore the MMIO mapping size we reserve) depends on it.
    let Some(fb_info) = query_framebuffer_info(caps.devmgr_query_ep, ipc_buf)
    else
    {
        syscall::thread_exit();
    };

    // Compute the VA reservation: `stride * height` rounded up to
    // 4 KiB pages, matching the bootloader's aperture seed.
    let span = u64::from(fb_info.stride) * u64::from(fb_info.height);
    let total_pages = span.div_ceil(0x1000);
    if total_pages == 0
    {
        syscall::thread_exit();
    }

    let Some(base) = arch::current::fb_mmio_init(info.self_aspace, caps.mmio_cap, total_pages)
    else
    {
        syscall::thread_exit();
    };

    // SAFETY: arch::fb_mmio_init mapped the entire framebuffer MMIO
    // region as writable; `fb_info.physical_base != 0` was verified
    // upstream (devmgr skipped this driver when it was zero).
    let Some(writer) = (unsafe { render::FramebufferWriter::new(base, &fb_info) })
    else
    {
        syscall::thread_exit();
    };

    service_loop(caps.service_ep, writer, ipc_buf);
}
