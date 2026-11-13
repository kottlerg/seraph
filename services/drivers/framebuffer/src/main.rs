// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/drivers/framebuffer/src/main.rs

//! Seraph userspace framebuffer device driver.
//!
//! Bound by devmgr to the boot framebuffer's platform device record (the
//! `boot-framebuffer` key), it receives the resource list
//! (`driver_binding::resources`): the bootloader-discovered GOP linear
//! framebuffer's pages as one `Mmio` range, a RECV cap on its service
//! endpoint, and its devmgr query cap (a SEND badged with this device's
//! catalog badge on the private driver endpoint of its devmgr spawn batch).
//! Owns the framebuffer end-to-end and is the sole driver-mediated sink for
//! userspace framebuffer bytes.
//!
//! After bootstrap the driver queries devmgr for its
//! [`boot_protocol::FramebufferInfo`] (geometry: width, height,
//! stride, pixel format) on the query cap and uses the `byte_len` in the
//! reply to size the MMIO mapping (`stride * height` rounded up to pages).
//! Once the framebuffer is mapped it reports ready (`DRIVER_READY`) on the
//! same cap, immediately before its service loop: devmgr serves the
//! driver's endpoint only after that report, and the driver exits when
//! devmgr refuses it.
//!
//! `FB_WRITE_BYTES` payloads are UTF-8. The service loop holds a single
//! `text::Utf8Decoder`; partial multi-byte sequences are buffered across
//! calls. Each assembled codepoint is resolved via the CP437 reverse →
//! font-extension → ASCII-fallback → `U+FFFD` chain in
//! `text::render_codepoint`, which feeds one or more 9×20 bitmaps to
//! the `FramebufferWriter`. `\n`, `\r`, and `\x08` (backspace) short-circuit
//! the decoder.
//!
//! Like the serial driver, this driver MUST NOT call `std::os::seraph::log!`;
//! the rule and its deadlock chain are in `docs/console-model.md` § Logging
//! constraint on the serial and framebuffer drivers. Diagnostics are dropped;
//! fatal bootstrap failures `thread_exit` silently.

#![warn(clippy::allow_attributes, clippy::allow_attributes_without_reason)]
#![warn(clippy::multiple_unsafe_ops_per_block)]
#![warn(clippy::large_stack_frames)]
// Staged roll-out of these lints: docs/coding-standards.md § Clippy. The
// test configuration is exempt from the second set, as from `unwrap_used`.
#![warn(
    clippy::significant_drop_tightening,
    clippy::volatile_composites,
    clippy::wildcard_enum_match_arm
)]
#![cfg_attr(
    not(test),
    warn(
        clippy::panic,
        clippy::panic_in_result_fn,
        clippy::string_slice,
        clippy::unreachable,
        clippy::unwrap_in_result
    )
)]

mod arch;

use boot_protocol::FramebufferInfo;
use driver_binding::resources::{self, PlatformDelivery, Resource};
use framebuffer::{authority, render};
use ipc::{IpcMessage, devmgr_labels, fb_errors, fb_labels};
use std::os::seraph::startup_info;
use text::{DecodeOutcome, Utf8Decoder};

const REPLACEMENT_CODEPOINT: u32 = 0xFFFD;

// ── Declaration ────────────────────────────────────────────────────────────

// What devmgr binds this driver to and how it starts it
// (docs/driver-binding.md § Driver Declarations): the boot framebuffer's
// record.
driver_binding::driver_declaration!(driver_binding::decl::Declaration {
    name: "framebuffer",
    class: Some("framebuffer"),
    matches: &[driver_binding::decl::Match::BootFramebuffer],
    instance_limit: Some(1),
    interrupt: driver_binding::decl::Interrupt::NONE,
    dma: false,
    dma_width: None,
    phys_access: false,
    reset: driver_binding::decl::Reset::None,
    tier: driver_binding::decl::Tier::Auxiliary,
});

// ── Bootstrap ──────────────────────────────────────────────────────────────

/// Receive the resource list (`driver_binding::resources`): the
/// framebuffer's pages as one `Mmio` range, and the endpoints.
fn bootstrap(creator_endpoint: u64, ipc_buf: *mut u64) -> Option<PlatformDelivery>
{
    if creator_endpoint == 0
    {
        return None;
    }
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let list = unsafe { resources::receive(creator_endpoint, ipc_buf) }.ok()?;
    PlatformDelivery::from_list(&list)
}

/// Query devmgr for this device's [`FramebufferInfo`] via the generic
/// `QUERY_DEVICE_INFO` reply schema. Verifies kind and version before
/// deserialising.
fn query_framebuffer_info(devmgr_ep: u64, ipc_buf: *mut u64) -> Option<FramebufferInfo>
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
    let (&[kind, version, byte_len], payload) = words.split_first_chunk::<3>()?;
    let kind = u32::try_from(kind).ok()?;
    let version = u32::try_from(version).ok()?;
    let byte_len = usize::try_from(byte_len).ok()?;
    if kind != ipc::device_info_kind::FRAMEBUFFER
        || version != boot_protocol::FRAMEBUFFER_INFO_VERSION
    {
        return None;
    }
    if byte_len != FramebufferInfo::SIZE
    {
        return None;
    }
    let payload = payload.get(..byte_len.div_ceil(8))?;
    let mut buf = [0u8; FramebufferInfo::SIZE];
    for (chunk, word) in buf.chunks_mut(8).zip(payload)
    {
        for (dst, src) in chunk.iter_mut().zip(word.to_le_bytes())
        {
            *dst = src;
        }
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
    let reply = if !authority::authorized(msg.label, msg.badge)
    {
        IpcMessage::new(fb_errors::UNAUTHORIZED)
    }
    else if msg.label & 0xFFFF == fb_labels::FB_WRITE_BYTES
    {
        // The mask bounds the length to 16 bits, so the conversion cannot fail.
        // 16 label bits exceed the 512 bytes one message's data words carry,
        // and the loop stops at those bytes.
        let byte_len = usize::try_from((msg.label >> 16) & 0xFFFF).unwrap_or(0);
        for &b in msg.data_bytes().iter().take(byte_len)
        {
            // Each unsafe call below draws through `writer`, whose base is the
            // framebuffer mapping `main` made for the framebuffer's geometry
            // and never unmaps; the FramebufferWriter advances its own cursor
            // within that geometry.
            match b
            {
                // `\n` and `\r` short-circuit the decoder, but drop
                // any in-flight UTF-8 sequence first — a half-
                // assembled lead byte stranded by a newline would
                // otherwise eat the next codepoint.
                b'\n' =>
                {
                    decoder.reset();
                    // SAFETY: the writer's framebuffer mapping stays valid and
                    // writable (above).
                    unsafe { writer.newline() };
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
                _ =>
                {
                    let mut outcome = decoder.push(b);
                    if outcome == DecodeOutcome::Truncated
                    {
                        // SAFETY: the writer's framebuffer mapping stays valid
                        // and writable (above).
                        unsafe { render_at(writer, REPLACEMENT_CODEPOINT) };
                        outcome = decoder.push(b);
                    }
                    match outcome
                    {
                        DecodeOutcome::Codepoint(cp) =>
                        {
                            // SAFETY: the writer's framebuffer mapping stays
                            // valid and writable (above).
                            unsafe { render_at(writer, cp) };
                        }
                        DecodeOutcome::Invalid | DecodeOutcome::Truncated =>
                        {
                            // SAFETY: the writer's framebuffer mapping stays
                            // valid and writable (above).
                            unsafe { render_at(writer, REPLACEMENT_CODEPOINT) };
                        }
                        DecodeOutcome::NeedMore =>
                        {}
                    }
                }
            }
        }
        IpcMessage::new(fb_errors::SUCCESS)
    }
    else if msg.label & 0xFFFF == fb_labels::FB_SET_ATTRS
    {
        // Sticky fg/bg for subsequent glyph blits. Payload is six bytes:
        // [fg_r, fg_g, fg_b, bg_r, bg_g, bg_b].
        if let &[fg_r, fg_g, fg_b, bg_r, bg_g, bg_b, ..] = msg.data_bytes()
        {
            writer.set_attrs([fg_r, fg_g, fg_b], [bg_r, bg_g, bg_b]);
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

fn service_loop(service_ep: u64, mut writer: render::FramebufferWriter, ipc_buf: *mut u64) -> !
{
    let mut decoder = Utf8Decoder::new();
    // No diagnostic hook: a `log!` here is a blocking call into logd, which
    // may itself be blocked mirroring a line to this driver (see the module
    // doc). The kernel's rate-limited recv-failure line and the guard's exit
    // remain the signal.
    let mut guard = ipc::recv_guard::RecvGuard::new(|_, _| {});
    loop
    {
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let msg = match unsafe { ipc::ipc_recv(service_ep, ipc_buf) }
        {
            Ok(msg) => msg,
            Err(e) =>
            {
                guard.on_failure(e);
                continue;
            }
        };
        guard.on_success();
        handle_request(&msg, &mut writer, &mut decoder, ipc_buf);
    }
}

// ── Entry ──────────────────────────────────────────────────────────────────

fn main() -> !
{
    let info = startup_info();

    #[expect(
        clippy::cast_ptr_alignment,
        reason = "the IPC buffer page is 4 KiB-aligned"
    )]
    let ipc_buf = info.ipc_buffer.cast::<u64>();

    // logd mirrors every log line through this driver, so a debug-authority
    // holder that stopped it would wait on its own log output: declare this
    // process undebuggable before it spawns a thread
    // (`procmgr_labels::DECLARE_NO_DEBUG`). A refusal leaves it debuggable.
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let _ = unsafe {
        ipc::ipc_call(
            info.procmgr_endpoint,
            &ipc::IpcMessage::new(ipc::procmgr_labels::DECLARE_NO_DEBUG),
            ipc_buf,
        )
    };

    let Some(device) = bootstrap(info.creator_endpoint, ipc_buf)
    else
    {
        syscall::thread_exit();
    };
    let Resource::Mmio {
        cap: mmio_cap,
        phys,
        bytes,
        ..
    } = device.registers
    else
    {
        syscall::thread_exit();
    };

    // Query devmgr for the framebuffer geometry. The reply size (and
    // therefore the MMIO mapping size we reserve) depends on it.
    let Some(fb_info) = query_framebuffer_info(device.endpoints.devmgr_query, ipc_buf)
    else
    {
        syscall::thread_exit();
    };

    // Compute the VA reservation: the page-aligned aperture covering
    // `[physical_base, physical_base + stride * height)`. The delivered
    // range must be exactly that aperture, the range devmgr's record of the
    // boot framebuffer carves its `Mmio` cap over, so the whole-region
    // mapping fits the reservation.
    let in_page = fb_info.physical_base & 0xFFF;
    let Some((span, total_pages, aperture_bytes)) = u64::from(fb_info.stride)
        .checked_mul(u64::from(fb_info.height))
        .and_then(|span| {
            let total_pages = in_page.checked_add(span)?.div_ceil(0x1000);
            Some((span, total_pages, total_pages.checked_mul(0x1000)?))
        })
    else
    {
        syscall::thread_exit();
    };
    if span == 0 || phys != fb_info.physical_base & !0xFFF || bytes != aperture_bytes
    {
        syscall::thread_exit();
    }

    // SAFETY: `info.self_aspace` is this process's address space, and the
    // delivered `Mmio` range, whose cap spans it, is checked above to be the
    // `total_pages` pages of the geometry devmgr reports.
    let Some(aperture) =
        (unsafe { arch::current::fb_mmio_init(info.self_aspace, mmio_cap, total_pages) })
    else
    {
        syscall::thread_exit();
    };
    let in_page_bytes = usize::try_from(in_page).unwrap_or(0);
    // SAFETY: `in_page_bytes` is below one page, inside the mapping.
    let base = unsafe { aperture.add(in_page_bytes) };

    // SAFETY: arch::fb_mmio_init mapped total_pages pages from `aperture`,
    // which cover the `stride * height` bytes from `base`, writable; `new`
    // validates the geometry itself and returns None for a framebuffer it
    // cannot drive.
    let Some(writer) = (unsafe { render::FramebufferWriter::new(base, &fb_info) })
    else
    {
        syscall::thread_exit();
    };

    // SAFETY: ipc_buf is the registered IPC buffer page.
    if unsafe { ipc::report_driver_ready(device.endpoints.devmgr_query, ipc_buf) }.is_err()
    {
        syscall::thread_exit();
    }
    service_loop(device.endpoints.service, writer, ipc_buf);
}
