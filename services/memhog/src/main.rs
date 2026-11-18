// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/memhog/src/main.rs

//! The memory hog test fixture: a supervised service that, on request, takes
//! what memmgr can still promise a process outside the system reserve until
//! the pressure level reads `CRITICAL`, and holds it until it is stopped
//! (services/memhog/README.md).
//!
//! memhog serves `ipc::memhog_labels` on the endpoint of the name its recipe
//! provides, which svcmgr delivers in bootstrap slot 0. The fill is
//! `mem_fill`'s, shared with crashme's `oom-fill` mode. Its recipe sets
//! `oom_stop = yes` and no reserve, so it is the service the out-of-memory
//! policy service stops: svctest's `oom` phase has it hog, and reads that it
//! was stopped and restarted idle.

use ipc::{IpcMessage, memhog_labels as hog};
use mem_fill::Fill;
use syscall_abi::SyscallError;

/// Bytes of stack the fixture touches at start, below its loop's frame.
const STACK_TOUCH_BYTES: usize = 16 * 1024;

fn main() -> !
{
    std::os::seraph::log::register_name(b"memhog");
    let info = std::os::seraph::startup_info();
    #[expect(
        clippy::cast_ptr_alignment,
        reason = "the IPC buffer page is 4 KiB-aligned"
    )]
    let ipc_buf = info.ipc_buffer.cast::<u64>();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let service = unsafe { ipc::bootstrap::request_slots::<1>(info.creator_endpoint, ipc_buf) }
        .map_or(0, |[cap]| cap);
    let nonce = syscall::random_u64().unwrap_or(0);
    if service == 0 || nonce == 0
    {
        std::os::seraph::log!(error: "no service endpoint or nonce");
        syscall::thread_exit();
    }
    let Some(mut fill) = Fill::new()
    else
    {
        std::os::seraph::log!(error: "ballast not allocated");
        syscall::thread_exit();
    };
    touch_stack();
    std::os::seraph::log!("serving");
    serve(service, nonce, &mut fill, ipc_buf)
}

/// Serve [`hog`]'s labels on `service`, and once hogging, take back what
/// other processes free every `mem_fill::TICK_MS` between requests.
fn serve(service: u64, nonce: u64, fill: &mut Fill, ipc_buf: *mut u64) -> !
{
    let mut hogging = false;
    loop
    {
        // 0 waits without bound.
        let timeout = if hogging { mem_fill::TICK_MS } else { 0 };
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let msg = match unsafe { ipc::ipc_recv_timeout(service, ipc_buf, timeout) }
        {
            Ok(msg) => msg,
            Err(e) if e == SyscallError::WouldBlock as i64 =>
            {
                fill.top_up();
                continue;
            }
            Err(_) => continue,
        };
        for &cap in msg.caps()
        {
            let _ = syscall::cap_delete(cap);
        }
        let reply = match msg.label
        {
            hog::PROBE => IpcMessage::builder(hog::SUCCESS)
                .word(0, nonce)
                .word(1, fill.pages())
                .build(),
            hog::HOG =>
            {
                hogging = true;
                match fill.to_critical()
                {
                    Ok(()) =>
                    {
                        std::os::seraph::log!("holding {} pages: memory critical", fill.pages());
                        IpcMessage::builder(hog::SUCCESS)
                            .word(0, fill.pages())
                            .build()
                    }
                    Err(why) =>
                    {
                        std::os::seraph::log!(
                            warn: "memory not critical ({why:?}), {} pages held",
                            fill.pages()
                        );
                        IpcMessage::new(hog::NOT_CRITICAL)
                    }
                }
            }
            _ => IpcMessage::new(hog::UNKNOWN_OPCODE),
        };
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
    }
}

/// Touch [`STACK_TOUCH_BYTES`] of the stack below this frame, so the fixture
/// faults no new stack page while memory is critical.
#[inline(never)]
#[expect(
    clippy::large_stack_frames,
    reason = "the frame is the touch: its array is the stack the fixture uses, written once at start"
)]
fn touch_stack()
{
    let mut probe = [0u8; STACK_TOUCH_BYTES];
    std::hint::black_box(&mut probe);
}
