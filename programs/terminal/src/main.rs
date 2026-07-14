// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// programs/terminal/src/main.rs

//! Terminal abstraction, v0.0.1 (#111).
//!
//! Relays a byte stream between hardware drivers and a child process's stdio,
//! with a tiny line discipline. Input arrives from two sources — the
//! virtio-input keyboard (#110) and serial RX (#66) — and output renders on the
//! framebuffer (#67) and mirrors to serial TX (#66). The child
//! (`/programs/shell` by default, overridable via `argv[1]`) is spawned with
//! piped stdio over the `ProcessInfo` stdio contract.
//!
//! Structure: one producer thread per input source (keyboard decodes key-downs
//! to bytes; serial forwards received UART bytes) sends down a shared `mpsc`
//! channel; per-child relay threads forward the child's stdout/stderr down the
//! same channel; the single consumer thread (this `main`) owns the output sink
//! and the child's stdin, applies the line discipline (local echo, single-line
//! backspace, CR→LF), and respawns the child when it exits. The consumer's sole
//! ownership of the sink is why no locking is needed, and its source-agnostic
//! discipline is why a new input source is just another producer.
//!
//! Remaining deferrals are documented in `README.md`: signals/cooked-raw/
//! job-control/multi-session (#29) and the real interactive shell (#112).

mod input;
mod output;

use std::io::Write;
use std::os::seraph::process::CommandExt;
use std::process::{ChildStdin, Command, Stdio};
use std::sync::mpsc::{Receiver, Sender, channel};

use ipc::IpcMessage;
use output::Sink;

/// Child spawned when the recipe passes no `argv[1]`. `terminal.svc` sets it
/// explicitly; this is the fallback.
const DEFAULT_CHILD: &str = "/programs/shell";

/// Printed once all driver caps are held and the keyboard thread is running;
/// the host test harness injects keys on seeing it. Kept in sync with
/// `xtask/src/commands/test_terminal.rs`.
const READY_MARKER: &str = "terminal: READY for injection";

/// Channel message: a decoded input byte run, a child output byte run, or the
/// child-exit edge (sent by the stdout relay on EOF).
pub(crate) enum Msg
{
    Input(Vec<u8>),
    Output(Vec<u8>),
    ChildExited,
}

fn main() -> !
{
    std::os::seraph::log::register_name(b"terminal");
    let info = std::os::seraph::startup_info();
    // cast_ptr_alignment: IPC buffer page is 4 KiB-aligned, stricter than u64.
    #[allow(clippy::cast_ptr_alignment)]
    let ipc_buf = info.ipc_buffer.cast::<u64>();

    let Some(registry) = bootstrap_devmgr_registry(info.creator_endpoint, ipc_buf)
    else
    {
        std::os::seraph::log!("terminal: no devmgr.registry seed; exiting");
        syscall::thread_exit();
    };
    let Some(input_cap) = query_device(registry, ipc::devmgr_labels::QUERY_INPUT_DEVICE, ipc_buf)
    else
    {
        std::os::seraph::log!("terminal: QUERY_INPUT_DEVICE failed; exiting");
        syscall::thread_exit();
    };
    // The framebuffer is the primary output but optional: a headless boot has
    // none, and the terminal then mirrors to serial only.
    let fb_cap = query_device(
        registry,
        ipc::devmgr_labels::QUERY_FRAMEBUFFER_DEVICE,
        ipc_buf,
    );
    if fb_cap.is_none()
    {
        std::os::seraph::log!("terminal: framebuffer unavailable; serial-only output");
    }
    let Some(serial_cap) = query_device(registry, ipc::devmgr_labels::QUERY_SERIAL_DEVICE, ipc_buf)
    else
    {
        std::os::seraph::log!("terminal: QUERY_SERIAL_DEVICE failed; exiting");
        syscall::thread_exit();
    };

    let child_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| DEFAULT_CHILD.to_string());

    let (tx, rx) = channel::<Msg>();
    let kbd_tx = tx.clone();
    std::thread::spawn(move || input::keyboard_loop(input_cap, &kbd_tx));
    // Second input producer: serial RX. `serial_cap` is also the Sink's TX cap
    // (a Copy `u32`); the driver multiplexes read and write on the one endpoint.
    let serial_rx_tx = tx.clone();
    std::thread::spawn(move || input::serial_loop(serial_cap, &serial_rx_tx));

    let mut sink = Sink::new(fb_cap, serial_cap);
    std::os::seraph::log!("{READY_MARKER}");

    run(&child_path, &rx, &tx, &mut sink)
}

/// Spawn the child, relay its stdio to the sink, feed it line-disciplined
/// input, and respawn it when it exits. Never returns.
fn run(child_path: &str, rx: &Receiver<Msg>, tx: &Sender<Msg>, sink: &mut Sink) -> !
{
    loop
    {
        // Start each child with default colours: a previous child that exited
        // mid-colour (e.g. crashed before its trailing `ESC[0m`) must not tint
        // the next child or the shell prompt. Dedups to a no-op when already
        // default (the common first-spawn case).
        sink.write(b"\x1b[0m");

        // The child session (shell) is the least-trusted process in the
        // system: place it at level 5 with a matching band ceiling so
        // neither it nor anything it spawns can climb above 5 — the
        // terminal itself (level 10) always preempts it.
        let mut child = match Command::new(child_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .priority(5)
            .sched_max(5)
            .spawn()
        {
            Ok(child) => child,
            Err(e) =>
            {
                std::os::seraph::log!("terminal: spawn {child_path} failed: {e}");
                syscall::thread_exit();
            }
        };

        let mut stdin = child.stdin.take();
        if let Some(out) = child.stdout.take()
        {
            let relay_tx = tx.clone();
            std::thread::spawn(move || relay_stdout(out, &relay_tx));
        }
        if let Some(err) = child.stderr.take()
        {
            let relay_tx = tx.clone();
            std::thread::spawn(move || relay_stderr(err, &relay_tx));
        }

        let mut line = Vec::new();
        loop
        {
            match rx.recv()
            {
                Ok(Msg::Input(bytes)) => discipline(&bytes, &mut line, sink, stdin.as_mut()),
                Ok(Msg::Output(bytes)) => sink.write(&bytes),
                Ok(Msg::ChildExited) => break,
                Err(_) =>
                {
                    std::os::seraph::log!("terminal: input channel closed; exiting");
                    syscall::thread_exit();
                }
            }
        }

        drop(stdin.take());
        let _ = child.wait();
        std::os::seraph::log!("terminal: child exited; respawning");
    }
}

/// Apply the v0.0.1 line discipline to a run of input bytes: local echo to the
/// sink, single-line backspace, and CR→LF translation to the child on Enter.
fn discipline(bytes: &[u8], line: &mut Vec<u8>, sink: &mut Sink, mut stdin: Option<&mut ChildStdin>)
{
    for &b in bytes
    {
        match b
        {
            b'\r' | b'\n' =>
            {
                sink.write(b"\r\n");
                line.push(b'\n');
                if let Some(si) = stdin.as_deref_mut()
                    && (si.write_all(line).is_err() || si.flush().is_err())
                {
                    std::os::seraph::log!("terminal: write to child stdin failed");
                }
                line.clear();
            }
            0x08 | 0x7f =>
            {
                if line.pop().is_some()
                {
                    sink.write(b"\x08 \x08");
                }
            }
            _ =>
            {
                line.push(b);
                sink.write(&[b]);
            }
        }
    }
}

/// Forward a child stream to the consumer as [`Msg::Output`] until EOF or a
/// read/channel error.
fn pump_stream<R: std::io::Read>(mut reader: R, tx: &Sender<Msg>)
{
    let mut buf = [0u8; 512];
    loop
    {
        match reader.read(&mut buf)
        {
            Ok(0) | Err(_) => break,
            Ok(n) =>
            {
                if tx.send(Msg::Output(buf[..n].to_vec())).is_err()
                {
                    break;
                }
            }
        }
    }
}

/// Relay the child's stdout, then post [`Msg::ChildExited`] on EOF so the
/// consumer reaps and respawns the child.
fn relay_stdout<R: std::io::Read>(reader: R, tx: &Sender<Msg>)
{
    pump_stream(reader, tx);
    let _ = tx.send(Msg::ChildExited);
}

/// Relay the child's stderr. No exit signal — stdout's EOF drives respawn, so
/// that a single channel message marks the child gone.
fn relay_stderr<R: std::io::Read>(reader: R, tx: &Sender<Msg>)
{
    pump_stream(reader, tx);
}

/// Pull the single bootstrap round; expect `caps[0]` from the recipe's
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
    (cap != 0).then_some(cap)
}

/// Query devmgr for a device endpoint cap, retrying briefly while the driver's
/// on-disk spawn completes.
fn query_device(registry: u32, label: u64, ipc_buf: *mut u64) -> Option<u32>
{
    for _ in 0..100
    {
        let req = IpcMessage::builder(label)
            .word(0, u64::from(ipc::DEVMGR_LABELS_VERSION))
            .build();
        // SAFETY: ipc_buf is the registered IPC buffer.
        let reply = unsafe { ipc::ipc_call(registry, &req, ipc_buf) };
        if let Ok(reply) = reply
            && reply.label == ipc::devmgr_errors::SUCCESS
            && let Some(&cap) = reply.caps().first()
            && cap != 0
        {
            return Some(cap);
        }
        let _ = syscall::thread_yield();
    }
    None
}
