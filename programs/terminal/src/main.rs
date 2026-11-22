// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// programs/terminal/src/main.rs

//! Terminal abstraction, v0.0.1 (#111).
//!
//! Relays a byte stream between hardware drivers and the standard streams of
//! an operator session's leader, with a tiny line discipline. Input arrives
//! from two sources — the virtio-input keyboard (#110) and serial RX (#66) —
//! and output renders on the framebuffer (#67) and mirrors to serial TX (#66).
//! The terminal is an interface of sessiond (`session.rs`): it opens the
//! session through the `sessiond.operator` SEND, handing over the leader's
//! pipes and death relay, and sessiond creates the leader (the shell its
//! recipe names), so the terminal holds no process handle and no namespace.
//!
//! Structure: one producer thread per input source (keyboard decodes key-downs
//! to bytes; serial forwards received UART bytes) sends down a shared `mpsc`
//! channel; per-session relay threads forward the leader's stdout/stderr down the
//! same channel; a watcher thread per session posts the leader's end, read
//! from its death relay; the single consumer thread (this `main`) owns the
//! output sink and the leader's stdin, applies the line discipline (local
//! echo, single-line backspace, CR→LF), and opens a new session when the
//! leader ends. The consumer's sole
//! ownership of the sink is why no locking is needed, and its source-agnostic
//! discipline is why a new input source is just another producer.
//!
//! Each driver class is followed by a [`device_tracker::Device`], which keeps its
//! current driver across devmgr's restart of it, on the class's watch. Its
//! tracker thread outlives `main`'s, so a fatal path ends the whole process
//! (`std::process::exit`), not the main thread alone.
//!
//! Remaining deferrals are documented in `README.md`: signals/cooked-raw/
//! job-control/multi-session (#29) and the real interactive shell (#112).

mod input;
mod output;
mod session;

use std::io::Write;
use std::process::ChildStdin;
use std::sync::mpsc::{Receiver, Sender, channel};

use output::Sink;

/// Printed once all driver caps are held and the keyboard thread is running;
/// the host test harness injects keys on seeing it. Kept in sync with
/// `xtask/src/commands/test/terminal.rs`.
const READY_MARKER: &str = "terminal: READY for injection";

/// Channel message: a decoded input byte run, a leader output byte run, or the
/// leader's end (sent by the session's watcher thread).
pub(crate) enum Msg
{
    Input(Vec<u8>),
    Output(Vec<u8>),
    SessionEnded,
}

fn main() -> !
{
    std::os::seraph::log::register_name(b"terminal");
    let info = std::os::seraph::startup_info();
    #[expect(
        clippy::cast_ptr_alignment,
        reason = "the IPC buffer page is 4 KiB-aligned, stricter than u64"
    )]
    let ipc_buf = info.ipc_buffer.cast::<u64>();

    let Some([input_class, fb_class, serial_class, operator]) =
        bootstrap_seeds(info.creator_endpoint, ipc_buf)
    else
    {
        std::os::seraph::log!(error: "terminal: a seed is missing; exiting");
        std::process::exit(1);
    };
    // SAFETY: ipc_buf is the registered IPC buffer.
    let input = unsafe { device_tracker::Device::start(input_class, "input", ipc_buf) };
    let Some(input_driver) = input.await_first("input")
    else
    {
        std::os::seraph::log!(error: "terminal: no input device; exiting");
        std::process::exit(1);
    };
    // The framebuffer is the primary output but optional: a headless boot has
    // none, and the terminal then mirrors to serial only, until devmgr serves
    // one.
    // SAFETY: ipc_buf is the registered IPC buffer.
    let framebuffer = unsafe { device_tracker::Device::start(fb_class, "framebuffer", ipc_buf) };
    if framebuffer.current().is_none()
    {
        std::os::seraph::log!(warn: "terminal: framebuffer unavailable; serial-only output");
    }
    // SAFETY: ipc_buf is the registered IPC buffer.
    let serial = unsafe { device_tracker::Device::start(serial_class, "serial", ipc_buf) };
    let Some(serial_driver) = serial.await_first("serial")
    else
    {
        std::os::seraph::log!(error: "terminal: no serial device; exiting");
        std::process::exit(1);
    };

    let (tx, rx) = channel::<Msg>();
    let kbd_tx = tx.clone();
    let kbd_input = input.clone();
    std::thread::spawn(move || input::keyboard_loop(&kbd_input, input_driver, &kbd_tx));
    // Second input producer: serial RX. The serial driver multiplexes read and
    // write on one endpoint, so the RX thread and the Sink's TX share the
    // device.
    let serial_rx_tx = tx.clone();
    let rx_serial = serial.clone();
    std::thread::spawn(move || input::serial_loop(&rx_serial, serial_driver, &serial_rx_tx));

    let mut sink = Sink::new(framebuffer, serial);
    std::os::seraph::log!("{READY_MARKER}");

    let mut client = session::Client::new(operator);
    run(&mut client, &rx, &tx, &mut sink)
}

/// Open a session, relay its leader's stdio to the sink, feed the leader
/// line-disciplined input, and open a new session when the leader ends.
/// Never returns.
fn run(client: &mut session::Client, rx: &Receiver<Msg>, tx: &Sender<Msg>, sink: &mut Sink) -> !
{
    loop
    {
        // Start each session with default colours: a previous leader that ended
        // mid-colour (e.g. crashed before its trailing `ESC[0m`) must not tint
        // the next session or the shell prompt. Dedups to a no-op when already
        // default (the common first-spawn case).
        sink.write(b"\x1b[0m");

        // sessiond creates the leader at level 5 with a band ceiling of 5,
        // so the terminal (level 10) always preempts it.
        let mut streams = client.open();

        let mut stdin = streams.take_stdin();
        for out in [
            streams.take_stdout().map(Pipe::Stdout),
            streams.take_stderr().map(Pipe::Stderr),
        ]
        .into_iter()
        .flatten()
        {
            let relay_tx = tx.clone();
            std::thread::spawn(move || out.pump(&relay_tx));
        }
        let watch_tx = tx.clone();
        let watcher = std::thread::spawn(move || {
            let status = streams.wait();
            let _ = watch_tx.send(Msg::SessionEnded);
            status
        });

        let mut line = Vec::new();
        loop
        {
            match rx.recv()
            {
                Ok(Msg::Input(bytes)) => discipline(&bytes, &mut line, sink, stdin.as_mut()),
                Ok(Msg::Output(bytes)) => sink.write(&bytes),
                Ok(Msg::SessionEnded) => break,
                Err(_) =>
                {
                    std::os::seraph::log!(error: "terminal: input channel closed; exiting");
                    std::process::exit(1);
                }
            }
        }

        drop(stdin.take());
        match watcher.join()
        {
            Ok(Ok(status)) =>
            {
                std::os::seraph::log!("terminal: session ended ({status}); opening another");
            }
            Ok(Err(_)) | Err(_) =>
            {
                std::os::seraph::log!(warn: "terminal: session end unread; opening another");
            }
        }
    }
}

/// One of the leader's output streams.
enum Pipe
{
    Stdout(std::process::ChildStdout),
    Stderr(std::process::ChildStderr),
}

impl Pipe
{
    /// Forward the stream to the consumer until EOF.
    fn pump(self, tx: &Sender<Msg>)
    {
        match self
        {
            Self::Stdout(out) => pump_stream(out, tx),
            Self::Stderr(err) => pump_stream(err, tx),
        }
    }
}

/// Apply the v0.0.1 line discipline to a run of input bytes: local echo to the
/// sink, single-line backspace, and CR→LF translation to the leader on Enter.
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
                    std::os::seraph::log!(warn: "terminal: write to the leader's stdin failed");
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

/// Forward a leader stream to the consumer as [`Msg::Output`] until EOF or a
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
                // A count past the buffer breaks the `Read` contract; it ends
                // the relay as a read error does.
                let Some(run) = buf.get(..n)
                else
                {
                    break;
                };
                if tx.send(Msg::Output(run.to_vec())).is_err()
                {
                    break;
                }
            }
        }
    }
}

/// Pull the bootstrap rounds; expect slots 0 to 3 from the recipe's
/// `seed = devmgr.class.input devmgr.class.framebuffer devmgr.class.serial
/// sessiond.operator`, in that order. `None` when any is absent.
fn bootstrap_seeds(creator_ep: u64, ipc_buf: *mut u64) -> Option<[u64; 4]>
{
    if creator_ep == 0
    {
        return None;
    }
    // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
    // Only the present caps ride, named by each round's presence word; an
    // absent slot decodes as `0`.
    let caps = unsafe { ipc::bootstrap::request_slots::<4>(creator_ep, ipc_buf) }.ok()?;
    caps.iter().all(|&cap| cap != 0).then_some(caps)
}
