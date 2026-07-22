// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! qmp.rs
//!
//! Minimal QMP (QEMU Machine Protocol) client for the QMP-driven tests.
//! Connects to QEMU's `-qmp unix:...` socket, completes the capabilities
//! handshake, and issues the handful of commands the harnesses need:
//! `input-send-event` (interactive-input test), `migrate` + `query-migrate`
//! and `quit` (snapshot-resume test).
//!
//! Hand-rolled (no JSON dependency): the messages are fixed strings and
//! responses are matched by substring. QMP messages are newline-delimited
//! JSON.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail};

/// A handshaken QMP connection.
struct Client
{
    writer: UnixStream,
    reader: BufReader<UnixStream>,
}

impl Client
{
    /// Connect to the QMP socket and complete the capabilities handshake.
    fn connect(socket: &Path) -> Result<Self>
    {
        let stream = connect_with_retry(socket)?;
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .context("setting QMP read timeout")?;
        let writer = stream.try_clone().context("cloning QMP stream")?;
        let mut client = Self {
            writer,
            reader: BufReader::new(stream),
        };

        // QMP greeting banner (one line) precedes the capabilities handshake.
        read_line(&mut client.reader).context("reading QMP greeting")?;
        client.send(r#"{"execute":"qmp_capabilities"}"#)?;
        client.read_result().context("qmp_capabilities handshake")?;
        Ok(client)
    }

    fn send(&mut self, json: &str) -> Result<()>
    {
        self.writer
            .write_all(json.as_bytes())
            .context("QMP write")?;
        self.writer.write_all(b"\n").context("QMP write newline")?;
        self.writer.flush().context("QMP flush")?;
        Ok(())
    }

    /// Read QMP lines until a command result, skipping asynchronous `event`
    /// lines. Returns the `return` line for callers that inspect its payload;
    /// bails on an `error` result.
    fn read_result(&mut self) -> Result<String>
    {
        for _ in 0..64
        {
            let line = read_line(&mut self.reader)?;
            if line.contains("\"error\"")
            {
                bail!("QMP error: {}", line.trim());
            }
            if line.contains("\"return\"")
            {
                return Ok(line);
            }
            // Otherwise an asynchronous event; keep reading.
        }
        bail!("QMP: no command result after 64 lines")
    }
}

/// Connect to the QMP socket, complete the handshake, and inject each
/// `(qcode, down)` event via `input-send-event`, in order. Callers build the
/// event list (taps are a down/up pair; held modifiers wrap the keys they
/// modify).
pub fn inject_events(socket: &Path, events: &[(&str, bool)]) -> Result<()>
{
    let mut client = Client::connect(socket)?;
    for &(qcode, down) in events
    {
        // Omit the `device` argument: in headless mode virtio-keyboard is the
        // sole keyboard, so the event routes to it unambiguously.
        let msg = format!(
            r#"{{"execute":"input-send-event","arguments":{{"events":[{{"type":"key","data":{{"down":{down},"key":{{"type":"qcode","data":"{qcode}"}}}}}}]}}}}"#
        );
        client.send(&msg)?;
        client
            .read_result()
            .with_context(|| format!("input-send-event {qcode} down={down}"))?;
    }

    Ok(())
}

/// Migrate the guest's state to `state_path` (QEMU's save-to-file recipe:
/// `migrate` with an `exec:cat > file` URI) and block until the migration
/// reports `completed`, or fail after `timeout`.
///
/// The source VM is left in QEMU's `postmigrate` runstate; the caller
/// [`quit`]s it before restoring the file elsewhere (the raw disk image
/// stays write-locked until the process exits).
pub fn migrate_to_file(socket: &Path, state_path: &Path, timeout: Duration) -> Result<()>
{
    let mut client = Client::connect(socket)?;
    let msg = format!(
        r#"{{"execute":"migrate","arguments":{{"uri":"exec:cat > {}"}}}}"#,
        state_path.display()
    );
    client.send(&msg)?;
    client.read_result().context("migrate command")?;

    let deadline = Instant::now() + timeout;
    loop
    {
        client.send(r#"{"execute":"query-migrate"}"#)?;
        let status = client.read_result().context("query-migrate")?;
        if status.contains("\"completed\"")
        {
            return Ok(());
        }
        if status.contains("\"failed\"") || status.contains("\"cancelled\"")
        {
            bail!("migration failed: {}", status.trim());
        }
        if Instant::now() >= deadline
        {
            bail!(
                "migration not completed within {}s: {}",
                timeout.as_secs(),
                status.trim()
            );
        }
        thread::sleep(Duration::from_millis(200));
    }
}

/// Ask QEMU to exit. The response read is best-effort: QEMU may close the
/// socket before or instead of acknowledging.
pub fn quit(socket: &Path) -> Result<()>
{
    let mut client = Client::connect(socket)?;
    client.send(r#"{"execute":"quit"}"#)?;
    let _ = client.read_result();
    Ok(())
}

fn connect_with_retry(socket: &Path) -> Result<UnixStream>
{
    // The guest prints READY deep into boot, long after QEMU created the
    // socket; the short retry only covers scheduling skew.
    let mut last = String::new();
    for _ in 0..50
    {
        match UnixStream::connect(socket)
        {
            Ok(s) => return Ok(s),
            Err(e) =>
            {
                last = e.to_string();
                thread::sleep(Duration::from_millis(100));
            }
        }
    }
    bail!(
        "connecting to QMP socket {} failed: {last}",
        socket.display()
    )
}

fn read_line(reader: &mut BufReader<UnixStream>) -> Result<String>
{
    let mut line = String::new();
    let n = reader.read_line(&mut line).context("reading QMP line")?;
    if n == 0
    {
        bail!("QMP connection closed");
    }
    Ok(line)
}
