// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! qmp.rs
//!
//! Minimal QMP (QEMU Machine Protocol) client for the interactive-input test.
//! Connects to QEMU's `-qmp unix:...` socket, completes the capabilities
//! handshake, and injects a fixed keyboard sequence via `input-send-event`.
//!
//! Hand-rolled (no JSON dependency): the handful of QMP messages are fixed
//! strings and responses are matched by substring. QMP messages are
//! newline-delimited JSON.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::thread;
use std::time::Duration;

use anyhow::{Context as _, Result, bail};

/// The key sequence injected by the input smoke test, as `(QKeyCode, down)`
/// pairs. After virtio-input decode this yields `a`, `A` (shifted), and Return
/// — the sequence `services/inputtest` asserts.
const SEQUENCE: &[(&str, bool)] = &[
    ("a", true),
    ("a", false),
    ("shift", true),
    ("a", true),
    ("a", false),
    ("shift", false),
    ("ret", true),
    ("ret", false),
];

/// Connect to the QMP socket, complete the handshake, and inject the input
/// test key sequence.
pub fn inject_input_test_sequence(socket: &Path) -> Result<()>
{
    let stream = connect_with_retry(socket)?;
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .context("setting QMP read timeout")?;
    let mut writer = stream.try_clone().context("cloning QMP stream")?;
    let mut reader = BufReader::new(stream);

    // QMP greeting banner (one line) precedes the capabilities handshake.
    read_line(&mut reader).context("reading QMP greeting")?;

    send(&mut writer, r#"{"execute":"qmp_capabilities"}"#)?;
    read_response(&mut reader).context("qmp_capabilities handshake")?;

    for &(qcode, down) in SEQUENCE
    {
        // Omit the `device` argument: in headless mode virtio-keyboard is the
        // sole keyboard, so the event routes to it unambiguously.
        let msg = format!(
            r#"{{"execute":"input-send-event","arguments":{{"events":[{{"type":"key","data":{{"down":{down},"key":{{"type":"qcode","data":"{qcode}"}}}}}}]}}}}"#
        );
        send(&mut writer, &msg)?;
        read_response(&mut reader)
            .with_context(|| format!("input-send-event {qcode} down={down}"))?;
    }

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

fn send(writer: &mut UnixStream, json: &str) -> Result<()>
{
    writer.write_all(json.as_bytes()).context("QMP write")?;
    writer.write_all(b"\n").context("QMP write newline")?;
    writer.flush().context("QMP flush")?;
    Ok(())
}

/// Read QMP lines until a command result (`return` or `error`), skipping
/// asynchronous `event` lines.
fn read_response(reader: &mut BufReader<UnixStream>) -> Result<()>
{
    for _ in 0..64
    {
        let line = read_line(reader)?;
        if line.contains("\"error\"")
        {
            bail!("QMP error: {}", line.trim());
        }
        if line.contains("\"return\"")
        {
            return Ok(());
        }
        // Otherwise an asynchronous event; keep reading.
    }
    bail!("QMP: no command result after 64 lines")
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
