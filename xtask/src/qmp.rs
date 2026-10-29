// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/qmp.rs

//! Minimal QMP (QEMU Machine Protocol) client for the QMP-driven tests.
//! Connects to QEMU's `-qmp unix:...` socket, completes the capabilities
//! handshake, and issues the handful of commands the harnesses need:
//! `input-send-event` (interactive-input test), `migrate` + `query-migrate`
//! and `quit` (snapshot-resume test).
//!
//! Hand-rolled (no JSON dependency): the messages are built by `format!`
//! from fixed templates, the one caller-supplied free-form string (the
//! migrate URI) JSON-escaped by `json_string`, and responses are matched
//! by substring. QMP messages are newline-delimited JSON.

use std::fmt::Write as _;
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

/// `exec:` migration URI that saves the outgoing state to `state_path`
/// (`exec:cat > <path>`). QEMU runs an `exec:` command through `/bin/sh -c`,
/// so the path is shell-quoted: whitespace and shell metacharacters in it
/// reach `cat` as one literal argument.
///
/// # Errors
///
/// Fails when `state_path` is not UTF-8, since the URI is a string.
pub fn exec_save_uri(state_path: &Path) -> Result<String>
{
    Ok(format!("exec:cat > {}", shell_quote(path_str(state_path)?)))
}

/// `exec:` migration URI that restores incoming state from `state_path`
/// (`exec:cat <path>`, for `-incoming`), shell-quoted as [`exec_save_uri`]
/// quotes it.
///
/// # Errors
///
/// Fails when `state_path` is not UTF-8, since the URI is a string.
pub fn exec_restore_uri(state_path: &Path) -> Result<String>
{
    Ok(format!("exec:cat {}", shell_quote(path_str(state_path)?)))
}

/// Migrate the guest's state to `state_path` (QEMU's save-to-file recipe:
/// `migrate` with the [`exec_save_uri`] URI) and block until the migration
/// reports `completed`, or fail after `timeout`. Any path is accepted: the
/// URI is shell-quoted and then JSON-escaped into the command.
///
/// The source VM is left in QEMU's `postmigrate` runstate; the caller
/// [`quit`]s it before restoring the file elsewhere (the raw disk image
/// stays write-locked until the process exits).
pub fn migrate_to_file(socket: &Path, state_path: &Path, timeout: Duration) -> Result<()>
{
    let msg = migrate_command(state_path)?;
    let mut client = Client::connect(socket)?;
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

/// The QMP `migrate` command saving the state to `state_path`: the
/// [`exec_save_uri`] URI, JSON-escaped into the command's string argument.
fn migrate_command(state_path: &Path) -> Result<String>
{
    let uri = exec_save_uri(state_path)?;
    Ok(format!(
        r#"{{"execute":"migrate","arguments":{{"uri":{}}}}}"#,
        json_string(&uri)
    ))
}

fn path_str(path: &Path) -> Result<&str>
{
    path.to_str()
        .with_context(|| format!("state path {} is not UTF-8", path.display()))
}

/// Quote `s` as one POSIX shell word: wrapped in single quotes, inside
/// which nothing is special but the single quote itself, written `'\''`
/// (close, escaped quote, reopen).
fn shell_quote(s: &str) -> String
{
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// `s` as a JSON string literal, quotes included: `"` and `\` are
/// backslash-escaped and control characters written as `\u00XX`.
fn json_string(s: &str) -> String
{
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars()
    {
        match c
        {
            '"' => out.push_str(r#"\""#),
            '\\' => out.push_str(r"\\"),
            c if c < ' ' =>
            {
                // Writing to a `String` cannot fail.
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn exec_uris_pass_a_path_with_shell_metacharacters_as_one_word()
    {
        // Unquoted, the space splits the path, `;` ends the command, and
        // `$x` expands; the single quote must close, escape, and reopen.
        let path = Path::new("/w s/it's;$x");
        assert_eq!(
            exec_save_uri(path).unwrap(),
            r"exec:cat > '/w s/it'\''s;$x'"
        );
        assert_eq!(
            exec_restore_uri(path).unwrap(),
            r"exec:cat '/w s/it'\''s;$x'"
        );
    }

    #[test]
    fn migrate_command_json_escapes_the_uri()
    {
        // An unescaped `"` would end the JSON string early and an unescaped
        // `\` would start an escape sequence, so QEMU would reject or
        // misread the command.
        let cmd = migrate_command(Path::new("/w/\"q\"\\b\n")).unwrap();
        assert_eq!(
            cmd,
            r#"{"execute":"migrate","arguments":{"uri":"exec:cat > '/w/\"q\"\\b\u000a'"}}"#
        );
    }

    #[test]
    fn non_utf8_state_path_is_rejected()
    {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let path = Path::new(OsStr::from_bytes(b"/w/\xff.bin"));
        assert!(exec_save_uri(path).is_err());
        assert!(exec_restore_uri(path).is_err());
    }
}
