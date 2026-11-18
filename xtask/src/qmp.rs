// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/qmp.rs

//! Minimal QMP (QEMU Machine Protocol) client for the QMP-driven tests.
//! Connects to QEMU's `-qmp unix:...` socket, completes the capabilities
//! handshake, and issues the handful of commands the harnesses need:
//! `input-send-event` (interactive-input test), `migrate` + `query-migrate`
//! and `quit` (snapshot-resume test), `stop` + `pmemsave` (the ACPI table
//! capture), `device_add` and `device_del` (the hotplug test), and
//! `system_powerdown` (the power-button test); and waits for the
//! `SHUTDOWN` event (the reboot and power-button tests) and the
//! `DEVICE_DELETED` event (the hotplug test).
//!
//! Hand-rolled (no JSON dependency): the messages are fixed strings or
//! `format!` templates, the free-form values (the migrate URI, the memory
//! dump's path) JSON-escaped by `json_string`, and responses are matched by
//! substring.
//! QMP messages are newline-delimited JSON.

use std::fmt::Write as _;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use crate::error::{Context as _, Result, bail};

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

    /// Wait up to `timeout` for QEMU's `SHUTDOWN` event and return its
    /// `reason`.
    fn wait_shutdown(&mut self, timeout: Duration) -> Result<String>
    {
        let start = Instant::now();
        loop
        {
            let left = timeout
                .checked_sub(start.elapsed())
                .filter(|left| !left.is_zero())
                .with_context(|| format!("no SHUTDOWN event within {}s", timeout.as_secs()))?;
            self.reader
                .get_ref()
                .set_read_timeout(Some(left))
                .context("setting QMP read timeout")?;
            let line = read_line(&mut self.reader).context("waiting for the SHUTDOWN event")?;
            if let Some(reason) = shutdown_reason(&line)
            {
                return Ok(reason.to_owned());
            }
        }
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

    let start = Instant::now();
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
        if start.elapsed() >= timeout
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

/// Stop the guest's vCPUs, then save `size` bytes of its physical memory
/// from `base` to `path` (`stop`, then `pmemsave`), and return once QEMU has
/// written the file. The guest is left stopped; the caller [`quit`]s it.
pub fn save_memory(socket: &Path, base: u64, size: u64, path: &Path) -> Result<()>
{
    let msg = pmemsave_command(base, size, path)?;
    let mut client = Client::connect(socket)?;
    client.send(r#"{"execute":"stop"}"#)?;
    client.read_result().context("stop")?;
    // QEMU answers once the whole file is written.
    client
        .reader
        .get_ref()
        .set_read_timeout(Some(PMEMSAVE_TIMEOUT))
        .context("setting QMP read timeout")?;
    client.send(&msg)?;
    client.read_result().context("pmemsave")?;
    Ok(())
}

/// How long `pmemsave` may take to write the guest's memory.
const PMEMSAVE_TIMEOUT: Duration = Duration::from_mins(2);

/// The QMP `pmemsave` command saving `size` bytes of guest physical memory
/// from `base` to `path`, the path JSON-escaped into the command's string
/// argument.
fn pmemsave_command(base: u64, size: u64, path: &Path) -> Result<String>
{
    Ok(format!(
        r#"{{"execute":"pmemsave","arguments":{{"val":{base},"size":{size},"filename":{}}}}}"#,
        json_string(path_str(path)?)
    ))
}

/// Connect, then wait up to `timeout` for QEMU's `SHUTDOWN` event and
/// return its `reason` (`guest-reset` for a guest reset under
/// `-no-reboot`, `guest-shutdown` for a guest power-off). Connect before
/// the guest can shut down: an event QEMU emits with no client connected is
/// lost.
pub fn wait_shutdown(socket: &Path, timeout: Duration) -> Result<String>
{
    Client::connect(socket)?.wait_shutdown(timeout)
}

/// Press the guest's power button (`system_powerdown`, the ACPI fixed
/// power-button event on q35), then wait up to `timeout` for QEMU's
/// `SHUTDOWN` event on the same connection and return its `reason`, as
/// [`wait_shutdown`] does.
pub fn powerdown(socket: &Path, timeout: Duration) -> Result<String>
{
    let mut client = Client::connect(socket)?;
    client.send(r#"{"execute":"system_powerdown"}"#)?;
    client.read_result().context("system_powerdown")?;
    client.wait_shutdown(timeout)
}

/// The `reason` of the QMP line `line` when it is the `SHUTDOWN` event;
/// `"unknown"` for a `SHUTDOWN` event without one; `None` for any other
/// line.
fn shutdown_reason(line: &str) -> Option<&str>
{
    (string_field(line, "event")? == "SHUTDOWN")
        .then(|| string_field(line, "reason").unwrap_or("unknown"))
}

/// The string value of the first `"key"` of the QMP line `line`, read up to
/// its closing quote (the values read hold no escaped quote); `None` when
/// it has none.
fn string_field<'a>(line: &'a str, key: &str) -> Option<&'a str>
{
    let (_, rest) = line.split_once(&format!("\"{key}\""))?;
    let rest = rest
        .trim_start()
        .strip_prefix(':')?
        .trim_start()
        .strip_prefix('"')?;
    rest.split_once('"').map(|(v, _)| v)
}

/// The value of a device property `device_add` sets: a JSON number, string
/// or boolean, as the property's type takes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Property<'a>
{
    /// An integer or a size (`dma_mask`, `logical_block_size`).
    Number(u64),
    /// A string, an id or an enumeration (`drive`, `disable-legacy`).
    String(&'a str),
    /// A boolean (`iommu_platform`).
    Bool(bool),
}

/// Hot-add the device `driver`, its id `id`, on the bus `bus` (a port's id),
/// with the further properties `properties`, each a name and a value.
pub fn device_add(
    socket: &Path,
    driver: &str,
    id: &str,
    bus: &str,
    properties: &[(&str, Property<'_>)],
) -> Result<()>
{
    let mut client = Client::connect(socket)?;
    client.send(&device_add_message(driver, id, bus, properties))?;
    client
        .read_result()
        .with_context(|| format!("device_add {driver} on {bus}"))?;
    Ok(())
}

/// The `device_add` command of [`device_add`].
fn device_add_message(
    driver: &str,
    id: &str,
    bus: &str,
    properties: &[(&str, Property<'_>)],
) -> String
{
    let mut arguments = format!(
        r#""driver":{},"id":{},"bus":{}"#,
        json_string(driver),
        json_string(id),
        json_string(bus)
    );
    for (name, value) in properties
    {
        let value = match *value
        {
            Property::Number(n) => n.to_string(),
            Property::String(s) => json_string(s),
            Property::Bool(b) => b.to_string(),
        };
        // Writing to a `String` cannot fail.
        let _ = write!(arguments, ",{}:{value}", json_string(name));
    }
    format!(r#"{{"execute":"device_add","arguments":{{{arguments}}}}}"#)
}

/// The `device_del` command of the device `id`.
fn device_del_message(id: &str) -> String
{
    format!(
        r#"{{"execute":"device_del","arguments":{{"id":{}}}}}"#,
        json_string(id)
    )
}

/// Ask QEMU to unplug the device `id` (`device_del`) and read its answer,
/// without waiting for the device's `DEVICE_DELETED` event: a guest that
/// loses its boot disk shuts down, and may power off before it powers the
/// slot off.
pub fn device_del_request(socket: &Path, id: &str) -> Result<()>
{
    let mut client = Client::connect(socket)?;
    client.send(&device_del_message(id))?;
    client
        .read_result()
        .with_context(|| format!("device_del {id}"))?;
    Ok(())
}

/// Ask QEMU to unplug the device `id` (`device_del`), then wait up to
/// `timeout` for its `DEVICE_DELETED` event. A device behind a native
/// hotplug port is unplugged only once the guest powers the slot off, so the
/// command returns at once and the event comes after; the one connection
/// sends the command and reads the event, so the event cannot be lost.
pub fn device_del(socket: &Path, id: &str, timeout: Duration) -> Result<()>
{
    let mut client = Client::connect(socket)?;
    client.send(&device_del_message(id))?;
    let start = Instant::now();
    let mut answered = false;
    loop
    {
        let left = timeout
            .checked_sub(start.elapsed())
            .filter(|left| !left.is_zero())
            .with_context(|| {
                format!(
                    "no DEVICE_DELETED event for {id} within {}s",
                    timeout.as_secs()
                )
            })?;
        client
            .reader
            .get_ref()
            .set_read_timeout(Some(left))
            .context("setting QMP read timeout")?;
        let line = read_line(&mut client.reader).context("waiting for the DEVICE_DELETED event")?;
        if !answered && line.contains("\"error\"")
        {
            bail!("device_del {id}: QMP error: {}", line.trim());
        }
        answered |= line.contains("\"return\"");
        if device_deleted(&line, id)
        {
            if !answered
            {
                bail!("device_del {id}: DEVICE_DELETED came before the command's answer");
            }
            return Ok(());
        }
    }
}

/// Whether the QMP line `line` is the `DEVICE_DELETED` event of the device
/// `id`; QEMU also sends the event for objects the device holds, which name
/// no `device`.
fn device_deleted(line: &str, id: &str) -> bool
{
    string_field(line, "event") == Some("DEVICE_DELETED")
        && string_field(line, "device") == Some(id)
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
        .with_context(|| format!("path {} is not UTF-8", path.display()))
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
    let mut out = String::with_capacity(s.len().saturating_add(2));
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
    fn device_add_names_the_driver_id_bus_and_properties()
    {
        assert_eq!(
            device_add_message(
                "edu",
                "hp\"0",
                "port",
                &[("dma_mask", Property::Number(0xFFFF_FFFF))]
            ),
            r#"{"execute":"device_add","arguments":{"driver":"edu","id":"hp\"0","bus":"port","dma_mask":4294967295}}"#
        );
        assert_eq!(
            device_add_message("edu", "a", "b", &[]),
            r#"{"execute":"device_add","arguments":{"driver":"edu","id":"a","bus":"b"}}"#
        );
        assert_eq!(
            device_add_message(
                "virtio-blk-pci",
                "d",
                "p",
                &[
                    ("drive", Property::String("n\"1")),
                    ("iommu_platform", Property::Bool(true)),
                    ("logical_block_size", Property::Number(512)),
                ]
            ),
            r#"{"execute":"device_add","arguments":{"driver":"virtio-blk-pci","id":"d","bus":"p","drive":"n\"1","iommu_platform":true,"logical_block_size":512}}"#
        );
    }

    #[test]
    fn device_del_names_the_device()
    {
        assert_eq!(
            device_del_message("hp\"0"),
            r#"{"execute":"device_del","arguments":{"id":"hp\"0"}}"#
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
    fn pmemsave_command_json_escapes_the_path()
    {
        let cmd = pmemsave_command(0x8000_0000, 512 << 20, Path::new("/w/\"m\".bin")).unwrap();
        assert_eq!(
            cmd,
            r#"{"execute":"pmemsave","arguments":{"val":2147483648,"size":536870912,"filename":"/w/\"m\".bin"}}"#
        );
    }

    #[test]
    fn shutdown_reason_reads_the_shutdown_event_only()
    {
        let reset = r#"{"timestamp": {"seconds": 1, "microseconds": 2}, "event": "SHUTDOWN", "data": {"guest": true, "reason": "guest-reset"}}"#;
        assert_eq!(shutdown_reason(reset), Some("guest-reset"));
        let off = r#"{"event":"SHUTDOWN","data":{"guest":true,"reason":"guest-shutdown"}}"#;
        assert_eq!(shutdown_reason(off), Some("guest-shutdown"));
        assert_eq!(
            shutdown_reason(r#"{"event": "SHUTDOWN", "data": {"guest": true}}"#),
            Some("unknown")
        );
        assert_eq!(
            shutdown_reason(
                r#"{"event": "RESET", "data": {"guest": true, "reason": "guest-reset"}}"#
            ),
            None
        );
        assert_eq!(shutdown_reason(r#"{"return": {}}"#), None);
    }

    #[test]
    fn device_deleted_reads_the_event_of_the_named_device_only()
    {
        let deleted = r#"{"timestamp": {"seconds": 1, "microseconds": 2}, "event": "DEVICE_DELETED", "data": {"device": "hotplug-edu", "path": "/machine/peripheral/hotplug-edu"}}"#;
        assert!(device_deleted(deleted, "hotplug-edu"));
        assert!(!device_deleted(deleted, "hotplug"));
        // An object the device held: no device named.
        let held = r#"{"event": "DEVICE_DELETED", "data": {"path": "/machine/peripheral/hotplug-edu/bus master[0]"}}"#;
        assert!(!device_deleted(held, "hotplug-edu"));
        assert!(!device_deleted(r#"{"return": {}}"#, "hotplug-edu"));
        assert!(!device_deleted(
            r#"{"event": "SHUTDOWN", "data": {"device": "hotplug-edu"}}"#,
            "hotplug-edu"
        ));
    }

    #[test]
    fn non_utf8_state_path_is_rejected()
    {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let path = Path::new(OsStr::from_bytes(b"/w/\xff.bin"));
        exec_save_uri(path).unwrap_err();
        exec_restore_uri(path).unwrap_err();
        pmemsave_command(0, 1, path).unwrap_err();
    }
}
