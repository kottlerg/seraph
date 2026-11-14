// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/guest.rs

//! A QEMU process a host harness drives, and the thread reading its serial
//! output: over QMP, the VMGENID snapshot-resume test and the ACPI table
//! capture; over the gdbstub, the interrupts-off wedge test.

use std::io::BufReader;
use std::process::Child;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail};

/// One QEMU instance and the thread reading its serial output.
///
/// Dropping a `Guest` kills QEMU, reaps it, and joins the reader, so every
/// exit path of a harness, an early `?` return included, releases the
/// process and the raw disk image's write lock it holds; `std::process::Child`
/// does not kill on drop, and an orphaned QEMU would hold that lock past the
/// run, blocking the next boot that opens the image. The error paths
/// therefore return without an explicit shutdown.
pub struct Guest
{
    child: Child,
    lines: mpsc::Receiver<String>,
    reader: Option<thread::JoinHandle<()>>,
}

impl Drop for Guest
{
    fn drop(&mut self)
    {
        self.teardown();
    }
}

impl Guest
{
    /// Kill QEMU, reap it, and join the reader thread. Idempotent: a
    /// second call (the drop after an explicit one) finds the child
    /// reaped and the reader joined.
    fn teardown(&mut self)
    {
        // Best-effort: both calls fail harmlessly when QEMU has already
        // exited and been reaped (after `wait_exit`), and a drop has no
        // caller to report to.
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(r) = self.reader.take()
        {
            let _ = r.join();
        }
    }

    /// Wrap a spawned child whose stdout is piped, starting the thread that
    /// reads its serial lines.
    ///
    /// # Errors
    ///
    /// Fails when the child's stdout was not piped; the child is then
    /// killed and reaped before returning, so it is not orphaned.
    pub fn from_child(mut child: Child) -> Result<Self>
    {
        let Some(stdout) = child.stdout.take()
        else
        {
            let _ = child.kill();
            let _ = child.wait();
            bail!("QEMU stdout unavailable");
        };

        // Read serial on a worker thread so the caller can enforce timeouts
        // via recv_timeout (std pipes have no read deadline).
        let (tx, rx) = mpsc::channel::<String>();
        let reader = thread::spawn(move || {
            let buf = BufReader::new(stdout);
            for line in std::io::BufRead::lines(buf)
            {
                let Ok(l) = line
                else
                {
                    break;
                };
                if tx.send(l).is_err()
                {
                    break;
                }
            }
        });

        Ok(Self {
            child,
            lines: rx,
            reader: Some(reader),
        })
    }

    /// Echo serial lines until every marker has appeared (in any order) or
    /// `timeout` passes.
    pub fn wait_for_markers(&mut self, markers: &[&str], timeout: Duration) -> Result<()>
    {
        let start = Instant::now();
        let mut pending: Vec<&str> = markers.to_vec();
        loop
        {
            let line = self.next_line(timeout.saturating_sub(start.elapsed()), &pending)?;
            pending.retain(|m| !line.contains(m));
            if pending.is_empty()
            {
                return Ok(());
            }
        }
    }

    /// Echo serial lines until one line holds any of `markers` or `timeout`
    /// passes.
    pub fn wait_for_any(&mut self, markers: &[&str], timeout: Duration) -> Result<()>
    {
        let start = Instant::now();
        loop
        {
            let line = self.next_line(timeout.saturating_sub(start.elapsed()), markers)?;
            if markers.iter().any(|m| line.contains(m))
            {
                return Ok(());
            }
        }
    }

    /// Echo serial lines until one holds `marker` or `timeout` passes, and
    /// return every line read, the marker's last.
    pub fn collect_until(&mut self, marker: &str, timeout: Duration) -> Result<Vec<String>>
    {
        let start = Instant::now();
        let mut lines = Vec::new();
        loop
        {
            let line = self.next_line(timeout.saturating_sub(start.elapsed()), &[marker])?;
            let done = line.contains(marker);
            lines.push(line);
            if done
            {
                return Ok(lines);
            }
        }
    }

    /// The next serial line, echoed, waiting at most `remaining`; the error
    /// names the `markers` still awaited.
    fn next_line(&self, remaining: Duration, markers: &[&str]) -> Result<String>
    {
        if remaining.is_zero()
        {
            bail!("timed out waiting for markers: {markers:?}");
        }
        let Ok(line) = self.lines.recv_timeout(remaining)
        else
        {
            bail!("serial stream ended waiting for markers: {markers:?}");
        };
        println!("{line}");
        Ok(line)
    }

    /// Kill QEMU and reap it now rather than at the end of scope (the
    /// teardown is [`Guest::teardown`], which `Drop` runs).
    pub fn shutdown(self)
    {
        drop(self);
    }

    /// Wait for the process to exit on its own (post-`quit`). On a timeout
    /// or a `try_wait` error the process is killed and reaped as `self`
    /// drops.
    pub fn wait_exit(mut self, timeout: Duration) -> Result<()>
    {
        let start = Instant::now();
        loop
        {
            if self
                .child
                .try_wait()
                .context("waiting for QEMU exit")?
                .is_some()
            {
                if let Some(r) = self.reader.take()
                {
                    let _ = r.join();
                }
                return Ok(());
            }
            if start.elapsed() >= timeout
            {
                bail!("QEMU did not exit within {}s after quit", timeout.as_secs());
            }
            thread::sleep(Duration::from_millis(100));
        }
    }
}

#[cfg(test)]
mod tests
{
    use std::io::Write as _;
    use std::process::{Command, Stdio};

    use super::*;

    /// A `cat` stand-in for QEMU: it runs until its stdin reaches EOF, and
    /// the test holds the write end in `child.stdin`. A broken teardown
    /// therefore cannot leave it on the host: dropping the `Child` closes
    /// that pipe and `cat` exits. It exits successfully only on that EOF.
    fn stand_in(stdout: Stdio) -> Child
    {
        Command::new("cat")
            .stdin(Stdio::piped())
            .stdout(stdout)
            .spawn()
            .unwrap()
    }

    /// A stand-in whose serial output is `text`, echoed by `cat`.
    fn echoing(text: &str) -> Guest
    {
        let mut child = stand_in(Stdio::piped());
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(text.as_bytes())
            .unwrap();
        Guest::from_child(child).unwrap()
    }

    #[test]
    fn teardown_kills_reaps_and_joins_a_live_guest()
    {
        let mut guest = Guest::from_child(stand_in(Stdio::piped())).unwrap();
        guest.teardown();
        // The status comes from the `Child` handle, cached by the reap: no
        // pid lookup. `None` means the child was not reaped. A success
        // status means it was never killed and only left on the stdin EOF
        // that `Child::wait` causes.
        let status = guest.child.try_wait().unwrap();
        assert!(status.is_some_and(|s| !s.success()));
        // A joined reader has returned and dropped its sender.
        assert!(matches!(
            guest.lines.try_recv(),
            Err(mpsc::TryRecvError::Disconnected)
        ));
    }

    #[test]
    fn wait_exit_fails_on_a_live_guest_past_its_deadline()
    {
        // The stand-in cannot exit while the test holds its stdin, so the
        // first poll finds it running and the zero deadline has passed.
        let guest = Guest::from_child(stand_in(Stdio::piped())).unwrap();
        assert!(guest.wait_exit(Duration::ZERO).is_err());
    }

    #[test]
    fn wait_exit_succeeds_once_the_guest_has_exited()
    {
        // Reaped through the handle first, so the first poll sees the exit
        // and no deadline is involved.
        let mut guest = Guest::from_child(stand_in(Stdio::piped())).unwrap();
        guest.child.kill().unwrap();
        guest.child.wait().unwrap();
        guest.wait_exit(Duration::ZERO).unwrap();
    }

    #[test]
    fn from_child_rejects_a_child_without_piped_stdout()
    {
        assert!(Guest::from_child(stand_in(Stdio::null())).is_err());
    }

    #[test]
    fn wait_for_any_returns_on_the_first_line_holding_one_marker()
    {
        let mut guest = echoing("firmware\n[Bds]Booting UEFI Shell\n");
        guest
            .wait_for_any(&["BdsDxe: ", "[Bds]Booting "], Duration::from_secs(10))
            .unwrap();
    }

    #[test]
    fn collect_until_returns_the_lines_through_the_marker()
    {
        let mut guest = echoing("a\nb marker\nc\n");
        let lines = guest
            .collect_until("marker", Duration::from_secs(10))
            .unwrap();
        assert_eq!(lines, ["a", "b marker"]);
        // The line after the marker is left for the next read, and a marker
        // that never comes times out.
        let rest = guest.collect_until("c", Duration::from_secs(10)).unwrap();
        assert_eq!(rest, ["c"]);
        guest
            .collect_until("d", Duration::from_millis(200))
            .unwrap_err();
    }

    #[test]
    fn wait_for_markers_needs_every_marker()
    {
        let mut guest = echoing("a\nb\n");
        guest
            .wait_for_markers(&["a", "b"], Duration::from_secs(10))
            .unwrap();
        // Nothing more arrives, so a third marker times out.
        assert!(
            guest
                .wait_for_markers(&["c"], Duration::from_millis(200))
                .is_err()
        );
    }
}
