// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/guest.rs

//! A QEMU process a host harness drives, and the thread reading its serial
//! output: over QMP, the VMGENID snapshot-resume test and the ACPI table
//! capture; over the gdbstub, the interrupts-off wedge test and the CET
//! shadow-stack test.
//!
//! It also holds what every harness that spawns QEMU reports when QEMU exits
//! under it ([`QemuStderr`], [`explain_exit`]): a QEMU that refuses its
//! command line exits before the first serial line, and the harness's own
//! error (a marker that never came, a stream that ended) does not name why.

use std::collections::VecDeque;
use std::io::BufReader;
use std::process::Child;
use std::sync::{Arc, Mutex, PoisonError, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use crate::error::{Context as _, Error, Result, bail};
use crate::qemu::LaunchVars;

/// How long [`explain_exit`] waits for QEMU to exit. A stream that ended is
/// QEMU exiting, which takes it well under this; a QEMU still running past it
/// failed the harness some other way.
const EXIT_GRACE: Duration = Duration::from_secs(2);

/// The most lines of QEMU's stderr [`explain_exit`] quotes: QEMU's refusal
/// of its command line is one, and a longer stderr is on the terminal.
const STDERR_TAIL: usize = 10;

/// QEMU's stderr, piped: echoed to the host's stderr as it arrives, as an
/// inherited stderr would be, with its last [`STDERR_TAIL`] lines kept for
/// [`explain_exit`].
pub struct QemuStderr
{
    tail: Arc<Mutex<VecDeque<String>>>,
    reader: Option<thread::JoinHandle<()>>,
}

impl QemuStderr
{
    /// Take `child`'s stderr and start the thread that reads it; `None`
    /// when the stderr was not piped (inherited, a file, or null).
    pub fn take(child: &mut Child) -> Option<Self>
    {
        let stderr = child.stderr.take()?;
        let tail = Arc::new(Mutex::new(VecDeque::with_capacity(STDERR_TAIL)));
        let kept = Arc::clone(&tail);
        let reader = thread::spawn(move || {
            for line in std::io::BufRead::lines(BufReader::new(stderr))
            {
                let Ok(l) = line
                else
                {
                    break;
                };
                eprintln!("{l}");
                let mut kept = kept.lock().unwrap_or_else(PoisonError::into_inner);
                if kept.len() == STDERR_TAIL
                {
                    kept.pop_front();
                }
                kept.push_back(l);
            }
        });
        Some(Self {
            tail,
            reader: Some(reader),
        })
    }

    /// Join the reader, which returns at the stream's end once QEMU has
    /// exited, and return the lines kept, oldest first.
    fn finish(&mut self) -> Vec<String>
    {
        if let Some(r) = self.reader.take()
        {
            let _ = r.join();
        }
        self.tail
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .cloned()
            .collect()
    }
}

/// `err`, a harness's failure while `child` (QEMU) ran, with QEMU's exit
/// added as its context when QEMU exits within [`EXIT_GRACE`]: the exit
/// status and, from `stderr` when QEMU's stderr was piped, its last lines,
/// which name why QEMU stopped (a socket path it refused, a device it
/// lacks). `err` is returned unchanged when QEMU still runs, since its
/// failure is then the harness's own.
pub fn explain_exit(err: Error, child: &mut Child, stderr: Option<&mut QemuStderr>) -> Error
{
    explain_exit_within(err, child, stderr, EXIT_GRACE)
}

/// [`explain_exit`], waiting at most `grace` for the exit.
fn explain_exit_within(
    err: Error,
    child: &mut Child,
    stderr: Option<&mut QemuStderr>,
    grace: Duration,
) -> Error
{
    let start = Instant::now();
    let status = loop
    {
        match child.try_wait()
        {
            Ok(Some(status)) => break status,
            Ok(None) if start.elapsed() < grace => thread::sleep(Duration::from_millis(20)),
            Ok(None) => return err,
            Err(e) => return err.context(format!("waiting for QEMU's exit failed: {e}")),
        }
    };
    let tail = stderr.map_or_default(QemuStderr::finish);
    if tail.is_empty()
    {
        err.context(format!("QEMU exited ({status})"))
    }
    else
    {
        err.context(format!(
            "QEMU exited ({status}); its stderr ends:\n{}",
            tail.join("\n")
        ))
    }
}

/// One QEMU instance and the thread reading its serial output.
///
/// Dropping a `Guest` kills QEMU, reaps it, and joins the reader, so every
/// exit path of a harness, an early `?` return included, releases the
/// process and the raw disk image's write lock it holds; `std::process::Child`
/// does not kill on drop, and an orphaned QEMU would hold that lock past the
/// run, blocking the next boot that opens the image. The error paths
/// therefore return without an explicit shutdown. The launch's variable store
/// ([`Guest::holding`]) is removed after QEMU is reaped.
pub struct Guest
{
    child: Child,
    lines: mpsc::Receiver<String>,
    reader: Option<thread::JoinHandle<()>>,
    /// QEMU's stderr, when the child's was piped.
    stderr: Option<QemuStderr>,
    /// Declared last: dropped after `Drop::drop` has reaped QEMU.
    vars: Option<LaunchVars>,
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
        if let Some(stderr) = self.stderr.as_mut()
        {
            stderr.finish();
        }
    }

    /// Wrap a spawned child whose stdout is piped, starting the thread that
    /// reads its serial lines, and the one that reads its stderr when that is
    /// piped too ([`QemuStderr`]).
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
            stderr: QemuStderr::take(&mut child),
            child,
            lines: rx,
            reader: Some(reader),
            vars: None,
        })
    }

    /// Keep `vars`, the variable store QEMU was launched on, until QEMU is
    /// reaped: QEMU opens it after the spawn returns.
    #[must_use]
    pub fn holding(mut self, vars: LaunchVars) -> Self
    {
        self.vars = Some(vars);
        self
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
        self.collect_until_any(&[marker], timeout)
    }

    /// Echo serial lines until one holds any of `markers` or `timeout`
    /// passes, and return every line read, that line last.
    pub fn collect_until_any(&mut self, markers: &[&str], timeout: Duration)
    -> Result<Vec<String>>
    {
        let start = Instant::now();
        let mut lines = Vec::new();
        loop
        {
            let line = self.next_line(timeout.saturating_sub(start.elapsed()), markers)?;
            let done = markers.iter().any(|m| line.contains(m));
            lines.push(line);
            if done
            {
                return Ok(lines);
            }
        }
    }

    /// The next serial line, echoed, waiting at most `remaining`; the error
    /// names the `markers` still awaited, and QEMU's exit when the stream
    /// ended with it ([`explain_exit`]).
    fn next_line(&mut self, remaining: Duration, markers: &[&str]) -> Result<String>
    {
        if remaining.is_zero()
        {
            bail!("timed out waiting for markers: {markers:?}");
        }
        let Ok(line) = self.lines.recv_timeout(remaining)
        else
        {
            let err = crate::error::err!("serial stream ended waiting for markers: {markers:?}");
            return Err(explain_exit(err, &mut self.child, self.stderr.as_mut()));
        };
        println!("{line}");
        Ok(line)
    }

    /// Echo serial lines until the stream ends, as QEMU's exit ends it, or
    /// `timeout` passes; whether it ended.
    pub fn echo_until_end(&mut self, timeout: Duration) -> bool
    {
        let start = Instant::now();
        loop
        {
            match self
                .lines
                .recv_timeout(timeout.saturating_sub(start.elapsed()))
            {
                Ok(line) => println!("{line}"),
                Err(mpsc::RecvTimeoutError::Disconnected) => return true,
                Err(mpsc::RecvTimeoutError::Timeout) => return false,
            }
        }
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

    /// A stand-in for a QEMU that refuses its command line: `script` run by
    /// `sh`, its stdout and stderr piped.
    fn exiting(script: &str) -> Guest
    {
        let child = Command::new("sh")
            .args(["-c", script])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        Guest::from_child(child).unwrap()
    }

    // Defect caught: a QEMU that exits before its first serial line reported
    // as a marker that never came, without its exit or its refusal.
    #[test]
    fn a_guest_that_exits_before_a_marker_is_reported_with_its_status_and_stderr()
    {
        let mut guest = exiting("echo 'UNIX socket path is too long' >&2; exit 3");
        let err = guest
            .wait_for_any(&["READY"], Duration::from_secs(30))
            .unwrap_err();
        let report = format!("{err:#}");
        assert!(report.contains("exit status: 3"), "{report}");
        assert!(report.contains("UNIX socket path is too long"), "{report}");
        assert!(report.contains("READY"), "{report}");
    }

    // Defect caught: a harness failure while QEMU still runs (its own
    // timeout, a refused request) reported as an exit.
    #[test]
    fn a_failure_while_qemu_runs_is_left_as_it_is()
    {
        // The stand-in cannot exit while the test holds its stdin.
        let mut child = stand_in(Stdio::null());
        let err = explain_exit_within(
            crate::error::err!("no answer"),
            &mut child,
            None,
            Duration::ZERO,
        );
        assert_eq!(format!("{err:#}"), "no answer");
        child.kill().unwrap();
        child.wait().unwrap();
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
