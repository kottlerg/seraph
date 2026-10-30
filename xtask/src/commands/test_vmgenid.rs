// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/commands/test_vmgenid.rs

//! VMGENID snapshot-resume test (#395). `x86_64` only — the `riscv64` `virt`
//! machine has no VMGENID ACPI support in QEMU.
//!
//! Proves the whole-VM-snapshot reseed chain end-to-end: bootloader VGIA
//! discovery, the kernel's generation-change detection, and post-resume
//! liveness. The generation ID cannot be changed at runtime (QMP/HMP exclude
//! it by design), so the test uses QEMU's save/restore recipe:
//!
//! 1. **Boot A** with a fixed GUID `G1`; wait for the kernel's
//!    `entropy: vmgenid armed` line (bootloader discovery + kernel consumer
//!    wired) and the terminal's READY marker (system fully up).
//! 2. **Save**: QMP `migrate` to a state file, wait `completed`, `quit`
//!    (releases the raw disk image's write lock).
//! 3. **Boot B** with GUID `G2` and `-incoming exec:cat <state>`: QEMU
//!    rewrites the GUID in guest RAM at migration load, before any vCPU
//!    resumes. Assert the kernel's `entropy: VM generation change detected`
//!    line — the same GUID compare the per-draw reseed path performs.
//! 4. **Liveness round**: inject the terminal test's `help` key sequence over
//!    QMP and assert the shell's output, proving the resumed system draws
//!    randomness and schedules normally after the forced reseed.
//!
//! A pure runner like `test-terminal`: requires a populated `x86_64` sysroot
//! with the default boot set (terminal + shell) and a repacked `disk.img`.

use std::io::BufReader;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail};

use crate::arch::Arch;
use crate::cli::TestVmgenidArgs;
use crate::context::Context;
use crate::firmware::find_ovmf_code;
use crate::qemu::{
    GdbMode, QemuLaunchSpec, RiscvMmu, build_qemu_argv, validate_sysroot_for_launch,
};
use crate::qmp;
use crate::util::{require_tool, step};

/// Kernel line proving VGIA discovery reached the entropy subsystem.
const ARMED_MARKER: &str = "entropy: vmgenid armed";

/// Kernel line the BSP tick poller prints on a generation change.
const CHANGE_MARKER: &str = "entropy: VM generation change detected";

/// Guest terminal READY marker; kept in sync with `programs/terminal`.
const READY_MARKER: &str = "terminal: READY for injection";

/// Liveness key sequence and its expected shell output — the terminal test's
/// `help` round without the backspace variant.
const EVENTS: &[(&str, bool)] = &[
    ("h", true),
    ("h", false),
    ("e", true),
    ("e", false),
    ("l", true),
    ("l", false),
    ("p", true),
    ("p", false),
    ("ret", true),
    ("ret", false),
];
const CHILD_LINE: &str = "shell built-ins:";

/// Fixed, distinct generation GUIDs for the two boots.
const GUID_A: &str = "8f2b7c11-3a5d-4e69-9d0a-1c2f4b5e6a70";
const GUID_B: &str = "3d94f0a2-6b1e-47c8-8c55-0e9a2d7b4f13";

/// Wall-clock budget per boot phase.
const TIMEOUT: Duration = Duration::from_mins(3);

/// Budget for the migrate-to-file completion poll.
const MIGRATE_TIMEOUT: Duration = Duration::from_mins(2);

/// One QEMU instance and the thread reading its serial output.
///
/// Dropping a `Guest` kills QEMU, reaps it, and joins the reader, so every
/// exit path of [`run`], an early `?` return included, releases the
/// process and the raw disk image's write lock it holds; `std::process::Child`
/// does not kill on drop, and an orphaned QEMU would hold that lock past the
/// run, blocking the next boot that opens the image. The error paths
/// therefore return without an explicit shutdown.
struct Guest
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
    fn from_child(mut child: Child) -> Result<Self>
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

    fn launch(
        qemu_binary: &Path,
        ctx: &Context,
        args: &TestVmgenidArgs,
        sock_path: &Path,
        guid: &str,
        incoming: Option<&str>,
    ) -> Result<Self>
    {
        let disk_path = ctx.disk_image();
        let firmware_code = find_ovmf_code()?;
        let spec = QemuLaunchSpec {
            arch: Arch::X86_64,
            disk_path: &disk_path,
            firmware_code_path: &firmware_code,
            firmware_vars_path: None,
            cpus: args.cpus,
            mem_mib: args.mem,
            headless: true,
            gdb: GdbMode::Off,
            qmp_socket: Some(sock_path),
            vmgenid_guid: Some(guid),
            incoming,
            riscv_mmu: RiscvMmu::Sv48,
        };
        let qemu_args = build_qemu_argv(&spec)?;

        let child = Command::new(qemu_binary)
            .args(&qemu_args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .context("spawning qemu-system-x86_64")?;
        Self::from_child(child)
    }

    /// Echo serial lines until every marker has appeared (in any order) or
    /// the deadline passes.
    fn wait_for_markers(&mut self, markers: &[&str], deadline: Instant) -> Result<()>
    {
        let mut pending: Vec<&str> = markers.to_vec();
        loop
        {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero()
            {
                bail!("timed out waiting for markers: {pending:?}");
            }
            let Ok(line) = self.lines.recv_timeout(remaining)
            else
            {
                bail!("serial stream ended waiting for markers: {pending:?}");
            };
            println!("{line}");
            pending.retain(|m| !line.contains(m));
            if pending.is_empty()
            {
                return Ok(());
            }
        }
    }

    /// Kill QEMU and reap it now rather than at the end of scope (the
    /// teardown is [`Guest::teardown`], which `Drop` runs).
    fn shutdown(self)
    {
        drop(self);
    }

    /// Wait for the process to exit on its own (post-`quit`). On a timeout
    /// or a `try_wait` error the process is killed and reaped as `self`
    /// drops.
    fn wait_exit(mut self, timeout: Duration) -> Result<()>
    {
        let deadline = Instant::now() + timeout;
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
            if Instant::now() >= deadline
            {
                bail!("QEMU did not exit within {}s after quit", timeout.as_secs());
            }
            thread::sleep(Duration::from_millis(100));
        }
    }
}

pub fn run(ctx: &Context, args: &TestVmgenidArgs) -> Result<()>
{
    validate_sysroot_for_launch(ctx, Arch::X86_64)?;
    let qemu_binary = require_tool(Arch::X86_64.qemu_binary())?;

    let work_dir = ctx.target_dir.join("xtask");
    std::fs::create_dir_all(&work_dir)
        .with_context(|| format!("creating {}", work_dir.display()))?;
    let sock_a = work_dir.join("vmgenid-a-qmp.sock");
    let sock_b = work_dir.join("vmgenid-b-qmp.sock");
    let state_path = work_dir.join("vmgenid-state.bin");
    for p in [&sock_a, &sock_b, &state_path]
    {
        let _ = std::fs::remove_file(p);
    }

    // Built before boot A so a path the URI cannot carry fails up front.
    let incoming = qmp::exec_restore_uri(&state_path)?;

    // ── Boot A: fixed GUID, wait until fully up ─────────────────────────────
    step("vmgenid test: boot A (source) — waiting for armed + READY markers");
    // Every `?` below drops the live `Guest`, which kills and reaps its QEMU
    // (see `Guest`).
    let mut guest_a = Guest::launch(&qemu_binary, ctx, args, &sock_a, GUID_A, None)?;
    guest_a
        .wait_for_markers(&[ARMED_MARKER, READY_MARKER], Instant::now() + TIMEOUT)
        .context("boot A")?;

    // ── Save: migrate to file, then quit to release the disk lock ──────────
    step("vmgenid test: migrating state to file");
    qmp::migrate_to_file(&sock_a, &state_path, MIGRATE_TIMEOUT).context("migrate to file")?;
    qmp::quit(&sock_a).context("quitting source QEMU")?;
    guest_a.wait_exit(Duration::from_secs(30))?;

    // ── Boot B: new GUID, restore the state, assert detection ──────────────
    step("vmgenid test: boot B (restore with new GUID) — waiting for detection");
    let mut guest_b = Guest::launch(&qemu_binary, ctx, args, &sock_b, GUID_B, Some(&incoming))?;
    guest_b
        .wait_for_markers(&[CHANGE_MARKER], Instant::now() + TIMEOUT)
        .context("generation-change detection after restore")?;

    // ── Liveness: the resumed guest still draws and schedules ───────────────
    step("vmgenid test: post-resume liveness round (help via QMP)");
    qmp::inject_events(&sock_b, EVENTS).context("QMP key injection after resume")?;
    let live = guest_b.wait_for_markers(&[CHILD_LINE], Instant::now() + TIMEOUT);
    guest_b.shutdown();
    let _ = std::fs::remove_file(&state_path);
    for p in [&sock_a, &sock_b]
    {
        let _ = std::fs::remove_file(p);
    }
    live.context("post-resume liveness round")?;

    step("vmgenid snapshot-resume test: PASS (detection + post-resume liveness)");
    Ok(())
}

#[cfg(test)]
mod tests
{
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
        assert!(guest.wait_exit(Duration::ZERO).is_ok());
    }

    #[test]
    fn from_child_rejects_a_child_without_piped_stdout()
    {
        assert!(Guest::from_child(stand_in(Stdio::null())).is_err());
    }
}
