// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// commands/test_terminal.rs

//! Terminal interactive test (#111). Launches QEMU (headless) with a QMP
//! control socket, waits for the guest `terminal` to print its READY marker on
//! the serial log, injects a known key sequence through the virtio-input
//! driver, then asserts — host-side — that both the terminal's local echo and
//! the child's relayed output appear on the serial stream.
//!
//! The verdict is computed here, not emitted by the guest: the terminal cannot
//! know the expected sequence, so the host scans the post-READY serial
//! transcript. This is the reusable pattern for interactive
//! programs (the `programs/shell` test under #112 reuses it by swapping the
//! child and the expected strings).
//!
//! A pure runner: it neither builds nor stages. `terminal.svc` ships in the
//! default boot set, so a plain `cargo xtask build` + `mkdisk` suffices; the CI
//! cell re-stages to drop other harness recipes before this boot.

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail};

use crate::arch::Arch;
use crate::cli::TestTerminalArgs;
use crate::context::Context;
use crate::firmware::find_ovmf_code;
use crate::qemu::{
    QemuLaunchSpec, build_qemu_argv, prepare_riscv_firmware, validate_sysroot_for_launch,
};
use crate::qmp;
use crate::util::{require_tool, step};

/// Marker the guest `terminal` prints once it holds every driver cap and the
/// keyboard thread is running. Kept in sync with `programs/terminal`.
const READY_MARKER: &str = "terminal: READY for injection";

/// Injected key events as `(qcode, down)`: `a`, then Shift+`a` (→ `A`,
/// exercising modifier-applied decode and modifier-event filtering), then `b`,
/// then Backspace (drops the `b`), then Enter. After the line discipline the
/// child receives `aA\n`. This covers the keysym-decode cases — lowercase,
/// shifted uppercase, modifier-event filtering, Return — plus backspace and
/// CR→LF, end-to-end through the real driver and the terminal.
const EVENTS: &[(&str, bool)] = &[
    ("a", true),
    ("a", false),
    ("shift", true),
    ("a", true),
    ("a", false),
    ("shift", false),
    ("b", true),
    ("b", false),
    ("backspace", true),
    ("backspace", false),
    ("ret", true),
    ("ret", false),
];

/// Child output line. Its presence proves the full loop: keyboard input reached
/// the child (incl. the Shift-decoded `A`), modifier events were filtered (no
/// stray bytes corrupting the line), single-line backspace dropped the `b`
/// before send, CR→LF delivered the line, and the child's stdout was relayed
/// back to serial. The driver writes it as one `SERIAL_WRITE_BYTES` call, so it
/// lands contiguously.
const CHILD_LINE: &str = "[echosh] aA";

/// Local-echo proof: each typed key-down is echoed to serial as its own write,
/// so the characters appear (interleaving-tolerant) as this subsequence —
/// including the `b` typed before the backspace erased it from the line.
const ECHO_SUBSEQUENCE: &str = "aAb";

/// Overall wall-clock budget for boot + inject + assert.
const TIMEOUT: Duration = Duration::from_secs(180);

pub fn run(ctx: &Context, args: &TestTerminalArgs) -> Result<()>
{
    validate_sysroot_for_launch(ctx, args.arch)?;

    let (firmware_code, firmware_vars) = match args.arch
    {
        Arch::X86_64 => (find_ovmf_code()?, None),
        Arch::Riscv64 =>
        {
            let (code, vars) = prepare_riscv_firmware(ctx)?;
            (code, Some(vars))
        }
    };

    let disk_path = ctx.disk_image();
    let sock_dir = ctx.target_dir.join("xtask");
    std::fs::create_dir_all(&sock_dir)
        .with_context(|| format!("creating {}", sock_dir.display()))?;
    let sock_path = sock_dir.join("terminal-test-qmp.sock");
    let _ = std::fs::remove_file(&sock_path);

    let spec = QemuLaunchSpec {
        arch: args.arch,
        disk_path: &disk_path,
        firmware_code_path: &firmware_code,
        firmware_vars_path: firmware_vars.as_deref(),
        cpus: args.cpus,
        headless: true,
        gdb: false,
        qmp_socket: Some(&sock_path),
    };
    let qemu_args = build_qemu_argv(&spec);
    let qemu_binary = require_tool(args.arch.qemu_binary())?;

    step("Launching QEMU for the terminal interactive test (QMP key injection)");
    let mut child = Command::new(&qemu_binary)
        .args(&qemu_args)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| format!("spawning {}", args.arch.qemu_binary()))?;

    let stdout = child.stdout.take().context("QEMU stdout unavailable")?;

    // Read serial on a worker thread so the main thread can enforce the overall
    // timeout via recv_timeout (std pipes have no read deadline).
    let (tx, rx) = mpsc::channel::<String>();
    let reader = thread::spawn(move || {
        let buf = BufReader::new(stdout);
        for line in buf.lines()
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

    let deadline = Instant::now() + TIMEOUT;
    let mut injected = false;
    let mut transcript = String::new();
    let mut verdict: Option<bool> = None;
    let mut inject_err: Option<anyhow::Error> = None;

    loop
    {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero()
        {
            break;
        }
        match rx.recv_timeout(remaining)
        {
            Ok(line) =>
            {
                println!("{line}");
                if injected
                {
                    transcript.push_str(&line);
                    transcript.push('\n');
                    if transcript.contains(CHILD_LINE)
                        && is_subsequence(&transcript, ECHO_SUBSEQUENCE)
                    {
                        verdict = Some(true);
                        break;
                    }
                }
                else if line.contains(READY_MARKER)
                {
                    injected = true;
                    if let Err(e) = qmp::inject_events(&sock_path, EVENTS)
                    {
                        inject_err = Some(e);
                        break;
                    }
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout | mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }

    let _ = child.kill();
    let _ = child.wait();
    let _ = reader.join();
    let _ = std::fs::remove_file(&sock_path);

    if let Some(e) = inject_err
    {
        return Err(e.context("QMP key injection failed"));
    }
    match verdict
    {
        Some(true) =>
        {
            step("terminal interactive test: PASS");
            Ok(())
        }
        Some(false) => bail!("terminal interactive test: assertion failed"),
        None =>
        {
            let saw_child = transcript.contains(CHILD_LINE);
            let saw_echo = is_subsequence(&transcript, ECHO_SUBSEQUENCE);
            bail!(
                "terminal interactive test: incomplete within {}s \
                 (ready+inject={injected}, child output={saw_child}, local echo={saw_echo})",
                TIMEOUT.as_secs()
            )
        }
    }
}

/// Whether `needle`'s characters appear in `haystack` in order, not
/// necessarily contiguously — tolerates logd output interleaving with the
/// terminal's per-keypress single-byte echoes on the shared serial stream.
fn is_subsequence(haystack: &str, needle: &str) -> bool
{
    let mut hay = haystack.chars();
    'outer: for nc in needle.chars()
    {
        for hc in hay.by_ref()
        {
            if hc == nc
            {
                continue 'outer;
            }
        }
        return false;
    }
    true
}
