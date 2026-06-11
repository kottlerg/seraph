// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// commands/test_terminal.rs

//! Terminal interactive test (#111, #291). Launches QEMU (headless) with a QMP
//! control socket, waits for the guest `terminal` to print its READY marker on
//! the serial log, then exercises both input sources in one boot:
//!
//! 1. **Keyboard round** — inject a known key sequence through the virtio-input
//!    driver over QMP, assert the terminal's local echo and the child's relayed
//!    output appear on the serial stream.
//! 2. **Serial RX round** — on a cleared transcript, write the same sequence to
//!    the guest UART receive path (QEMU's `-serial stdio` is bidirectional, so
//!    host stdin reaches the guest serial RX), assert the same echo + child
//!    round-trip. This proves the serial-input source (#291).
//!
//! The verdict is computed here, not emitted by the guest: the terminal cannot
//! know the expected sequence, so the host scans the post-READY serial
//! transcript. The child is `programs/shell` (#112); the injected `help`
//! exercises a built-in whose output and the shell's `$ ` prompt are asserted
//! on serial.
//!
//! A pure runner: it neither builds nor stages. `terminal.svc` ships in the
//! default boot set, so a plain `cargo xtask build` + `mkdisk` suffices; the CI
//! cell re-stages to drop other harness recipes before this boot.

use std::io::{BufRead, BufReader, Write};
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
    GdbMode, QemuLaunchSpec, build_qemu_argv, prepare_riscv_firmware, validate_sysroot_for_launch,
};
use crate::qmp;
use crate::util::{require_tool, step};

/// Marker the guest `terminal` prints once it holds every driver cap and the
/// keyboard thread is running. Kept in sync with `programs/terminal`.
const READY_MARKER: &str = "terminal: READY for injection";

/// Injected key events as `(qcode, down)`: types `help`, then a stray `x`
/// dropped by Backspace, then Enter. After the line discipline the child
/// receives `help\n`. This covers the keysym decode (lowercase letters,
/// Return), single-line backspace (the `x` is erased before send), and CR→LF,
/// end-to-end through the real driver and the terminal.
const EVENTS: &[(&str, bool)] = &[
    ("h", true),
    ("h", false),
    ("e", true),
    ("e", false),
    ("l", true),
    ("l", false),
    ("p", true),
    ("p", false),
    ("x", true),
    ("x", false),
    ("backspace", true),
    ("backspace", false),
    ("ret", true),
    ("ret", false),
];

/// Child output marker. Its presence proves the full loop: keyboard input
/// reached the shell (the typed `help`), single-line backspace dropped the `x`
/// before send, CR→LF delivered the line, the shell ran the `help` built-in,
/// and its stdout was relayed back to serial. The shell writes the help block
/// in one `write_all`, so this first line lands contiguously.
const CHILD_LINE: &str = "shell built-ins:";

/// Local-echo proof: each typed key-down is echoed to serial as its own write,
/// so the characters appear (interleaving-tolerant) as this subsequence —
/// including the `x` typed before the backspace erased it from the line.
const ECHO_SUBSEQUENCE: &str = "helpx";

/// The shell's prompt, rendered to serial via the terminal. Acceptance for
/// #112 requires it appears once the shell is the terminal's child.
const PROMPT: &str = "$ ";

/// Serial RX round (#291): bytes written to the guest UART via QEMU's
/// bidirectional `-serial stdio`. Mirrors the keyboard sequence — `help`, a
/// stray `x` erased by DEL (`0x7f`), then Enter (CR) — so the same
/// `ECHO_SUBSEQUENCE` / `CHILD_LINE` / `PROMPT` markers apply. The terminal's
/// line discipline erases the `x` before sending and translates CR→LF.
const SERIAL_INPUT: &[u8] = b"helpx\x7f\r";

/// Overall wall-clock budget for boot + inject + assert.
const TIMEOUT: Duration = Duration::from_mins(3);

// too_many_lines: a linear QMP-driven test (boot, wait for READY, inject keys
// and serial RX, assert echoed markers). Splitting the sequential assertions
// would obscure the flow without reducing complexity.
#[allow(clippy::too_many_lines)]
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
        mem_mib: args.mem,
        headless: true,
        gdb: GdbMode::Off,
        qmp_socket: Some(&sock_path),
    };
    let qemu_args = build_qemu_argv(&spec)?;
    let qemu_binary = require_tool(args.arch.qemu_binary())?;

    step("Launching QEMU for the terminal interactive test (QMP key + serial RX injection)");
    let mut child = Command::new(&qemu_binary)
        .args(&qemu_args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| format!("spawning {}", args.arch.qemu_binary()))?;

    let stdout = child.stdout.take().context("QEMU stdout unavailable")?;
    // QEMU stdin feeds the guest UART receive path (`-serial stdio` is
    // bidirectional); the serial round writes the input sequence here.
    let mut qemu_stdin = child.stdin.take().context("QEMU stdin unavailable")?;

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
    // Two input rounds in one boot. `ready` gates the first injection on the
    // READY marker; `kbd_pass` gates the keyboard→serial transition. The
    // transcript is cleared between rounds so the serial round's assertions
    // cannot be satisfied by leftover keyboard output.
    let mut ready = false;
    let mut kbd_pass = false;
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
        let Ok(line) = rx.recv_timeout(remaining)
        else
        {
            break;
        };
        println!("{line}");

        if !ready
        {
            if line.contains(READY_MARKER)
            {
                ready = true;
                if let Err(e) = qmp::inject_events(&sock_path, EVENTS)
                {
                    inject_err = Some(e.context("QMP key injection failed"));
                    break;
                }
            }
            continue;
        }

        transcript.push_str(&line);
        transcript.push('\n');
        let round_done = transcript.contains(CHILD_LINE)
            && transcript.contains(PROMPT)
            && is_subsequence(&transcript, ECHO_SUBSEQUENCE);
        if !round_done
        {
            continue;
        }
        if kbd_pass
        {
            // Serial round passed too: both input sources verified.
            verdict = Some(true);
            break;
        }
        // Keyboard round passed; start the serial round on a fresh transcript by
        // writing the same sequence to the guest UART receive path.
        kbd_pass = true;
        transcript.clear();
        if let Err(e) = qemu_stdin
            .write_all(SERIAL_INPUT)
            .and_then(|()| qemu_stdin.flush())
        {
            inject_err = Some(anyhow::Error::new(e).context("serial RX injection failed"));
            break;
        }
    }

    let _ = child.kill();
    let _ = child.wait();
    let _ = reader.join();
    let _ = std::fs::remove_file(&sock_path);

    if let Some(e) = inject_err
    {
        return Err(e);
    }
    if verdict == Some(true)
    {
        step("terminal interactive test: PASS (keyboard + serial input)");
        return Ok(());
    }
    let phase = if !ready
    {
        "boot (READY marker never seen)"
    }
    else if !kbd_pass
    {
        "keyboard round"
    }
    else
    {
        "serial round"
    };
    let saw_child = transcript.contains(CHILD_LINE);
    let saw_prompt = transcript.contains(PROMPT);
    let saw_echo = is_subsequence(&transcript, ECHO_SUBSEQUENCE);
    bail!(
        "terminal interactive test: incomplete within {}s (failed at {phase}; \
         prompt={saw_prompt}, child output={saw_child}, local echo={saw_echo})",
        TIMEOUT.as_secs()
    )
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
