// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/commands/test/terminal.rs

//! Terminal interactive test (#111, #291). Launches QEMU (headless) with a QMP
//! control socket and the debug port, with the GDB stub staged on the
//! virtio-input driver. Waits for the guest `terminal` to print its READY
//! marker on the serial log, then runs three rounds in one boot:
//!
//! 1. **Keyboard round** — inject a known key sequence through the virtio-input
//!    driver over QMP, assert the terminal's local echo and the child's relayed
//!    output appear on the serial stream.
//! 2. **Serial RX round** — on a cleared transcript, write the same sequence to
//!    the guest UART receive path (QEMU's `-serial stdio` is bidirectional, so
//!    host stdin reaches the guest serial RX), assert the same echo + child
//!    round-trip. This proves the serial-input source (#291).
//! 3. **Input restart round** — the host kills the virtio-input driver
//!    through the GDB stub (`debug_stub::kill_held`), devmgr restarts it at the
//!    class's next ordinal, and the terminal must log that it holds the new
//!    instance; on a cleared transcript the keyboard sequence is injected again,
//!    and the round asserts the echo and the relayed child output, which only
//!    a terminal reading the new instance shows
//!    (services/devmgr/docs/responsibilities.md § Driver Restart).
//!
//! The stub holds every thread of the input driver when it attaches, so the
//! host connects at once and detaches, which releases it, and attaches again
//! for the kill.
//!
//! The verdict is computed here, not emitted by the guest: the terminal cannot
//! know the expected sequence, so the host scans the post-READY serial
//! transcript. The child is `programs/shell` (#112); the injected `help`
//! exercises a built-in whose output and the shell's `$ ` prompt are asserted
//! on serial.
//!
//! A pure runner: it does not build, and stages only the GDB stub, which it
//! removes again, repacking the disk images in the layout they had.
//! `terminal.svc` ships in the default boot set, so a plain `cargo xtask build`
//! and `mkdisk` suffice; the CI cell re-stages to drop other harness recipes
//! before this boot.

use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{ChildStdin, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use crate::error::{Context as _, Result, bail};

use crate::arch::Arch;
use crate::commands::test::cases::CaseArgs;
use crate::context::Context;
use crate::debug_stub;
use crate::disk::DiskLayout;
use crate::guest::{QemuStderr, explain_exit};
use crate::qemu::QemuDisplay;
use crate::qemu::{
    Firmware, GdbMode, InterruptRemapping, Iommu, QemuLaunchSpec, RiscvMmu, RiscvZkr, SecondDisk,
    X86Paging, X86ShadowStack, build_qemu_argv, validate_sysroot_for_launch,
};
use crate::qemu_gdb::Stub;
use crate::qmp;
use crate::socket_dir::SocketDir;
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
/// #112 requires it appears once the shell is the terminal session's leader.
const PROMPT: &str = "$ ";

/// Serial RX round (#291): bytes written to the guest UART via QEMU's
/// bidirectional `-serial stdio`. Mirrors the keyboard sequence — `help`, a
/// stray `x` erased by DEL (`0x7f`), then Enter (CR) — so the same
/// `ECHO_SUBSEQUENCE` / `CHILD_LINE` / `PROMPT` markers apply. The terminal's
/// line discipline erases the `x` before sending and translates CR→LF.
const SERIAL_INPUT: &[u8] = b"helpx\x7f\r";

/// The virtio-input driver's process name, which the GDB stub is staged on:
/// its install path, which devmgr creates it with as its `argv[0]`.
const INPUT_DRIVER: &str = "/services/drivers/virtio-input";

/// The terminal's line once it holds the input driver devmgr restarted at the
/// class's next ordinal. Kept in sync with `shared/device-tracker`.
const INPUT_REPLACED: &str = "[terminal] input driver at ordinal 1";

/// Budget for the stub's answer to the host's first request: the stub
/// answers once its look for the target at its start has ended
/// (`services/gdbstub/src/main.rs`).
const FIRST_ANSWER_TIMEOUT: Duration = Duration::from_mins(2);

/// Budget for any later answer of the stub.
const ANSWER_TIMEOUT: Duration = Duration::from_secs(20);

/// Overall wall-clock budget for boot, the three rounds, and the restart.
const TIMEOUT: Duration = Duration::from_mins(5);

/// Where the test stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Round
{
    /// Waiting for the READY marker.
    Boot,
    Keyboard,
    SerialRx,
    /// The input driver is killed; waiting for the terminal to hold the
    /// restarted one.
    Killed,
    /// The keyboard sequence again, after the restart.
    Restarted,
    Passed,
}

impl Round
{
    /// The round's name in a failure.
    fn name(self) -> &'static str
    {
        match self
        {
            Self::Boot => "boot (READY marker never seen)",
            Self::Keyboard => "keyboard round",
            Self::SerialRx => "serial round",
            Self::Killed => "input restart (the terminal never held the restarted driver)",
            Self::Restarted => "input restart round",
            Self::Passed => "none",
        }
    }
}

pub fn run(ctx: &Context, args: &CaseArgs) -> Result<()>
{
    validate_sysroot_for_launch(ctx, args.arch)?;
    // Held until the case returns, after its last QEMU has exited.
    let _host = crate::host_lock::admit_boot(ctx, &args.host, args.cpus, 1)?;
    let layout = debug_stub::stage(ctx, args.arch, INPUT_DRIVER)?;
    let tested = boot(ctx, args, layout);
    let unstaged = debug_stub::unstage(ctx, args.arch, layout);
    tested?;
    unstaged
}

/// Boot the staged images of `layout`, with `disk-data.img` as the second
/// disk when it holds the data partition, and run the rounds (see the module
/// documentation).
fn boot(ctx: &Context, args: &CaseArgs, layout: DiskLayout) -> Result<()>
{
    let firmware = Firmware::prepare(ctx, args.arch)?;
    let vars = firmware.launch_vars()?;

    let disk_path = ctx.disk_image();
    let data_image = layout.second_image(ctx);
    // Removed on every return, after QEMU is reaped below.
    let sockets = SocketDir::create()?;
    let sock_path = sockets.socket("terminal.qmp")?;
    let debug_port = crate::util::debug_port_or_free(None)?;

    let spec = QemuLaunchSpec {
        arch: args.arch,
        disk_path: &disk_path,
        disk_block_size: crate::disk::logical_block_size(&disk_path)?,
        second_disk: data_image
            .as_deref()
            .map(SecondDisk::of_image)
            .transpose()?,
        firmware_code_path: &firmware.code,
        firmware_vars_path: vars.path(),
        smm: firmware.smm,
        cpus: args.cpus,
        threads_per_core: 1,
        mem_mib: args.mem,
        display: QemuDisplay::Headless,
        gdb: GdbMode::Off,
        qmp_socket: Some(&sock_path),
        vmgenid_guid: Some("auto"),
        incoming: None,
        riscv_mmu: RiscvMmu::Sv48,
        riscv_zkr: RiscvZkr::On,
        idle_wait: crate::qemu::IdleWait::Off,
        x86_paging: X86Paging::Four,
        x86_shadow_stack: X86ShadowStack::Off,
        iommu: Iommu::Attached,
        interrupt_remapping: InterruptRemapping::for_sysroot(ctx),
        debug_port: Some(debug_port),
        test_devices: false,
        hotplug_port: None,
    };
    let qemu_args = build_qemu_argv(&spec)?;
    let qemu_binary = require_tool(args.arch.qemu_binary())?;

    step("Launching QEMU for the terminal interactive test (QMP key + serial RX injection)");
    let mut child = Command::new(&qemu_binary)
        .args(&qemu_args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("spawning {}", args.arch.qemu_binary()))?;
    let mut stderr = QemuStderr::take(&mut child);

    let stdout = child.stdout.take().context("QEMU stdout unavailable")?;
    // QEMU stdin feeds the guest UART receive path (`-serial stdio` is
    // bidirectional); the serial round writes the input sequence here.
    let qemu_stdin = child.stdin.take().context("QEMU stdin unavailable")?;

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

    let mut test = Test {
        arch: args.arch,
        qmp: &sock_path,
        debug_port,
        qemu_stdin,
        round: Round::Boot,
        transcript: String::new(),
        stub: None,
    };
    let driven = test
        .drive(&rx)
        .and_then(|()| test.passed())
        .map_err(|e| explain_exit(e, &mut child, stderr.as_mut()));

    let _ = child.kill();
    let _ = child.wait();
    let _ = reader.join();

    driven?;
    step("terminal interactive test: PASS (keyboard + serial input, input driver restart)");
    Ok(())
}

/// One boot's test: its inputs, and where it stands.
struct Test<'a>
{
    arch: Arch,
    /// The QMP socket the keys are injected through.
    qmp: &'a Path,
    /// The host port the debug port is attached on.
    debug_port: u16,
    /// The guest's serial receive line.
    qemu_stdin: ChildStdin,
    round: Round,
    /// The serial lines since the current round started.
    transcript: String,
    /// The connection to the GDB stub, once it has attached.
    stub: Option<Stub>,
}

impl Test<'_>
{
    /// Whether the rounds passed; the error names the round that did not
    /// and what its transcript shows.
    fn passed(&self) -> Result<()>
    {
        if self.round == Round::Passed
        {
            return Ok(());
        }
        let saw_child = self.transcript.contains(CHILD_LINE);
        let saw_prompt = self.transcript.contains(PROMPT);
        let saw_echo = is_subsequence(&self.transcript, ECHO_SUBSEQUENCE);
        bail!(
            "terminal interactive test: incomplete within {}s (failed at {}; \
             prompt={saw_prompt}, child output={saw_child}, local echo={saw_echo})",
            TIMEOUT.as_secs(),
            self.round.name()
        )
    }

    /// Take serial lines from `rx` until the rounds pass, the stream ends, or
    /// [`TIMEOUT`] passes. An error is a failed injection or stub request.
    fn drive(&mut self, rx: &mpsc::Receiver<String>) -> Result<()>
    {
        let start = Instant::now();
        let attached = format!("{} ({INPUT_DRIVER})", debug_stub::ATTACHED_MARKER);
        while self.round != Round::Passed
        {
            let remaining = TIMEOUT.saturating_sub(start.elapsed());
            let Ok(line) = rx.recv_timeout(remaining)
            else
            {
                return Ok(());
            };
            println!("{line}");
            if self.stub.is_none() && line.contains(&attached)
            {
                self.release_driver()?;
            }
            self.transcript.push_str(&line);
            self.transcript.push('\n');
            self.advance(&line)?;
        }
        Ok(())
    }

    /// Connect to the stub, which has attached to the input driver and
    /// holds its threads, and detach, which releases them; the stub attaches
    /// again at the next `qSupported`.
    fn release_driver(&mut self) -> Result<()>
    {
        let mut stub = Stub::connect_tcp(
            &format!("127.0.0.1:{}", self.debug_port),
            FIRST_ANSWER_TIMEOUT,
        )?;
        stub.request(b"qSupported")?;
        stub.set_answer_timeout(ANSWER_TIMEOUT)?;
        stub.expect_ok(b"D")?;
        self.stub = Some(stub);
        Ok(())
    }

    /// Act on `line`, the latest, for the current round.
    fn advance(&mut self, line: &str) -> Result<()>
    {
        let round_done = self.transcript.contains(CHILD_LINE)
            && self.transcript.contains(PROMPT)
            && is_subsequence(&self.transcript, ECHO_SUBSEQUENCE);
        match self.round
        {
            Round::Boot if line.contains(READY_MARKER) =>
            {
                self.next(Round::Keyboard);
                qmp::inject_events(self.qmp, EVENTS).context("QMP key injection failed")?;
            }
            Round::Keyboard if round_done =>
            {
                // On a fresh transcript, the same sequence on the guest UART.
                self.next(Round::SerialRx);
                self.qemu_stdin
                    .write_all(SERIAL_INPUT)
                    .and_then(|()| self.qemu_stdin.flush())
                    .context("serial RX injection failed")?;
            }
            Round::SerialRx if round_done =>
            {
                let stub = self
                    .stub
                    .as_mut()
                    .context("the GDB stub never attached to the input driver")?;
                // The stub attaches again, holding the driver, for the kill.
                stub.request(b"qSupported")?;
                let pc = debug_stub::kill_held(stub, self.arch, INPUT_DRIVER)?;
                step(&format!(
                    "terminal interactive test: moved the input driver's main thread \
                     from {pc:#x} to 0"
                ));
                self.next(Round::Killed);
            }
            Round::Killed if line.contains(INPUT_REPLACED) =>
            {
                self.next(Round::Restarted);
                qmp::inject_events(self.qmp, EVENTS).context("QMP key injection failed")?;
            }
            // The shell's prompt came before the transcript was cleared, and the
            // next one waits on a line no later output ends.
            Round::Restarted
                if self.transcript.contains(CHILD_LINE)
                    && is_subsequence(&self.transcript, ECHO_SUBSEQUENCE) =>
            {
                self.round = Round::Passed;
            }
            Round::Boot
            | Round::Keyboard
            | Round::SerialRx
            | Round::Killed
            | Round::Restarted
            | Round::Passed =>
            {}
        }
        Ok(())
    }

    /// Start `round` on a cleared transcript, so its assertions cannot be
    /// met by the output of an earlier one.
    fn next(&mut self, round: Round)
    {
        self.round = round;
        self.transcript.clear();
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
