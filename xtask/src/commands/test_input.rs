// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! commands/test_input.rs
//!
//! virtio-input interactive smoke test. Launches QEMU (headless) with a QMP
//! control socket, waits for the guest `inputtest` service to print its READY
//! marker on the serial log, injects a known key sequence via QMP, then asserts
//! the guest reports the harness pass marker.
//!
//! A pure runner: it neither builds nor stages. The `inputtest` recipe must be
//! staged into `sysroot/config/svcmgr/services/` and `disk.img` repacked
//! (`cargo xtask mkdisk`) beforehand — see xtask/README.md and the CI input
//! cell.

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail};

use crate::arch::Arch;
use crate::cli::TestInputArgs;
use crate::context::Context;
use crate::firmware::find_ovmf_code;
use crate::qemu::{
    QemuLaunchSpec, build_qemu_argv, prepare_riscv_firmware, validate_sysroot_for_launch,
};
use crate::qmp;
use crate::util::{require_tool, step};

/// Marker the guest `inputtest` prints once it holds the input cap and is about
/// to block on its first read. Kept in sync with `services/inputtest`.
const READY_MARKER: &str = "inputtest: READY for injection";
/// Harness pass/fail markers (testing.md); the guest registers the name
/// `inputtest`, so the full lines read `[inputtest] ALL TESTS PASSED` etc.
const PASS_MARKER: &str = "ALL TESTS PASSED";
const FAIL_MARKER: &str = "SOME TESTS FAILED";

/// Overall wall-clock budget for boot + inject + assert.
const TIMEOUT: Duration = Duration::from_secs(180);

pub fn run(ctx: &Context, args: &TestInputArgs) -> Result<()>
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
    let sock_path = sock_dir.join("input-test-qmp.sock");
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

    step("Launching QEMU for the virtio-input smoke test (QMP key injection)");
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
                if !injected && line.contains(READY_MARKER)
                {
                    injected = true;
                    if let Err(e) = qmp::inject_input_test_sequence(&sock_path)
                    {
                        inject_err = Some(e);
                        break;
                    }
                }
                if line.contains(PASS_MARKER)
                {
                    verdict = Some(true);
                    break;
                }
                if line.contains(FAIL_MARKER)
                {
                    verdict = Some(false);
                    break;
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
            step("input smoke test: PASS");
            Ok(())
        }
        Some(false) => bail!("input smoke test: guest reported '{FAIL_MARKER}'"),
        None => bail!(
            "input smoke test: no pass/fail marker within {}s (timeout or early QEMU exit)",
            TIMEOUT.as_secs()
        ),
    }
}
