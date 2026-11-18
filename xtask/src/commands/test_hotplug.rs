// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/commands/test_hotplug.rs

//! PCI Express hotplug test: a device hot-added behind a root port is found by
//! devmgr, given its BARs, recorded, and bound, and its driver's DMA and MSI
//! work; removed, its driver is withdrawn and the slot powered off or
//! ejected; added again, it is bound anew and works.
//!
//! Stages the `hotplug-check` fixture's recipe and the `test-dma` class into the
//! boot set, repacks the disk images in the layout they have, and boots the
//! current sysroot with an empty `pcie-root-port` and a QMP socket. Once devmgr
//! logs the slot's grant and the fixture logs [`READY_MARKER`], the host
//! hot-adds QEMU's `edu` device behind the port (QMP `device_add`). Once the
//! fixture logs [`REMOVE_MARKER`], the host removes it (QMP `device_del`)
//! and waits for QEMU's `DEVICE_DELETED`; devmgr's removal lines must come in
//! their order. Once the fixture logs [`READD_MARKER`], the host adds the
//! device again and waits for the fixture's verdict.
//!
//! Each boot runs that cycle under one hotplug control. Under native control
//! devmgr manages the slot ([`MANAGED_MARKER`]): `device_del` presses the
//! slot's attention button, and QEMU deletes the device once devmgr powers the
//! slot off ([`NATIVE_REMOVAL`]). Under the firmware's, q35's default on
//! `x86_64`, `_OSC` withholds native control and devmgr leaves the slot to
//! the firmware ([`FIRMWARE_MARKER`]): QEMU's GPE method notifies the slot's
//! device, acpid posts devmgr's job, and `device_del` completes once acpid
//! runs the slot's `_EJ0` after devmgr's removal ([`FIRMWARE_REMOVAL`],
//! [`EJECT_MARKER`]). On `x86_64` both boots run, the firmware's first, the
//! native one with QEMU's ACPI PCI hotplug off, so `_OSC` grants native
//! control; on riscv64 the platform description table grants it. The staged
//! files are always removed and the images repacked in that layout
//! afterwards. The host kills QEMU, as `test-debug-port` does.
//!
//! A pure runner: requires a populated sysroot from `cargo xtask build`.

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use crate::arch::Arch;
use crate::cli::TestHotplugArgs;
use crate::context::Context;
use crate::disk::DiskLayout;
use crate::error::{Context as _, Result, bail};
use crate::firmware::find_ovmf_code;
use crate::qemu::{
    EDU_DMA_MASK, GdbMode, HOTPLUG_PORT_ID, HotplugControl, Iommu, QemuDisplay, QemuLaunchSpec,
    RiscvMmu, RiscvZkr, SecondDisk, X86Paging, X86ShadowStack, build_qemu_argv,
    prepare_riscv_firmware, validate_sysroot_for_launch,
};
use crate::qmp;
use crate::util::{require_tool, step};

/// The fixture's recipe, as `cargo xtask build` installs it under
/// `config/svcmgr/tests/`, staged into `config/svcmgr/services/` for the boot.
const RECIPE: &str = "hotplug-check.svc";

/// The class of the driver the fixture waits for, as `cargo xtask build`
/// installs it under `config/devmgr/tests/`, staged into
/// `config/devmgr/classes/` for the boot.
const CLASS: &str = "test-dma.class";

/// The fixture's line once it watches the `test-dma` class. Kept in sync
/// with `services/hotplug-check/src/main.rs`.
const READY_MARKER: &str = "[hotplug-check] READY for the hot-added device";

/// The fixture's line once the hot-added device passed its probes. Kept in
/// sync with `services/hotplug-check/src/main.rs`.
const REMOVE_MARKER: &str = "[hotplug-check] READY for the removal";

/// The fixture's line once devmgr withdrew the removed device's driver. Kept
/// in sync with `services/hotplug-check/src/main.rs`.
const READD_MARKER: &str = "[hotplug-check] WITHDRAWN at ordinal 0; READY for the re-added device";

/// devmgr's lines of a native removal, in the order they must come: the
/// poller starts the removal at the end of the attention button's abort
/// window, the driver's held memory is released once its device is
/// withdrawn, the removal job ends, and the poller powers the slot off. Kept
/// in sync with `services/devmgr/src/hotplug.rs` and
/// `services/devmgr/src/bind.rs`.
const NATIVE_REMOVAL: [&str; 4] = [
    "removing its functions (its attention button's abort window elapsed)",
    "driver withdrawn, its memory released",
    "functions removed: 1, drivers withdrawn: 1,",
    "powered off (empty)",
];

/// devmgr's lines of a removal the firmware asks for, in the order they must
/// come: acpid's job starts the removal, the driver's held memory is released
/// once its device is withdrawn, and the removal job ends. Kept in sync with
/// `services/devmgr/src/hotplug.rs` and `services/devmgr/src/bind.rs`.
const FIRMWARE_REMOVAL: [&str; 3] = [
    "removing its functions (the firmware's eject request)",
    "driver withdrawn, its memory released",
    "functions removed: 1, drivers withdrawn: 1,",
];

/// acpid's line once it ran the slot's `_EJ0` after devmgr's removal job.
/// Kept in sync with `services/acpid/src/server.rs`.
const EJECT_MARKER: &str = "ejected (_EJ0) once devmgr removed 1 functions";

/// The fixture's line when every check passed.
const PASS_MARKER: &str = "[hotplug-check] PASS";

/// The fixture's line when a check failed, followed by the reason.
const FAIL_MARKER: &str = "[hotplug-check] FAIL";

/// devmgr's line once it manages a slot. Kept in sync with
/// `services/devmgr/src/hotplug.rs`.
const MANAGED_MARKER: &str = "managed (native control by";

/// devmgr's line for a slot whose host bridge's `_OSC` withholds native
/// control, which it leaves to the firmware. Kept in sync with
/// `services/devmgr/src/hotplug.rs`.
const FIRMWARE_MARKER: &str = "firmware hotplug: _OSC control";

/// The id `device_add` gives the hot-added `edu`.
const DEVICE_ID: &str = "hotplug-edu";

/// Budget for a boot to reach its markers.
const BOOT_TIMEOUT: Duration = Duration::from_mins(5);

/// Budget for the fixture's verdict after the hot-add: past the poller's
/// period, the link wait, the add job, the driver's settle, and the probes.
const VERDICT_TIMEOUT: Duration = Duration::from_mins(3);

/// Budget for a removal, from `device_del` to devmgr's last removal line:
/// past the poller's period, the attention button's five-second abort
/// window, and the withdrawal, or acpid's job and `_EJ0`.
const REMOVAL_TIMEOUT: Duration = Duration::from_mins(1);

pub fn run(ctx: &Context, args: &TestHotplugArgs) -> Result<()>
{
    validate_sysroot_for_launch(ctx, args.arch)?;
    // Held until the command returns, after its last QEMU has exited.
    let _host = crate::host_lock::admit_boot(ctx, &args.host, args.cpus, 1)?;
    let config = ctx.sysroot.join("config");
    let staged = [
        (
            config.join("svcmgr").join("tests").join(RECIPE),
            config.join("svcmgr").join("services").join(RECIPE),
        ),
        (
            config.join("devmgr").join("tests").join(CLASS),
            config.join("devmgr").join("classes").join(CLASS),
        ),
    ];
    // Read before staging, so a failed staging repack cannot change the
    // layout the restore writes.
    let layout = crate::disk::current_layout(ctx)?;
    let booted = stage(&staged)
        .and_then(|()| crate::disk::create_disk_image(ctx, args.arch, layout))
        .and_then(|()| boots(ctx, args, layout));
    // Restore first, and surface its failure ahead of the boot's: a staged
    // recipe would start the fixture on every later boot.
    unstage(&staged)
        .and_then(|()| crate::disk::create_disk_image(ctx, args.arch, layout))
        .context("restoring the disk images without the fixture")?;
    booted?;
    step(
        "hotplug test: PASS (the hot-added device was bound and works, its removal withdrew its \
         driver and powered the slot off or ejected it, and it was bound again)",
    );
    Ok(())
}

/// Copy each `(source, staged)` pair.
fn stage(staged: &[(PathBuf, PathBuf)]) -> Result<()>
{
    for (source, to) in staged
    {
        std::fs::copy(source, to)
            .with_context(|| format!("staging {} as {}", source.display(), to.display()))?;
    }
    Ok(())
}

/// Remove every staged copy that exists; the first failure is returned once
/// all were tried.
fn unstage(staged: &[(PathBuf, PathBuf)]) -> Result<()>
{
    let mut result = Ok(());
    for (_, to) in staged
    {
        if to.exists()
            && let Err(e) = std::fs::remove_file(to)
            && result.is_ok()
        {
            result =
                Err(crate::error::Error::from(e).context(format!("removing {}", to.display())));
        }
    }
    result
}

/// The boots of the test: on `x86_64` the machine's default first, the
/// firmware's hotplug through acpid, then native control; on riscv64 native
/// control (the platform table's grant).
fn boots(ctx: &Context, args: &TestHotplugArgs, layout: DiskLayout) -> Result<()>
{
    if args.arch == Arch::X86_64
    {
        boot(ctx, args, layout, HotplugControl::Firmware)?;
    }
    boot(ctx, args, layout, HotplugControl::Native)
}

/// Boot the images of `layout` with the hotplug port under `control`, run
/// its check, and kill QEMU.
fn boot(
    ctx: &Context,
    args: &TestHotplugArgs,
    layout: DiskLayout,
    control: HotplugControl,
) -> Result<()>
{
    let (firmware_code, firmware_vars) = match args.arch
    {
        Arch::X86_64 => (find_ovmf_code()?, None),
        Arch::Riscv64 =>
        {
            let (code, vars) = prepare_riscv_firmware(ctx)?;
            (code, Some(vars))
        }
    };
    let sock_dir = ctx.target_dir.join("xtask");
    std::fs::create_dir_all(&sock_dir)
        .with_context(|| format!("creating {}", sock_dir.display()))?;
    let sock_path = sock_dir.join("hotplug-test-qmp.sock");
    let _ = std::fs::remove_file(&sock_path);
    let disk_path = ctx.disk_image();
    let data_image = layout.second_image(ctx);
    let spec = QemuLaunchSpec {
        arch: args.arch,
        disk_path: &disk_path,
        disk_block_size: crate::disk::logical_block_size(&disk_path)?,
        second_disk: data_image
            .as_deref()
            .map(SecondDisk::of_image)
            .transpose()?,
        firmware_code_path: &firmware_code,
        firmware_vars_path: firmware_vars.as_deref(),
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
        x86_paging: X86Paging::Four,
        x86_shadow_stack: X86ShadowStack::Off,
        iommu: Iommu::Attached,
        debug_port: None,
        test_devices: false,
        hotplug_port: Some(control),
    };
    let qemu_args = build_qemu_argv(&spec)?;
    let qemu_binary = require_tool(args.arch.qemu_binary())?;

    step(&format!(
        "hotplug test: booting with an empty root port, hotplug control {control:?}"
    ));
    let mut child = Command::new(&qemu_binary)
        .args(&qemu_args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| format!("spawning {}", args.arch.qemu_binary()))?;
    let result = watch(&mut child, &sock_path, control);
    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_file(&sock_path);
    result
}

/// Read the serial stream of `child` and run the check of a boot under
/// `control`: devmgr takes the slot's grant (managed, or left to the
/// firmware), the host hot-adds `edu` once the fixture is ready, removes it,
/// adds it again, and the fixture passes.
fn watch(child: &mut Child, socket: &Path, control: HotplugControl) -> Result<()>
{
    let stdout = child.stdout.take().context("QEMU stdout unavailable")?;
    // Serial lines on a worker thread, so each wait has a deadline; the
    // thread echoes the guest's log until QEMU is killed.
    let (tx, rx) = mpsc::channel::<String>();
    let _reader = thread::spawn(move || {
        for line in BufReader::new(stdout).lines()
        {
            let Ok(l) = line
            else
            {
                break;
            };
            println!("{l}");
            if tx.send(l).is_err()
            {
                break;
            }
        }
    });
    let mut lines = Lines {
        rx,
        start: Instant::now(),
    };
    // The grant devmgr must log for the slot, and the one it must not.
    let (grant, wrong) = match control
    {
        HotplugControl::Firmware => (FIRMWARE_MARKER, MANAGED_MARKER),
        HotplugControl::Native => (MANAGED_MARKER, FIRMWARE_MARKER),
    };
    let (mut granted, mut ready) = (false, false);
    while !(granted && ready)
    {
        let line = lines.until(
            BOOT_TIMEOUT,
            "the slot's grant and the fixture ready",
            |l| {
                [grant, wrong, READY_MARKER, FAIL_MARKER]
                    .iter()
                    .any(|m| l.contains(m))
            },
        )?;
        if line.contains(wrong) || line.contains(FAIL_MARKER)
        {
            bail!("before the hot-add, under {control:?} control: {line}");
        }
        granted |= line.contains(grant);
        ready |= line.contains(READY_MARKER);
    }
    step("hotplug test: slot granted and the fixture ready; hot-adding edu");
    let add = || {
        qmp::device_add(
            socket,
            "edu",
            DEVICE_ID,
            HOTPLUG_PORT_ID,
            &[("dma_mask", EDU_DMA_MASK)],
        )
    };
    add()?;
    lines.start = Instant::now();
    let line = lines.until(
        VERDICT_TIMEOUT,
        "the fixture's probes of the added device",
        |l| l.contains(REMOVE_MARKER) || l.contains(FAIL_MARKER),
    )?;
    if line.contains(FAIL_MARKER)
    {
        bail!("the fixture failed: {line}");
    }
    step("hotplug test: the added device works; removing it");
    qmp::device_del(socket, DEVICE_ID, REMOVAL_TIMEOUT)?;
    step("hotplug test: QEMU deleted the device");
    lines.start = Instant::now();
    match control
    {
        HotplugControl::Firmware => removal(&lines, &FIRMWARE_REMOVAL, Some(EJECT_MARKER))?,
        HotplugControl::Native => removal(&lines, &NATIVE_REMOVAL, None)?,
    }
    step("hotplug test: devmgr withdrew the driver and the slot let the card go; adding edu again");
    add()?;
    lines.start = Instant::now();
    let verdict = lines.until(VERDICT_TIMEOUT, "the fixture's verdict", |l| {
        l.contains(PASS_MARKER) || l.contains(FAIL_MARKER)
    })?;
    if !verdict.contains(PASS_MARKER)
    {
        bail!("the fixture failed: {verdict}");
    }
    Ok(())
}

/// Read the lines of a removal: each of devmgr's `markers` once, in their
/// order; the fixture's [`READD_MARKER`], which may come among them, since
/// the fixture sees the driver withdrawn as devmgr takes it out of its
/// class; and `also`, when given, a line of another service that may come
/// among them too.
fn removal(lines: &Lines, markers: &[&str], also: Option<&str>) -> Result<()>
{
    let mut next = 0usize;
    let mut withdrawn = false;
    let mut seen = also.is_none();
    while next < markers.len() || !withdrawn || !seen
    {
        let line = lines.until(REMOVAL_TIMEOUT, "the removal's lines", |l| {
            l.contains(READD_MARKER)
                || l.contains(FAIL_MARKER)
                || also.is_some_and(|m| l.contains(m))
                || markers.iter().any(|m| l.contains(m))
        })?;
        if line.contains(FAIL_MARKER)
        {
            bail!("the fixture failed: {line}");
        }
        if line.contains(READD_MARKER)
        {
            withdrawn = true;
            continue;
        }
        if also.is_some_and(|m| line.contains(m))
        {
            seen = true;
            continue;
        }
        match markers.iter().position(|m| line.contains(m))
        {
            Some(at) if at == next => next = next.saturating_add(1),
            _ => bail!("removal line out of order or repeated: {line}"),
        }
    }
    Ok(())
}

/// The serial lines of a boot, each wait bounded from `start`.
struct Lines
{
    rx: mpsc::Receiver<String>,
    start: Instant,
}

impl Lines
{
    /// The next line `matches` holds for, within `timeout` of `start`; fails
    /// naming `what` when none comes or the stream ends.
    fn until(&self, timeout: Duration, what: &str, matches: impl Fn(&str) -> bool)
    -> Result<String>
    {
        loop
        {
            let remaining = timeout.saturating_sub(self.start.elapsed());
            match self.rx.recv_timeout(remaining)
            {
                Ok(line) if matches(&line) => return Ok(line),
                Ok(_) =>
                {}
                Err(mpsc::RecvTimeoutError::Timeout) =>
                {
                    bail!("no line for {what} within {}s", timeout.as_secs())
                }
                Err(mpsc::RecvTimeoutError::Disconnected) =>
                {
                    bail!("the serial stream ended before {what}")
                }
            }
        }
    }
}
