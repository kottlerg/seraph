// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/commands/test_hotplug.rs

//! PCI Express native hotplug test: a device hot-added behind a root port is
//! found by devmgr, given its BARs, recorded, and bound, and its driver's DMA
//! and MSI work; removed, its driver is withdrawn and the slot powered off;
//! added again, it is bound anew and works. A disk hot-added behind the port
//! is mounted through vfsd, torn down at its removal and mounted again; and
//! the loss of the root filesystem's driver, or of the boot disk, ends vfsd
//! and shuts the system down.
//!
//! The device boots stage the `hotplug-check` fixture's recipe and the
//! `test-dma` class into the boot set, repack the disk images in the layout
//! they have, and boot the current sysroot with an empty `pcie-root-port`
//! and a QMP socket. Once devmgr logs the slot managed ([`MANAGED_MARKER`])
//! and the fixture logs [`READY_MARKER`], the host hot-adds QEMU's `edu`
//! device behind the port (QMP `device_add`). Once the fixture logs
//! [`REMOVE_MARKER`], the host removes it (QMP `device_del`, which presses
//! the slot's attention button) and waits for QEMU's `DEVICE_DELETED`, which
//! QEMU sends once devmgr powers the slot off; devmgr's removal lines must
//! come in their order ([`REMOVAL_MARKERS`]). Once the fixture logs
//! [`READD_MARKER`], the host adds the device again and waits for the
//! fixture's verdict. On `x86_64` that boot turns QEMU's ACPI PCI hotplug
//! off, so `_OSC` grants native control; a boot before it, with the
//! machine's default, checks that devmgr leaves the slot alone when `_OSC`
//! withholds it ([`REFUSED_MARKER`]). On riscv64 the platform description
//! table grants it.
//!
//! The storage boots stage the fixture's disk-mode recipe alone and repack
//! the images in the split-data layout at the same block size, so the data
//! partition is on `disk-data.img`. The first places that image's
//! `virtio-blk-pci` behind the port from boot (`PortDisk::Data`), so vfsd
//! mounts `/data` on it at startup: once devmgr manages the slot and the
//! fixture holds a file open there ([`DISK_REMOVE_MARKER`]), the host
//! removes the disk and requires devmgr's removal lines and vfsd's
//! [`VFSD_REMOVED_MARKER`]; once the fixture logs [`DISK_READD_MARKER`], it
//! adds the disk again on the same block node. The fixture then stops and
//! kills the root mount's driver, and the host requires its verdict, vfsd's
//! [`ROOT_LOST_MARKER`], svcmgr's [`SHUTDOWN_MARKER`], and QEMU's exit. The
//! second boots with the boot disk itself behind the port (`PortDisk::Boot`)
//! and the data disk on a slot of its own; once the slot is managed and the
//! fixture ready, the host removes the boot disk and requires the same last
//! three. Both run under native control.
//!
//! The staged files are always removed and the images repacked in their
//! layout afterwards. The host kills QEMU after a boot that does not shut
//! down, as `test-debug-port` does.
//!
//! A pure runner: requires a populated sysroot from `cargo xtask build`.

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use crate::arch::Arch;
use crate::cli::TestHotplugArgs;
use crate::context::Context;
use crate::disk::{DataPlacement, DiskLayout};
use crate::error::{Context as _, Result, bail};
use crate::firmware::find_ovmf_code;
use crate::qemu::{
    EDU_DMA_MASK, GdbMode, HOTPLUG_PORT_ID, HotplugControl, HotplugPort, Iommu, PORT_DISK_ID,
    PortDisk, QemuDisplay, QemuLaunchSpec, RiscvMmu, RiscvZkr, SecondDisk, X86Paging,
    X86ShadowStack, build_qemu_argv, port_disk_properties, prepare_riscv_firmware,
    validate_sysroot_for_launch,
};
use crate::qmp;
use crate::util::{require_tool, step};

/// The fixture's recipe for the device boots, as `cargo xtask build`
/// installs it under `config/svcmgr/tests/`, staged into
/// `config/svcmgr/services/` for them.
const RECIPE: &str = "hotplug-check.svc";

/// The class of the driver the fixture waits for in the device boots, as
/// `cargo xtask build` installs it under `config/devmgr/tests/`, staged into
/// `config/devmgr/classes/` for them.
const CLASS: &str = "test-dma.class";

/// The fixture's disk-mode recipe for the storage boots, installed and
/// staged as [`RECIPE`] is.
const DISK_RECIPE: &str = "hotplug-check-disk.svc";

/// The fixture's line once it watches the `test-dma` class. Kept in sync
/// with `services/hotplug-check/src/main.rs`.
const READY_MARKER: &str = "[hotplug-check] READY for the hot-added device";

/// The fixture's line once the hot-added device passed its probes. Kept in
/// sync with `services/hotplug-check/src/main.rs`.
const REMOVE_MARKER: &str = "[hotplug-check] READY for the removal";

/// The fixture's line once devmgr withdrew the removed device's driver. Kept
/// in sync with `services/hotplug-check/src/main.rs`.
const READD_MARKER: &str = "[hotplug-check] WITHDRAWN at ordinal 0; READY for the re-added device";

/// The disk-mode fixture's line once it knows the root mount's driver and
/// holds a file open under `/data`. Kept in sync with
/// `services/hotplug-check/src/disk.rs`.
const DISK_REMOVE_MARKER: &str =
    "[hotplug-check] HOLDING a file open on /data; READY for the removal of its disk";

/// The disk-mode fixture's line once vfsd tore the removed disk's mount
/// down. Kept in sync with `services/hotplug-check/src/disk.rs`.
const DISK_READD_MARKER: &str =
    "[hotplug-check] TORN DOWN /data, its disk removed; READY for the re-added disk";

/// devmgr's lines of a removal, in the order they must come: the poller
/// starts the removal at the end of the attention button's abort window, the
/// driver's held memory is released once its device is withdrawn, the
/// removal job ends, and the poller powers the slot off. Kept in sync with
/// `services/devmgr/src/hotplug.rs` and `services/devmgr/src/bind.rs`.
const REMOVAL_MARKERS: [&str; 4] = [
    "removing its functions (its attention button's abort window elapsed)",
    "driver withdrawn, its memory released",
    "functions removed: 1, drivers withdrawn: 1,",
    "powered off (empty)",
];

/// vfsd's line once it found a disk it holds removed. Kept in sync with
/// `services/vfsd/src/watch.rs`.
const VFSD_REMOVED_MARKER: &str = "removed; tearing down its mounts";

/// vfsd's line once its root filesystem is lost. Kept in sync with
/// `services/vfsd/src/watch.rs`.
const ROOT_LOST_MARKER: &str = "[vfsd] ERROR FATAL: root filesystem lost";

/// svcmgr's line once a critical service, here vfsd, died. Kept in sync
/// with `services/svcmgr/src/restart.rs`.
const SHUTDOWN_MARKER: &str = "critical service unrecoverable: vfsd; initiating graceful shutdown";

/// The fixture's line when every check passed.
const PASS_MARKER: &str = "[hotplug-check] PASS";

/// The fixture's line when a check failed, followed by the reason.
const FAIL_MARKER: &str = "[hotplug-check] FAIL";

/// devmgr's line once it manages a slot. Kept in sync with
/// `services/devmgr/src/hotplug.rs`.
const MANAGED_MARKER: &str = "managed (native control by";

/// devmgr's line for a slot whose host bridge's `_OSC` withholds native
/// control. Kept in sync with `services/devmgr/src/hotplug.rs`.
const REFUSED_MARKER: &str = "not managed: _OSC control";

/// The id `device_add` gives the hot-added `edu`.
const DEVICE_ID: &str = "hotplug-edu";

/// Budget for a boot to reach its markers.
const BOOT_TIMEOUT: Duration = Duration::from_mins(5);

/// Budget for the fixture's verdict after the hot-add: past the poller's
/// period, the link wait, the add job, the driver's settle, and the probes.
const VERDICT_TIMEOUT: Duration = Duration::from_mins(3);

/// Budget for a removal, from `device_del` to devmgr's last removal line:
/// past the poller's period, the attention button's five-second abort
/// window, and the withdrawal.
const REMOVAL_TIMEOUT: Duration = Duration::from_mins(1);

/// Budget for the loss of the root, from the kill of its driver or the
/// removal of its disk to QEMU's exit: past the poller's period and the
/// abort window for a removal, vfsd's exit, and svcmgr's graceful shutdown.
const SHUTDOWN_TIMEOUT: Duration = Duration::from_mins(2);

pub fn run(ctx: &Context, args: &TestHotplugArgs) -> Result<()>
{
    validate_sysroot_for_launch(ctx, args.arch)?;
    // Held until the command returns, after its last QEMU has exited.
    let _host = crate::host_lock::admit_boot(ctx, &args.host, args.cpus, 1)?;
    let config = ctx.sysroot.join("config");
    let staged = |dir: &str, into: &str, file: &str| {
        (
            config.join(dir).join("tests").join(file),
            config.join(dir).join(into).join(file),
        )
    };
    let device_set = [
        staged("svcmgr", "services", RECIPE),
        staged("devmgr", "classes", CLASS),
    ];
    let storage_set = [staged("svcmgr", "services", DISK_RECIPE)];
    // Read before staging, so a failed staging repack cannot change the
    // layout the restore writes.
    let layout = crate::disk::current_layout(ctx)?;
    let storage_layout = DiskLayout {
        block_size: layout.block_size,
        data: DataPlacement::SecondImage,
    };
    let booted = stage(&device_set)
        .and_then(|()| crate::disk::create_disk_image(ctx, args.arch, layout))
        .and_then(|()| device_boots(ctx, args, layout))
        .and_then(|()| unstage(&device_set))
        .and_then(|()| stage(&storage_set))
        .and_then(|()| crate::disk::create_disk_image(ctx, args.arch, storage_layout))
        .and_then(|()| storage_boots(ctx, args));
    // Restore first, and surface its failure ahead of the boot's: a staged
    // recipe would start the fixture on every later boot.
    let unstaged = unstage(&device_set);
    unstage(&storage_set)
        .and(unstaged)
        .and_then(|()| crate::disk::create_disk_image(ctx, args.arch, layout))
        .context("restoring the disk images without the fixture")?;
    booted?;
    step(
        "hotplug test: PASS (the hot-added device was bound and works, its removal withdrew its \
         driver and powered the slot off, and it was bound again; the data disk's mount was \
         torn down at its removal and the disk mounted again when added back; the loss of the root driver and \
         of the boot disk shut the system down)",
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

/// The device boots: on `x86_64` the machine's default first, which must
/// leave the slot unmanaged, then native control; on riscv64 native control
/// (the platform table's grant).
fn device_boots(ctx: &Context, args: &TestHotplugArgs, layout: DiskLayout) -> Result<()>
{
    let data_image = layout.second_image(ctx);
    if args.arch == Arch::X86_64
    {
        let port = HotplugPort::empty(HotplugControl::Firmware);
        boot(ctx, args, data_image.as_deref(), port, |lines, _| {
            refused(lines)
        })?;
    }
    let port = HotplugPort::empty(HotplugControl::Native);
    boot(ctx, args, data_image.as_deref(), port, device_check)
}

/// The storage boots, on the split-data layout under native control: the
/// data disk behind the port removed and added again, then the root driver
/// killed; and the boot disk behind the port removed.
fn storage_boots(ctx: &Context, args: &TestHotplugArgs) -> Result<()>
{
    let data_image = ctx.data_disk_image();
    let block_size = crate::disk::logical_block_size(&data_image)?;
    let port = HotplugPort {
        control: HotplugControl::Native,
        disk: Some(PortDisk::Data {
            path: &data_image,
            block_size,
        }),
    };
    boot(ctx, args, None, port, |lines, socket| {
        disk_check(lines, socket, block_size)
    })?;
    let port = HotplugPort {
        control: HotplugControl::Native,
        disk: Some(PortDisk::Boot),
    };
    boot(ctx, args, Some(&data_image), port, boot_disk_check)
}

/// Boot the current images with `second_disk` attached when given and the
/// hotplug port `port`, run `check` on the boot's serial lines and its QMP
/// socket, and kill QEMU.
fn boot(
    ctx: &Context,
    args: &TestHotplugArgs,
    second_disk: Option<&Path>,
    port: HotplugPort<'_>,
    check: impl FnOnce(&mut Lines, &Path) -> Result<()>,
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
    let spec = QemuLaunchSpec {
        arch: args.arch,
        disk_path: &disk_path,
        disk_block_size: crate::disk::logical_block_size(&disk_path)?,
        second_disk: second_disk.map(SecondDisk::of_image).transpose()?,
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
        hotplug_port: Some(port),
    };
    let qemu_args = build_qemu_argv(&spec)?;
    let qemu_binary = require_tool(args.arch.qemu_binary())?;

    let behind = match port.disk
    {
        None => "an empty root port",
        Some(PortDisk::Data { .. }) => "the data disk behind the root port",
        Some(PortDisk::Boot) => "the boot disk behind the root port",
    };
    step(&format!(
        "hotplug test: booting with {behind}, hotplug control {:?}",
        port.control
    ));
    let mut child = Command::new(&qemu_binary)
        .args(&qemu_args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| format!("spawning {}", args.arch.qemu_binary()))?;
    let result = child
        .stdout
        .take()
        .context("QEMU stdout unavailable")
        .and_then(|stdout| check(&mut Lines::read(stdout), &sock_path));
    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_file(&sock_path);
    result
}

/// The check of the boot under the machine's default on `x86_64`: devmgr
/// refuses the slot.
fn refused(lines: &Lines) -> Result<()>
{
    let line = lines.until(BOOT_TIMEOUT, "devmgr's refusal of the slot", |l| {
        l.contains(MANAGED_MARKER) || l.contains(REFUSED_MARKER)
    })?;
    if !line.contains(REFUSED_MARKER)
    {
        bail!("devmgr managed the slot while _OSC withholds native control: {line}");
    }
    Ok(())
}

/// Wait for devmgr to manage the slot and for the fixture's line `ready`;
/// fails on a refusal of the slot or a failed check.
fn managed_and_ready(lines: &Lines, ready_marker: &str) -> Result<()>
{
    let (mut managed, mut ready) = (false, false);
    while !(managed && ready)
    {
        let line = lines.until(
            BOOT_TIMEOUT,
            "the slot managed and the fixture ready",
            |l| {
                [MANAGED_MARKER, REFUSED_MARKER, ready_marker, FAIL_MARKER]
                    .iter()
                    .any(|m| l.contains(m))
            },
        )?;
        if line.contains(REFUSED_MARKER) || line.contains(FAIL_MARKER)
        {
            bail!("before the hot-plug: {line}");
        }
        managed |= line.contains(MANAGED_MARKER);
        ready |= line.contains(ready_marker);
    }
    Ok(())
}

/// The check of the device boot under native control: devmgr manages the
/// slot, the host hot-adds `edu` once the fixture is ready, removes it and
/// adds it again on the fixture's lines, and the fixture passes.
fn device_check(lines: &mut Lines, socket: &Path) -> Result<()>
{
    managed_and_ready(lines, READY_MARKER)?;
    step("hotplug test: slot managed and the fixture ready; hot-adding edu");
    let add = || {
        qmp::device_add(
            socket,
            "edu",
            DEVICE_ID,
            HOTPLUG_PORT_ID,
            &[("dma_mask", qmp::Property::Number(EDU_DMA_MASK))],
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
    removal(lines, READD_MARKER, &[])?;
    step("hotplug test: devmgr withdrew the driver and powered the slot off; adding edu again");
    add()?;
    lines.start = Instant::now();
    verdict(lines)
}

/// The check of the storage boot with the data disk behind the port: once
/// the slot is managed and the fixture holds a file open on the disk, the
/// host removes it, and adds it again, a `virtio-blk-pci` of
/// `block_size`-byte blocks on the same node, once vfsd has torn its mount
/// down; the fixture passes, kills the root mount's driver, and the system
/// shuts down ([`root_lost`]).
fn disk_check(lines: &mut Lines, socket: &Path, block_size: u32) -> Result<()>
{
    managed_and_ready(lines, DISK_REMOVE_MARKER)?;
    step("hotplug test: slot managed and a file open on its disk; removing the data disk");
    qmp::device_del(socket, PORT_DISK_ID, REMOVAL_TIMEOUT)?;
    step("hotplug test: QEMU deleted the disk");
    lines.start = Instant::now();
    removal(lines, DISK_READD_MARKER, &[VFSD_REMOVED_MARKER])?;
    step(
        "hotplug test: devmgr withdrew the driver and powered the slot off, vfsd tore the mount \
         down; adding the disk again",
    );
    qmp::device_add(
        socket,
        "virtio-blk-pci",
        PORT_DISK_ID,
        HOTPLUG_PORT_ID,
        &port_disk_properties(block_size, Iommu::Attached),
    )?;
    lines.start = Instant::now();
    verdict(lines)?;
    step("hotplug test: the disk was mounted again; the root driver is killed");
    lines.start = Instant::now();
    root_lost(lines)
}

/// The check of the storage boot with the boot disk behind the port: once
/// the slot is managed and the fixture ready, its file open on the data
/// disk, the host removes the boot disk, and the system shuts down
/// ([`root_lost`]). The fixture's lines after the removal are not read: it
/// waits for a removal of the data disk that does not come, and the loss
/// ends its calls.
fn boot_disk_check(lines: &mut Lines, socket: &Path) -> Result<()>
{
    managed_and_ready(lines, DISK_REMOVE_MARKER)?;
    step("hotplug test: slot managed with the boot disk behind it; removing the boot disk");
    // The guest shuts down at the loss and may power off before it powers
    // the slot off, so no `DEVICE_DELETED` is waited for.
    qmp::device_del_request(socket, PORT_DISK_ID)?;
    lines.start = Instant::now();
    root_lost(lines)
}

/// Wait for the fixture's verdict, which must be a pass.
fn verdict(lines: &Lines) -> Result<()>
{
    let verdict = lines.until(VERDICT_TIMEOUT, "the fixture's verdict", |l| {
        l.contains(PASS_MARKER) || l.contains(FAIL_MARKER)
    })?;
    if !verdict.contains(PASS_MARKER)
    {
        bail!("the fixture failed: {verdict}");
    }
    Ok(())
}

/// Read the loss of the root: vfsd's [`ROOT_LOST_MARKER`], then svcmgr's
/// [`SHUTDOWN_MARKER`], then the end of the serial stream as QEMU exits,
/// each within [`SHUTDOWN_TIMEOUT`] of `lines.start`.
fn root_lost(lines: &Lines) -> Result<()>
{
    lines.until(SHUTDOWN_TIMEOUT, "vfsd's loss of its root", |l| {
        l.contains(ROOT_LOST_MARKER)
    })?;
    lines.until(SHUTDOWN_TIMEOUT, "svcmgr's shutdown at vfsd's exit", |l| {
        l.contains(SHUTDOWN_MARKER)
    })?;
    lines.end(SHUTDOWN_TIMEOUT, "QEMU's exit at the shutdown")
}

/// Read the lines of a removal: each of devmgr's [`REMOVAL_MARKERS`] once, in
/// their order, each of `also` at least once in any order, and the fixture's
/// `readd`, which may come among them, since the fixture sees the removal
/// as devmgr takes the driver out of its class.
fn removal(lines: &Lines, readd: &str, also: &[&str]) -> Result<()>
{
    let mut next = 0usize;
    let mut withdrawn = false;
    let mut seen = vec![false; also.len()];
    while next < REMOVAL_MARKERS.len() || !withdrawn || seen.contains(&false)
    {
        let line = lines.until(REMOVAL_TIMEOUT, "the removal's lines", |l| {
            l.contains(readd)
                || l.contains(FAIL_MARKER)
                || REMOVAL_MARKERS.iter().chain(also).any(|m| l.contains(m))
        })?;
        if line.contains(FAIL_MARKER)
        {
            bail!("the fixture failed: {line}");
        }
        if line.contains(readd)
        {
            withdrawn = true;
            continue;
        }
        if let Some(at) = also.iter().position(|m| line.contains(m))
        {
            if let Some(seen) = seen.get_mut(at)
            {
                *seen = true;
            }
            continue;
        }
        match REMOVAL_MARKERS.iter().position(|m| line.contains(m))
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
    /// Read the serial stream `stdout` on a worker thread, so each wait has
    /// a deadline; the thread echoes the guest's log until QEMU exits or is
    /// killed.
    fn read(stdout: std::process::ChildStdout) -> Self
    {
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
        Self {
            rx,
            start: Instant::now(),
        }
    }

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

    /// Wait, within `timeout` of `start`, for the serial stream to end, QEMU
    /// having exited; fails naming `what` when it does not.
    fn end(&self, timeout: Duration, what: &str) -> Result<()>
    {
        loop
        {
            let remaining = timeout.saturating_sub(self.start.elapsed());
            match self.rx.recv_timeout(remaining)
            {
                Ok(_) =>
                {}
                Err(mpsc::RecvTimeoutError::Timeout) =>
                {
                    bail!("no {what} within {}s", timeout.as_secs())
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(()),
            }
        }
    }
}
