// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/commands/test/hotplug.rs

//! PCI Express hotplug test: a device hot-added behind a root port is found by
//! devmgr, given its BARs, recorded, and bound, and its driver's DMA and MSI
//! work; removed, its driver is withdrawn and the slot powered off or
//! ejected; added again, it is bound anew and works. A disk behind the port
//! is torn down at its removal and mounted again through vfsd, and a copy of
//! it added at another location takes none of the roles its storage
//! statement binds to the disk's location; and the loss
//! of the root filesystem's driver, or of the boot disk, ends vfsd and shuts
//! the system down.
//!
//! The device boots stage the `hotplug-check` fixture's recipe and the
//! `test-dma` class into the boot set, repack the disk images in the layout
//! they have, and boot the current sysroot with two empty `pcie-root-port`s
//! and a QMP socket. Once devmgr logs the first slot's grant and the fixture
//! logs [`READY_MARKER`], the host hot-adds QEMU's `edu` device behind that
//! port (QMP `device_add`). Once the fixture logs [`REMOVE_MARKER`], the
//! host removes it (QMP `device_del`) and waits for QEMU's
//! `DEVICE_DELETED`; devmgr's removal lines must come in their order. Once
//! the fixture logs [`READD_MARKER`], the host adds the device again and
//! waits for the fixture's verdict. Once the fixture passes, the host
//! hot-adds a `virtio-blk-pci` disk with no MSI-X vectors behind the second
//! port: devmgr must bind it from the drivers directory's virtio-blk, at the
//! auxiliary tier, as it binds every device unbound after the boot pass,
//! give its driver the wired line its `INTx` pin is routed to, which the
//! firmware never programmed into it, and the driver must come up
//! ([`disk_bound`]).
//!
//! Each device boot runs that cycle under one hotplug control. Under native
//! control devmgr manages the slot ([`MANAGED_MARKER`]): `device_del`
//! presses the slot's attention button, and QEMU deletes the device once
//! devmgr powers the slot off ([`NATIVE_REMOVAL`]). Under the firmware's,
//! q35's default on `x86_64`, `_OSC` withholds native control and devmgr
//! leaves the slot to the firmware ([`FIRMWARE_MARKER`]): QEMU's GPE method
//! notifies the slot's device, acpid posts devmgr's job, and `device_del`
//! completes once acpid runs the slot's `_EJ0` after devmgr's removal
//! ([`FIRMWARE_REMOVAL`], [`EJECT_MARKER`]). On `x86_64` both boots run,
//! the firmware's first, the native one with QEMU's ACPI PCI hotplug off, so
//! `_OSC` grants native control; on riscv64 the platform description table
//! grants it.
//!
//! The storage boots stage the fixture's disk-mode recipe alone and repack
//! the images in the split-data layout at the same block size, so the data
//! and swap partitions are on `disk-data.img`, named by the storage
//! statement the layout stages on the disk at the location the boot places
//! that image, and swapd takes its partition from that disk. The first
//! places that image's `virtio-blk-pci` behind the first port from boot
//! (`PortDisk::Data`), its statement naming the port's location
//! (`DataDisk::HotplugPort`), so vfsd mounts `/data` on it at startup: once
//! devmgr manages the slot and the fixture holds a file open there
//! ([`DISK_REMOVE_MARKER`]), the host removes the disk and requires
//! devmgr's removal lines and vfsd's [`VFSD_REMOVED_MARKER`]. Once the
//! fixture logs [`DISK_READD_MARKER`], the host adds a copy of the image,
//! taken before the boot, behind the second port ([`add_copy_disk`]): it
//! carries the data partition the storage statement names, at another
//! location than the statement's, so vfsd, asked by the fixture's `MOUNT`,
//! must log that the partition is not on its disk and is seen on the copy,
//! and take nothing ([`ELSEWHERE_MARKER`]); the fixture's mount before the
//! data disk is back fails the case. The host then adds the data disk again
//! on the same block node, and requires vfsd's line placing `/data` on the
//! disk at the port's location and the fixture's mount there
//! ([`DISK_MOUNTED_MARKER`]): the copy beside it denies nothing. The
//! fixture then stops and kills the root mount's driver, and the host
//! requires its verdict, vfsd's [`ROOT_LOST_MARKER`], svcmgr's
//! [`SHUTDOWN_MARKER`], and QEMU's exit. The second boots with the boot disk
//! itself behind that port (`PortDisk::Boot`) and the data disk at the
//! second disk's slot, its statement naming that slot (`DataDisk::Slot`);
//! once the slot is managed and the fixture ready, the host removes the boot
//! disk and requires the same last three. Both run under native control.
//!
//! The staged files are always removed and the images repacked in their
//! layout afterwards. The host kills QEMU after a boot that does not shut
//! down, as the `debug-port` case does.
//!
//! A pure runner: requires a populated sysroot from `cargo xtask build`.

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use crate::arch::Arch;
use crate::commands::test::cases::CaseArgs;
use crate::context::Context;
use crate::disk::{DataDisk, DataPlacement, DiskLayout};
use crate::error::{Context as _, Result, bail};
use crate::guest::{QemuStderr, explain_exit};
use crate::qemu::{
    EDU_DMA_MASK, Firmware, GdbMode, HOTPLUG_DISK_PORT_ID, HOTPLUG_PORT_ID, HotplugControl,
    HotplugPort, Iommu, PORT_DISK_ID, PORT_DISK_LOCATION, PortDisk, QemuDisplay, QemuLaunchSpec,
    RiscvMmu, RiscvZkr, SecondDisk, X86Paging, X86ShadowStack, build_qemu_argv,
    port_disk_properties, validate_sysroot_for_launch,
};
use crate::qmp::{self, Property};
use crate::socket_dir::SocketDir;
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

/// The disk-mode fixture's line once it mounted `/data` on the re-added
/// disk, beside the copy of it. Kept in sync with
/// `services/hotplug-check/src/disk.rs`.
const DISK_MOUNTED_MARKER: &str =
    "[hotplug-check] MOUNTED /data on the re-added disk beside the copy of it";

/// The text of vfsd's line, a warning, for `/data` when the partition the
/// storage statement names is not on the disk it binds it to and a disk
/// elsewhere carries it, up to the bound disk's location. Kept in sync with
/// `resolve_role` in `services/vfsd/src/main.rs`.
const ELSEWHERE_MARKER: &str = "/data: no partition named by the storage statement: not on ";

/// vfsd's line for `/data` once it took the partition the storage statement
/// names, up to the block it starts at. Kept in sync with `resolve_role` in
/// `services/vfsd/src/main.rs`.
const NAMED_DATA_MARKER: &str = "[vfsd] /data: partition named by the storage statement at block ";

/// The id `device_add` gives the storage boot's copy of the data disk.
const COPY_DISK_ID: &str = "hotplug-copy-disk";

/// The block node of the storage boot's copy of the data disk.
const COPY_DISK_NODE: &str = "hotplug-copy-disk-node";

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
/// control, which it leaves to the firmware. Kept in sync with
/// `services/devmgr/src/hotplug.rs`.
const FIRMWARE_MARKER: &str = "firmware hotplug: _OSC control";

/// The id `device_add` gives the hot-added `edu`.
const DEVICE_ID: &str = "hotplug-edu";

/// Whether the boot attaches the IOMMU: attached, as every launch's
/// default, so the hot-added disk is put behind it as the launchers put a
/// boot `virtio-pci` device (`iommu_platform=on`).
const IOMMU: Iommu = Iommu::Attached;

/// The id `device_add` gives the hot-added disk.
const DISK_ID: &str = "hotplug-disk";

/// The block node of the hot-added disk's image, which its `drive`
/// property names.
const DISK_NODE: &str = "hotplug-disk-node";

/// The size of the hot-added disk's raw image, zero-filled: the disk is only
/// bound, never read.
const DISK_BYTES: u64 = 1 << 20;

/// devmgr's line once it binds a virtio-blk function: after the disk's
/// hot-add, the disk's. Kept in sync with `services/devmgr/src/bind.rs`.
const DISK_BIND_MARKER: &str = "[devmgr] virtio-blk: binds PCI";

/// devmgr's line when it binds virtio-blk from the drivers directory, whose
/// declaration asks for the boot tier: the driver runs at the auxiliary
/// tier. After the disk's hot-add, it shows the disk bound from the drivers
/// directory. Kept in sync with `services/devmgr/src/bind.rs`.
const DISK_DIRECTORY_MARKER: &str = "virtio-blk: boot tier not granted from the drivers directory";

/// The virtio-blk driver's line once it serves its disk. Kept in sync with
/// `services/drivers/virtio/blk/src/main.rs`.
const DISK_READY_MARKER: &str = "[virtio-blk] ready, entering service loop";

/// devmgr's line when it gives virtio-blk a wired line: after the hot-add
/// of the disk, which has no MSI-X vectors ([`add_disk`]), the line its
/// `INTx` pin is routed to (on `x86_64` by the `_PRT` acpid pushed, on
/// riscv64 by the `virt` host's swizzle). Kept in sync with
/// `services/devmgr/src/bind.rs`.
const DISK_WIRED_MARKER: &str = "[devmgr] virtio-blk: Wired interrupt, 1 vector(s)";

/// Budget for a boot to reach its markers.
const BOOT_TIMEOUT: Duration = Duration::from_mins(5);

/// Budget for the fixture's verdict after the hot-add: past the poller's
/// period, the link wait, the add job, the driver's settle, and the probes.
const VERDICT_TIMEOUT: Duration = Duration::from_mins(3);

/// Budget for a removal, from `device_del` to devmgr's last removal line:
/// past the poller's period, the attention button's five-second abort
/// window, and the withdrawal, or acpid's job and `_EJ0`.
const REMOVAL_TIMEOUT: Duration = Duration::from_mins(1);

/// Budget for the loss of the root, from the kill of its driver or the
/// removal of its disk to QEMU's exit: past the poller's period and the
/// abort window for a removal, vfsd's exit, and svcmgr's graceful shutdown.
const SHUTDOWN_TIMEOUT: Duration = Duration::from_mins(2);

pub fn run(ctx: &Context, args: &CaseArgs) -> Result<()>
{
    validate_sysroot_for_launch(ctx, args.arch)?;
    // Held until the case returns, after its last QEMU has exited.
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
    let booted = stage(&device_set)
        .and_then(|()| crate::disk::create_disk_image(ctx, args.arch, layout))
        .and_then(|()| device_boots(ctx, args, layout))
        .and_then(|()| unstage(&device_set))
        .and_then(|()| stage(&storage_set))
        .and_then(|()| storage_boots(ctx, args, layout));
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
         driver and powered the slot off or ejected it, and it was bound again; a hot-added \
         disk was bound from the drivers directory on its wired line; the data disk's mount was \
         torn down at its removal and the disk mounted again when added back, and a copy of it \
         at another location took none of its roles and denied none; the loss of the root driver and of the \
         boot disk shut the system down)",
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

/// The device boots: on `x86_64` the machine's default first, the
/// firmware's hotplug through acpid, then native control; on riscv64 native
/// control (the platform table's grant).
fn device_boots(ctx: &Context, args: &CaseArgs, layout: DiskLayout) -> Result<()>
{
    let data_image = layout.second_image(ctx);
    let disk_image = ctx.target_dir.join("xtask").join("hotplug-disk.img");
    let controls: &[HotplugControl] = match args.arch
    {
        Arch::X86_64 => &[HotplugControl::Firmware, HotplugControl::Native],
        Arch::Riscv64 => &[HotplugControl::Native],
    };
    for &control in controls
    {
        std::fs::File::create(&disk_image)
            .and_then(|f| f.set_len(DISK_BYTES))
            .with_context(|| format!("creating {}", disk_image.display()))?;
        let booted = boot(
            ctx,
            args,
            data_image.as_deref(),
            HotplugPort::empty(control),
            |lines, socket| device_check(lines, socket, &disk_image, control),
        );
        let _ = std::fs::remove_file(&disk_image);
        booted?;
    }
    Ok(())
}

/// The storage boots, on the split-data layout at `layout`'s block size
/// under native control, each packed with the statement naming the location
/// it places the data disk at: the data disk behind the port removed, a copy
/// of it added at another location, the disk added again, then the root
/// driver killed; and the boot disk behind the port removed.
fn storage_boots(ctx: &Context, args: &CaseArgs, layout: DiskLayout) -> Result<()>
{
    let split = |at: DataDisk| DiskLayout {
        block_size: layout.block_size,
        data: DataPlacement::SecondImage(at),
    };
    crate::disk::create_disk_image(ctx, args.arch, split(DataDisk::HotplugPort))?;
    let data_image = ctx.data_disk_image();
    let block_size = crate::disk::logical_block_size(&data_image)?;
    // Copied before the boot writes the data disk: its GPT, and so the data
    // partition's type GUID, unique GUID and priority, are the data disk's,
    // and the file the fixture writes is not on it.
    let copy_image = ctx.target_dir.join("xtask").join("hotplug-copy-disk.img");
    std::fs::copy(&data_image, &copy_image).with_context(|| {
        format!(
            "copying {} to {}",
            data_image.display(),
            copy_image.display()
        )
    })?;
    let port = HotplugPort {
        control: HotplugControl::Native,
        disk: Some(PortDisk::Data {
            path: &data_image,
            block_size,
        }),
    };
    let checked = boot(ctx, args, None, port, |lines, socket| {
        disk_check(lines, socket, block_size, &copy_image)
    });
    let _ = std::fs::remove_file(&copy_image);
    checked?;
    crate::disk::create_disk_image(ctx, args.arch, split(DataDisk::Slot))?;
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
    args: &CaseArgs,
    second_disk: Option<&Path>,
    port: HotplugPort<'_>,
    check: impl FnOnce(&mut Lines, &Path) -> Result<()>,
) -> Result<()>
{
    let firmware = Firmware::prepare(ctx, args.arch)?;
    let vars = firmware.launch_vars()?;
    // Removed on every return, after QEMU is reaped below.
    let sockets = SocketDir::create()?;
    let sock_path = sockets.socket("hotplug.qmp")?;
    let disk_path = ctx.disk_image();
    let spec = QemuLaunchSpec {
        arch: args.arch,
        disk_path: &disk_path,
        disk_block_size: crate::disk::logical_block_size(&disk_path)?,
        second_disk: second_disk.map(SecondDisk::of_image).transpose()?,
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
        x86_paging: X86Paging::Four,
        x86_shadow_stack: X86ShadowStack::Off,
        iommu: IOMMU,
        debug_port: None,
        test_devices: false,
        hotplug_port: Some(port),
    };
    let qemu_args = build_qemu_argv(&spec)?;
    let qemu_binary = require_tool(args.arch.qemu_binary())?;

    let behind = match port.disk
    {
        None => "two empty root ports",
        Some(PortDisk::Data { .. }) => "two root ports, the data disk behind the first",
        Some(PortDisk::Boot) => "two root ports, the boot disk behind the first",
    };
    step(&format!(
        "hotplug test: booting with {behind}, hotplug control {:?}",
        port.control
    ));
    let mut child = Command::new(&qemu_binary)
        .args(&qemu_args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("spawning {}", args.arch.qemu_binary()))?;
    let mut stderr = QemuStderr::take(&mut child);
    let result = child
        .stdout
        .take()
        .context("QEMU stdout unavailable")
        .and_then(|stdout| check(&mut Lines::read(stdout), &sock_path))
        .map_err(|e| explain_exit(e, &mut child, stderr.as_mut()));
    let _ = child.kill();
    let _ = child.wait();
    result
}

/// Wait for devmgr's grant of the slot under `control` and for the
/// fixture's line `ready_marker`; fails on the other grant or a failed check.
fn granted_and_ready(lines: &Lines, control: HotplugControl, ready_marker: &str) -> Result<()>
{
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
                [grant, wrong, ready_marker, FAIL_MARKER]
                    .iter()
                    .any(|m| l.contains(m))
            },
        )?;
        if line.contains(wrong) || line.contains(FAIL_MARKER)
        {
            bail!("before the hot-plug, under {control:?} control: {line}");
        }
        granted |= line.contains(grant);
        ready |= line.contains(ready_marker);
    }
    Ok(())
}

/// The check of a device boot under `control`: devmgr takes the slot's
/// grant (managed, or left to the firmware), the host hot-adds `edu` once
/// the fixture is ready, removes it and adds it again on the fixture's
/// lines, and the fixture passes; then a disk over the image `disk`
/// hot-added behind the second port is bound ([`disk_bound`]).
fn device_check(
    lines: &mut Lines,
    socket: &Path,
    disk: &Path,
    control: HotplugControl,
) -> Result<()>
{
    granted_and_ready(lines, control, READY_MARKER)?;
    step("hotplug test: slot granted and the fixture ready; hot-adding edu");
    let add = || {
        qmp::device_add(
            socket,
            "edu",
            DEVICE_ID,
            HOTPLUG_PORT_ID,
            &[("dma_mask", Property::Number(EDU_DMA_MASK))],
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
        HotplugControl::Firmware =>
        {
            removal(lines, &FIRMWARE_REMOVAL, READD_MARKER, &[EJECT_MARKER])?;
        }
        HotplugControl::Native => removal(lines, &NATIVE_REMOVAL, READD_MARKER, &[])?,
    }
    step("hotplug test: devmgr withdrew the driver and the slot let the card go; adding edu again");
    add()?;
    lines.start = Instant::now();
    verdict(lines)?;
    step("hotplug test: the fixture passed; hot-adding a virtio-blk disk");
    add_disk(socket, disk)?;
    lines.start = Instant::now();
    disk_bound(lines)
}

/// Hot-add the disk behind the second port: a raw block node over the image
/// `disk` (QMP `blockdev-add`), then a `virtio-blk-pci` on it, behind the
/// IOMMU when the boot attaches one, as the launchers put a boot disk, with
/// no MSI-X vectors (`vectors=0`): virtio-pci has no MSI capability, so its
/// driver is given the wired line of its `INTx` pin. The storage boot's
/// disk added again ([`port_disk_properties`]) keeps its vectors.
fn add_disk(socket: &Path, disk: &Path) -> Result<()>
{
    qmp::blockdev_add_raw(socket, DISK_NODE, disk)?;
    qmp::device_add(
        socket,
        "virtio-blk-pci",
        DISK_ID,
        HOTPLUG_DISK_PORT_ID,
        &[
            ("drive", Property::Text(DISK_NODE)),
            ("disable-legacy", Property::Text("on")),
            ("iommu_platform", Property::Flag(IOMMU == Iommu::Attached)),
            ("vectors", Property::Number(0)),
        ],
    )
}

/// Read the lines of the hot-added disk's bind, in any order: devmgr binds
/// virtio-blk to it ([`DISK_BIND_MARKER`]), from the drivers directory, at the
/// auxiliary tier ([`DISK_DIRECTORY_MARKER`]), and on the wired line of its
/// `INTx` pin ([`DISK_WIRED_MARKER`]), and the driver serves the disk
/// ([`DISK_READY_MARKER`]). They are read from the lines after the hot-add,
/// which the boot disk's bind precedes.
fn disk_bound(lines: &Lines) -> Result<()>
{
    let markers = [
        DISK_BIND_MARKER,
        DISK_DIRECTORY_MARKER,
        DISK_WIRED_MARKER,
        DISK_READY_MARKER,
    ];
    let mut seen = [false; 4];
    while !seen.iter().all(|&s| s)
    {
        let line = lines.until(VERDICT_TIMEOUT, "the hot-added disk's bind", |l| {
            markers.iter().any(|m| l.contains(m))
        })?;
        for (s, m) in seen.iter_mut().zip(markers)
        {
            *s |= line.contains(m);
        }
    }
    Ok(())
}

/// The check of the storage boot with the data disk behind the port: once
/// the slot is managed and the fixture holds a file open on the disk, the
/// host removes it; once vfsd has torn its mount down, the host adds
/// `copy_image`, a copy of the disk, behind the second port
/// ([`add_copy_disk`]), and requires vfsd's line that `/data`'s named
/// partition is not on the disk at the port's location and is seen on the
/// copy, with no mount before it; then adds the disk again, a
/// `virtio-blk-pci` of `block_size`-byte blocks on the same node, and
/// requires vfsd's line placing `/data` at the port's location and the
/// fixture's mount there; the fixture passes, kills the root mount's driver,
/// and the system shuts down ([`root_lost`]).
fn disk_check(lines: &mut Lines, socket: &Path, block_size: u32, copy_image: &Path) -> Result<()>
{
    granted_and_ready(lines, HotplugControl::Native, DISK_REMOVE_MARKER)?;
    step("hotplug test: slot managed and a file open on its disk; removing the data disk");
    qmp::device_del(socket, PORT_DISK_ID, REMOVAL_TIMEOUT)?;
    step("hotplug test: QEMU deleted the disk");
    lines.start = Instant::now();
    removal(
        lines,
        &NATIVE_REMOVAL,
        DISK_READD_MARKER,
        &[VFSD_REMOVED_MARKER],
    )?;
    step(
        "hotplug test: devmgr withdrew the driver and powered the slot off, vfsd tore the mount \
         down; adding a copy of the disk behind the second port",
    );
    add_copy_disk(socket, copy_image, block_size)?;
    lines.start = Instant::now();
    let port = vfsd_location(PORT_DISK_LOCATION);
    let seen = lines.until(VERDICT_TIMEOUT, "vfsd's sighting of the copy", |l| {
        [ELSEWHERE_MARKER, DISK_MOUNTED_MARKER, FAIL_MARKER]
            .iter()
            .any(|m| l.contains(m))
    })?;
    elsewhere_seen(&seen, &port)?;
    step(
        "hotplug test: vfsd saw /data's named partition on the copy, off its disk, and took \
         nothing; adding the disk again",
    );
    qmp::device_add(
        socket,
        "virtio-blk-pci",
        PORT_DISK_ID,
        HOTPLUG_PORT_ID,
        &port_disk_properties(block_size, IOMMU),
    )?;
    lines.start = Instant::now();
    let (mut placed, mut mounted) = (false, false);
    while !(placed && mounted)
    {
        let line = lines.until(VERDICT_TIMEOUT, "the re-added disk's mount", |l| {
            [NAMED_DATA_MARKER, DISK_MOUNTED_MARKER, FAIL_MARKER]
                .iter()
                .any(|m| l.contains(m))
        })?;
        let (on_port, is_mount) = mounted_on(&line, &port)?;
        placed |= on_port;
        mounted |= is_mount;
    }
    step("hotplug test: /data mounted again on its disk beside the copy");
    lines.start = Instant::now();
    verdict(lines)?;
    step("hotplug test: the fixture passed; the root driver is killed");
    lines.start = Instant::now();
    root_lost(lines)
}

/// The text vfsd logs for a disk at `at`: `PCI` and the location.
fn vfsd_location(at: storage_statement::PciLocation) -> String
{
    format!(
        "PCI {:04x}:{:02x}:{:02x}.{}",
        at.segment, at.bus, at.device, at.function
    )
}

/// Check `line`, the first after the copy's add that is vfsd's sighting,
/// the fixture's mount, or its failure: it must be vfsd's line that
/// `/data`'s named partition is not on the disk at `port` and is seen on
/// another disk, at another location, and not taken.
fn elsewhere_seen(line: &str, port: &str) -> Result<()>
{
    let Some((_, rest)) = line.split_once(ELSEWHERE_MARKER)
    else
    {
        bail!("before the data disk was added again: {line}");
    };
    let seen = rest
        .strip_prefix(port)
        .and_then(|rest| rest.strip_prefix("; seen on disk "))
        .and_then(|rest| rest.strip_suffix("; not taken"))
        .and_then(|rest| rest.split_once(" at "));
    match seen
    {
        Some((_, at)) if at != port => Ok(()),
        _ => bail!("vfsd's line does not place the named partition off {port}: {line}"),
    }
}

/// Read `line`, one after the data disk's re-add: whether it is vfsd's line
/// placing `/data` on the disk at `port`, and whether it is the fixture's
/// mount. A failure of the fixture, or `/data` placed elsewhere, fails.
fn mounted_on(line: &str, port: &str) -> Result<(bool, bool)>
{
    if line.contains(FAIL_MARKER)
    {
        bail!("the fixture failed: {line}");
    }
    if line.contains(NAMED_DATA_MARKER)
    {
        if !line.trim_end().ends_with(&format!(" at {port}"))
        {
            bail!("vfsd placed /data on another disk than the one at {port}: {line}");
        }
        return Ok((true, false));
    }
    Ok((false, line.contains(DISK_MOUNTED_MARKER)))
}

/// Hot-add `image`, a copy of the data disk, behind the second port: a raw
/// block node over it (QMP `blockdev-add`), then a `virtio-blk-pci` on it
/// with the properties of the data disk's device added again, on that node.
/// Its data partition is the one the storage statement names, as the data
/// disk's is, at the second port's location, which the statement does not
/// name.
fn add_copy_disk(socket: &Path, image: &Path, block_size: u32) -> Result<()>
{
    qmp::blockdev_add_raw(socket, COPY_DISK_NODE, image)?;
    let mut properties = port_disk_properties(block_size, IOMMU);
    properties.retain(|&(name, _)| name != "drive");
    properties.push(("drive", Property::Text(COPY_DISK_NODE)));
    qmp::device_add(
        socket,
        "virtio-blk-pci",
        COPY_DISK_ID,
        HOTPLUG_DISK_PORT_ID,
        &properties,
    )
}

/// The check of the storage boot with the boot disk behind the port: once
/// the slot is managed and the fixture ready, its file open on the data
/// disk, the host removes the boot disk, and the system shuts down
/// ([`root_lost`]). The fixture's lines after the removal are not read: it
/// waits for a removal of the data disk that does not come, and the loss
/// ends its calls.
fn boot_disk_check(lines: &mut Lines, socket: &Path) -> Result<()>
{
    granted_and_ready(lines, HotplugControl::Native, DISK_REMOVE_MARKER)?;
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

/// Read the lines of a removal: each of devmgr's `markers` once, in their
/// order; each of `also`, lines of other services, at least once in any
/// order; and the fixture's `readd`, which may come among them, since the
/// fixture sees the removal as devmgr takes the driver out of its class.
fn removal(lines: &Lines, markers: &[&str], readd: &str, also: &[&str]) -> Result<()>
{
    let mut next = 0usize;
    let mut withdrawn = false;
    let mut seen = vec![false; also.len()];
    while next < markers.len() || !withdrawn || seen.contains(&false)
    {
        let line = lines.until(REMOVAL_TIMEOUT, "the removal's lines", |l| {
            l.contains(readd)
                || l.contains(FAIL_MARKER)
                || markers.iter().chain(also).any(|m| l.contains(m))
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

#[cfg(test)]
mod tests
{
    use super::*;

    const PORT: &str = "PCI 0000:01:00.0";

    // Defect caught: the copy's step read as a pass when vfsd took the
    // copy's partition, mounted before the data disk was back, or saw the
    // partition at the very location the statement names.
    #[test]
    fn only_a_sighting_off_the_named_location_passes_the_copy_step()
    {
        elsewhere_seen(
            "[vfsd] WARN /data: no partition named by the storage statement: not on PCI \
             0000:01:00.0; seen on disk 2 at PCI 0000:02:00.0; not taken",
            PORT,
        )
        .unwrap();
        for line in [
            "[vfsd] WARN /data: no partition named by the storage statement: not on PCI \
             0000:01:00.0; seen on disk 2 at PCI 0000:01:00.0; not taken",
            "[vfsd] WARN /data: no partition named by the storage statement: not on PCI \
             0000:02:00.0; seen on disk 2 at PCI 0000:03:00.0; not taken",
            "[hotplug-check] MOUNTED /data on the re-added disk beside the copy of it",
            "[hotplug-check] FAIL: MOUNT at /data answered 0x7",
        ]
        {
            elsewhere_seen(line, PORT).unwrap_err();
        }
    }

    // Defect caught: /data placed on the copy after the re-add, or a
    // failure of the fixture, read as the re-added disk's mount.
    #[test]
    fn the_re_added_mount_must_be_at_the_port()
    {
        assert_eq!(
            mounted_on(
                "[vfsd] /data: partition named by the storage statement at block 2048 on disk 3 \
                 at PCI 0000:01:00.0",
                PORT
            )
            .unwrap(),
            (true, false)
        );
        assert_eq!(
            mounted_on(DISK_MOUNTED_MARKER, PORT).unwrap(),
            (false, true)
        );
        mounted_on(
            "[vfsd] /data: partition named by the storage statement at block 2048 on disk 2 at \
             PCI 0000:02:00.0",
            PORT,
        )
        .unwrap_err();
        mounted_on("[hotplug-check] FAIL: reading", PORT).unwrap_err();
    }

    #[test]
    fn the_port_location_reads_as_vfsd_logs_it()
    {
        assert_eq!(vfsd_location(PORT_DISK_LOCATION), PORT);
    }
}
