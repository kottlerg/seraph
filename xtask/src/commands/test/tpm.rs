// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/commands/test/tpm.rs

//! TPM 2.0 driver test. `x86_64` only: QEMU's TPM devices sit in the PC
//! Client TPM range, which the riscv64 `virt` machine does not decode.
//!
//! Boots the default boot set twice, once with QEMU's `tpm-tis` device (the
//! FIFO interface) and once with `tpm-crb` (the CRB interface), each backed
//! by a `swtpm` emulator started on a fresh state directory, so every boot
//! meets a TPM no one has used. A TPM launch leaves out the `virtio-rng-pci`
//! device, so the TPM driver is the `hwrng` class's only member. Each boot
//! passes on three lines: the TPM driver's report of the interface it found,
//! its first `READ` answered with bytes from the TPM, and entropyd's first
//! accepted contribution, which can then only have come from the TPM.
//!
//! A pure runner like the `vmgenid` case: requires a populated `x86_64` sysroot
//! with the default boot set and a repacked `disk.img`, and `swtpm` on the
//! host.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use crate::error::{Context as _, Result, bail};

use crate::arch::Arch;
use crate::commands::test::cases::CaseArgs;
use crate::context::Context;
use crate::guest::Guest;
use crate::qemu::{
    Firmware, GdbMode, Iommu, QemuDisplay, QemuLaunchSpec, RiscvMmu, RiscvZkr, Tpm, TpmInterface,
    X86Paging, X86ShadowStack, build_qemu_argv_with_tpm, validate_sysroot_for_launch,
};
use crate::util::{require_tool, step};

/// The TPM driver's line once its first `READ` is answered with bytes.
const READ_MARKER: &str = "first READ answered:";

/// entropyd's line once the kernel accepts its first contribution
/// (`services/entropyd`); the TPM is the class's only member, ordinal 0.
const CONTRIBUTION_MARKER: &str = "entropy contribution accepted:";

/// The ordinal entropyd's line names.
const ORDINAL_MARKER: &str = "from hwrng ordinal 0";

/// Wall-clock budget per boot.
const TIMEOUT: Duration = Duration::from_mins(3);

/// How long `swtpm` gets to create its control socket.
const SOCKET_WAIT: Duration = Duration::from_secs(10);

/// The TPM driver's line naming `interface`.
const fn interface_marker(interface: TpmInterface) -> &'static str
{
    match interface
    {
        TpmInterface::Fifo => "FIFO interface (interface id",
        TpmInterface::Crb => "CRB interface (interface id",
    }
}

/// A running `swtpm`. Dropping it kills and reaps the emulator, so every
/// exit path of the test, an early `?` included, ends it.
struct Swtpm
{
    child: Child,
}

impl Drop for Swtpm
{
    fn drop(&mut self)
    {
        // Best-effort: both fail harmlessly once the emulator has exited.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Start `swtpm` as a TPM 2.0 on a fresh state directory `state`, with its
/// control socket at `socket`, and wait for the socket. The emulator is not
/// told to start the TPM: the firmware or the driver sends `TPM2_Startup`.
fn start_swtpm(swtpm: &Path, state: &Path, socket: &Path) -> Result<Swtpm>
{
    if state.exists()
    {
        std::fs::remove_dir_all(state).with_context(|| format!("removing {}", state.display()))?;
    }
    std::fs::create_dir_all(state).with_context(|| format!("creating {}", state.display()))?;
    let child = Command::new(swtpm)
        .arg("socket")
        .arg("--tpm2")
        .arg("--tpmstate")
        .arg(format!("dir={}", state.display()))
        .arg("--ctrl")
        .arg(format!("type=unixio,path={}", socket.display()))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .context("spawning swtpm")?;
    let mut emulator = Swtpm { child };
    let start = Instant::now();
    while !socket.exists()
    {
        if let Some(status) = emulator.child.try_wait().context("polling swtpm")?
        {
            bail!("swtpm exited before creating its socket ({status})");
        }
        if start.elapsed() > SOCKET_WAIT
        {
            bail!(
                "swtpm did not create {} within {SOCKET_WAIT:?}",
                socket.display()
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Ok(emulator)
}

/// Launch QEMU for one boot with a TPM of `interface` on the emulator's
/// `socket`.
fn launch(
    qemu_binary: &Path,
    ctx: &Context,
    args: &CaseArgs,
    interface: TpmInterface,
    socket: &Path,
) -> Result<Guest>
{
    let disk_path = ctx.disk_image();
    let firmware = Firmware::prepare(ctx, Arch::X86_64)?;
    let vars = firmware.launch_vars()?;
    let spec = QemuLaunchSpec {
        arch: Arch::X86_64,
        disk_path: &disk_path,
        disk_block_size: crate::disk::logical_block_size(&disk_path)?,
        second_disk: None,
        firmware_code_path: &firmware.code,
        firmware_vars_path: vars.path(),
        smm: false,
        cpus: args.cpus,
        threads_per_core: 1,
        mem_mib: args.mem,
        display: QemuDisplay::Headless,
        gdb: GdbMode::Off,
        qmp_socket: None,
        vmgenid_guid: Some("auto"),
        incoming: None,
        riscv_mmu: RiscvMmu::Sv48,
        riscv_zkr: RiscvZkr::On,
        x86_paging: X86Paging::Four,
        x86_shadow_stack: X86ShadowStack::Off,
        iommu: Iommu::Attached,
        debug_port: None,
        test_devices: false,
        hotplug_port: None,
    };
    let qemu_args = build_qemu_argv_with_tpm(&spec, Some(Tpm { interface, socket }))?;
    let child = Command::new(qemu_binary)
        .args(&qemu_args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .context("spawning qemu-system-x86_64")?;
    Ok(Guest::from_child(child)?.holding(vars))
}

/// The state directory and control socket of the emulator behind
/// `interface`'s boot, under `work_dir`.
fn emulator_paths(work_dir: &Path, interface: TpmInterface) -> (PathBuf, PathBuf)
{
    let name = interface.device();
    (
        work_dir.join(format!("{name}-state")),
        work_dir.join(format!("{name}.sock")),
    )
}

pub fn run(ctx: &Context, args: &CaseArgs) -> Result<()>
{
    validate_sysroot_for_launch(ctx, Arch::X86_64)?;
    let swtpm = require_tool("swtpm")?;
    // Held until the case returns, after its last QEMU has exited.
    let _host = crate::host_lock::admit_boot(ctx, &args.host, args.cpus, 1)?;
    let qemu_binary = require_tool(Arch::X86_64.qemu_binary())?;

    let work_dir = ctx.target_dir.join("xtask").join("tpm");
    std::fs::create_dir_all(&work_dir)
        .with_context(|| format!("creating {}", work_dir.display()))?;

    for interface in [TpmInterface::Fifo, TpmInterface::Crb]
    {
        let device = interface.device();
        let (state, socket) = emulator_paths(&work_dir, interface);
        let _ = std::fs::remove_file(&socket);
        step(&format!(
            "tpm test: {device} boot, waiting for the driver's READ and entropyd"
        ));
        // Dropped in reverse order: QEMU first, then the emulator it holds.
        let emulator = start_swtpm(&swtpm, &state, &socket)?;
        let mut guest = launch(&qemu_binary, ctx, args, interface, &socket)?;
        let seen = guest.wait_for_markers(
            &[
                interface_marker(interface),
                READ_MARKER,
                CONTRIBUTION_MARKER,
                ORDINAL_MARKER,
            ],
            TIMEOUT,
        );
        guest.shutdown();
        drop(emulator);
        let _ = std::fs::remove_file(&socket);
        seen.with_context(|| format!("{device} boot"))?;
    }

    step("tpm test: PASS (tpm-tis and tpm-crb: READ answered, contribution accepted)");
    Ok(())
}
