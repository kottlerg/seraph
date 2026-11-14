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

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use anyhow::{Context as _, Result};

use crate::arch::Arch;
use crate::cli::TestVmgenidArgs;
use crate::context::Context;
use crate::firmware::find_ovmf_code;
use crate::guest::Guest;
use crate::qemu::QemuDisplay;
use crate::qemu::{
    GdbMode, Iommu, QemuLaunchSpec, RiscvMmu, X86Paging, build_qemu_argv,
    validate_sysroot_for_launch,
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

/// Launch QEMU for one boot of the test with the generation GUID `guid`,
/// restoring the state at `incoming` when one is given.
fn launch(
    qemu_binary: &Path,
    ctx: &Context,
    args: &TestVmgenidArgs,
    sock_path: &Path,
    guid: &str,
    incoming: Option<&str>,
) -> Result<Guest>
{
    let disk_path = ctx.disk_image();
    let firmware_code = find_ovmf_code()?;
    let spec = QemuLaunchSpec {
        arch: Arch::X86_64,
        disk_path: &disk_path,
        disk_block_size: crate::disk::logical_block_size(&disk_path)?,
        second_disk: None,
        firmware_code_path: &firmware_code,
        firmware_vars_path: None,
        cpus: args.cpus,
        mem_mib: args.mem,
        display: QemuDisplay::Headless,
        gdb: GdbMode::Off,
        qmp_socket: Some(sock_path),
        vmgenid_guid: Some(guid),
        incoming,
        riscv_mmu: RiscvMmu::Sv48,
        x86_paging: X86Paging::Four,
        iommu: Iommu::Attached,
        debug_port: None,
        test_devices: false,
    };
    let qemu_args = build_qemu_argv(&spec)?;

    let child = Command::new(qemu_binary)
        .args(&qemu_args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .context("spawning qemu-system-x86_64")?;
    Guest::from_child(child)
}

pub fn run(ctx: &Context, args: &TestVmgenidArgs) -> Result<()>
{
    validate_sysroot_for_launch(ctx, Arch::X86_64)?;
    // Held until the command returns, after its last QEMU has exited.
    let _host = crate::host_lock::admit_boot(ctx, &args.host, args.cpus, 1)?;
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
    let mut guest_a = launch(&qemu_binary, ctx, args, &sock_a, GUID_A, None)?;
    guest_a
        .wait_for_markers(&[ARMED_MARKER, READY_MARKER], TIMEOUT)
        .context("boot A")?;

    // ── Save: migrate to file, then quit to release the disk lock ──────────
    step("vmgenid test: migrating state to file");
    qmp::migrate_to_file(&sock_a, &state_path, MIGRATE_TIMEOUT).context("migrate to file")?;
    qmp::quit(&sock_a).context("quitting source QEMU")?;
    guest_a.wait_exit(Duration::from_secs(30))?;

    // ── Boot B: new GUID, restore the state, assert detection ──────────────
    step("vmgenid test: boot B (restore with new GUID) — waiting for detection");
    let mut guest_b = launch(&qemu_binary, ctx, args, &sock_b, GUID_B, Some(&incoming))?;
    guest_b
        .wait_for_markers(&[CHANGE_MARKER], TIMEOUT)
        .context("generation-change detection after restore")?;

    // ── Liveness: the resumed guest still draws and schedules ───────────────
    step("vmgenid test: post-resume liveness round (help via QMP)");
    qmp::inject_events(&sock_b, EVENTS).context("QMP key injection after resume")?;
    let live = guest_b.wait_for_markers(&[CHILD_LINE], TIMEOUT);
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
