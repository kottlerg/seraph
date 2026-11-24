// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/commands/test/storage_roles.rs

//! Storage roles test: vfsd gives each storage role to the boot disk, the
//! disk at the PCI location the bootloader reported that carries the boot
//! ESP, or to the partition the signed storage statement names on the disk
//! it binds it to, and to no other disk (docs/storage.md § GPT Role-GUID
//! Discovery). Both arches.
//!
//! Five boots of the default boot set, each to the terminal's
//! [`READY_MARKER`] and swapd's taking of the swap partition, or its line
//! that it has none ([`NO_SWAP_MARKER`]), read vfsd's lines: the boot
//! controller it was told of, the boot disk it found there, and, for each
//! role (the root, `/esp`, `/data` and swap), the partition it took and the
//! location of its disk, or why it took none.
//!
//! 1. **Split**: the images in the split-data layout, `disk-data.img` on the
//!    second slot. The statement the layout stages names `/data` and swap
//!    on the disk at that slot's location: the root and `/esp` are on the
//!    boot disk, `/data` and swap named on the second disk.
//! 2. **Moved**: the same images, `disk-data.img` at another slot
//!    (`SecondSlot::Moved`). The root and `/esp` are on the boot disk;
//!    `/data` and swap are not taken, vfsd naming the disk it saw their
//!    partitions on, and swapd has no partition.
//! 3. **Foreign, higher priority**: the single image, and on the second slot a
//!    foreign disk ([`crate::disk::create_foreign_image`]) whose ESP, root,
//!    data and swap partitions carry priority `0xFFFF`, above `disk.img`'s.
//! 4. **Foreign, equal priority**: the same at `disk.img`'s priority, 0.
//! 5. **Copy**: the single image, and a copy of `disk.img` on the second
//!    slot, which carries the boot ESP too.
//!
//! In the last three, every role is on the boot disk, and the boot disk is
//! the disk at the boot controller: a role given to the second disk, or no
//! boot disk, fails the case.
//!
//! A pure runner: requires a populated sysroot from `cargo xtask build`. The
//! split boot repacks the images in the split-data layout when they are not
//! in it, and the images are repacked in the layout they had afterwards.

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use crate::error::{Context as _, Result, bail};

use crate::arch::Arch;
use crate::commands::test::cases::CaseArgs;
use crate::context::Context;
use crate::disk::{DataDisk, DataPlacement, DiskLayout};
use crate::guest::Guest;
use crate::qemu::{
    Firmware, GdbMode, Iommu, QemuDisplay, QemuLaunchSpec, SecondDisk, SecondSlot, build_qemu_argv,
    validate_sysroot_for_launch,
};
use crate::util::{require_tool, step};

/// The terminal's line once the boot set is up.
const READY_MARKER: &str = "terminal: READY for injection";

/// swapd's line once it took the swap partition and registered it.
const SWAP_MARKER: &str = "swap partition: ";

/// swapd's line when vfsd hands it no swap partition. Kept in sync with
/// `services/swapd/src/main.rs`.
const NO_SWAP_MARKER: &str = "no swap partition; swap stays in RAM";

/// The text of vfsd's line for a role whose named partition is not on the
/// disk the statement binds it to, after the role's name and up to that
/// disk. Kept in sync with `resolve_role` in `services/vfsd/src/main.rs`.
const ELSEWHERE_MARKER: &str = ": no partition named by the storage statement: not on ";

/// vfsd's line naming the location the bootloader reported, its text from
/// `PCI ` on.
const CONTROLLER_MARKER: &str = "boot controller: ";

/// vfsd's line naming the boot disk and its location.
const BOOT_DISK_MARKER: &str = "boot disk: disk ";

/// vfsd's line when it found no boot disk.
const NO_BOOT_DISK_MARKER: &str = "no boot disk: ";

/// Wall-clock budget of one boot, to both markers.
const TIMEOUT: Duration = Duration::from_mins(4);

/// The roles a boot resolves, as vfsd's lines name them.
const ROLES: [&str; 4] = ["root", "/esp", "/data", "swap"];

/// Where a boot must find a role's partition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum On
{
    /// On the boot disk, by type and priority (the ESP: the one the
    /// firmware booted).
    BootDisk,
    /// On the second disk, named by the storage statement.
    Named,
    /// Taken by no partition: its named partition is on a disk outside the
    /// place the statement binds it to.
    Untaken,
}

/// One boot of the case.
struct Boot<'a>
{
    label: &'a str,
    /// The disk on the second slot.
    second: &'a Path,
    /// The second slot.
    slot: SecondSlot,
    /// Where each of [`ROLES`] must be found.
    roles: [On; 4],
}

pub fn run(ctx: &Context, args: &CaseArgs) -> Result<()>
{
    validate_sysroot_for_launch(ctx, args.arch)?;
    // Held until the case returns, after its last QEMU has exited.
    let _host = crate::host_lock::admit_boot(ctx, &args.host, args.cpus, 1)?;
    let qemu_binary = require_tool(args.arch.qemu_binary())?;
    // Read before any repack, so a failed repack cannot change the layout the
    // restore writes.
    let layout = crate::disk::current_layout(ctx)?;
    let firmware = Firmware::prepare(ctx, args.arch)?;
    let scratch = ctx.target_dir.join("xtask").join("storage-roles");
    std::fs::create_dir_all(&scratch).with_context(|| format!("creating {}", scratch.display()))?;

    let boot = |boot: &Boot<'_>| -> Result<()> {
        step(&format!("storage-roles test: {}", boot.label));
        // Removed when the boot returns, after the guest is shut down.
        let vars = firmware.launch_vars()?;
        let mut guest = launch(
            &qemu_binary,
            ctx,
            args,
            &firmware.code,
            vars.path(),
            boot.second,
            boot.slot,
        )?;
        let lines = collect(&mut guest);
        guest.shutdown();
        check(&lines?, boot.roles).with_context(|| boot.label.to_owned())
    };

    let split = DiskLayout {
        block_size: layout.block_size,
        data: DataPlacement::SecondImage(DataDisk::Slot),
    };
    let single = DiskLayout {
        block_size: layout.block_size,
        data: DataPlacement::MainImage,
    };
    let foreign = scratch.join("foreign.img");
    let copy = scratch.join("disk-copy.img");
    let result = (|| -> Result<()> {
        crate::disk::create_disk_image(ctx, args.arch, split)
            .context("packing the split layout")?;
        boot(&Boot {
            label: "split: /data and swap named on the second disk",
            second: &ctx.data_disk_image(),
            slot: SecondSlot::Named,
            roles: [On::BootDisk, On::BootDisk, On::Named, On::Named],
        })?;
        boot(&Boot {
            label: "moved: /data and swap named on a disk at another slot",
            second: &ctx.data_disk_image(),
            slot: SecondSlot::Moved,
            roles: [On::BootDisk, On::BootDisk, On::Untaken, On::Untaken],
        })?;
        crate::disk::create_disk_image(ctx, args.arch, single)
            .context("packing the single image")?;
        for (label, priority) in [
            ("a foreign disk at priority 0xFFFF", 0xFFFF),
            ("a foreign disk at equal priority", 0),
        ]
        {
            crate::disk::create_foreign_image(&foreign, args.arch, layout.block_size, priority)?;
            boot(&Boot {
                label,
                second: &foreign,
                slot: SecondSlot::Named,
                roles: [On::BootDisk; 4],
            })?;
        }
        std::fs::copy(ctx.disk_image(), &copy)
            .with_context(|| format!("copying the boot disk to {}", copy.display()))?;
        boot(&Boot {
            label: "a copy of the boot disk",
            second: &copy,
            slot: SecondSlot::Named,
            roles: [On::BootDisk; 4],
        })
    })();
    let _ = std::fs::remove_dir_all(&scratch);
    // Restore before reporting the boots' result: a later case boots the
    // layout it found.
    crate::disk::create_disk_image(ctx, args.arch, layout).context("restoring the images")?;
    result?;
    step("storage-roles test: PASS (roles on the boot disk or named; none on another disk)");
    Ok(())
}

/// Launch QEMU on the current `disk.img` with `second` at `slot`, and the
/// variable store `firmware_vars`.
fn launch(
    qemu_binary: &Path,
    ctx: &Context,
    args: &CaseArgs,
    firmware_code: &Path,
    firmware_vars: &Path,
    second: &Path,
    slot: SecondSlot,
) -> Result<Guest>
{
    let disk_path = ctx.disk_image();
    let spec = QemuLaunchSpec {
        arch: args.arch,
        disk_path: &disk_path,
        disk_block_size: crate::disk::logical_block_size(&disk_path)?,
        second_disk: Some(SecondDisk {
            slot,
            ..SecondDisk::of_image(second)?
        }),
        firmware_code_path: firmware_code,
        firmware_vars_path: firmware_vars,
        smm: false,
        cpus: args.cpus,
        threads_per_core: 1,
        mem_mib: args.mem,
        display: QemuDisplay::Headless,
        gdb: GdbMode::Off,
        qmp_socket: None,
        vmgenid_guid: (args.arch == Arch::X86_64).then_some("auto"),
        incoming: None,
        riscv_mmu: args.riscv_mmu,
        riscv_zkr: crate::qemu::RiscvZkr::On,
        x86_paging: args.x86_paging,
        x86_shadow_stack: crate::qemu::X86ShadowStack::Off,
        iommu: Iommu::Attached,
        debug_port: None,
        test_devices: false,
        hotplug_port: None,
    };
    let qemu_args = build_qemu_argv(&spec)?;
    let child = Command::new(qemu_binary)
        .args(&qemu_args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("spawning {}", qemu_binary.display()))?;
    Guest::from_child(child)
}

/// The boot's serial lines up to both [`READY_MARKER`] and [`SWAP_MARKER`]
/// or [`NO_SWAP_MARKER`], in either order, within [`TIMEOUT`]; ended early
/// by vfsd's [`NO_BOOT_DISK_MARKER`], which halts the boot.
fn collect(guest: &mut Guest) -> Result<Vec<String>>
{
    let start = std::time::Instant::now();
    let mut lines = Vec::new();
    let mut pending = vec![READY_MARKER, SWAP_MARKER];
    while !pending.is_empty()
    {
        let mut awaited = pending.clone();
        awaited.push(NO_BOOT_DISK_MARKER);
        if pending.contains(&SWAP_MARKER)
        {
            awaited.push(NO_SWAP_MARKER);
        }
        let read = guest.collect_until_any(&awaited, TIMEOUT.saturating_sub(start.elapsed()))?;
        let last = read.last().cloned().unwrap_or_default();
        lines.extend(read);
        if last.contains(NO_BOOT_DISK_MARKER)
        {
            break;
        }
        pending.retain(|marker| {
            !(last.contains(marker) || *marker == SWAP_MARKER && last.contains(NO_SWAP_MARKER))
        });
    }
    Ok(lines)
}

/// Check a boot's `lines`: vfsd found the boot disk at the boot controller,
/// and each of [`ROLES`] where `roles` says: on the boot disk, at its
/// location; named, by the statement and at another; untaken, its named
/// partition seen on a disk at another location than the one the statement
/// binds it to and not taken, and for swap, swapd given none.
fn check(lines: &[String], roles: [On; 4]) -> Result<()>
{
    if let Some(line) = lines.iter().find(|line| line.contains(NO_BOOT_DISK_MARKER))
    {
        bail!("vfsd found no boot disk: {line}");
    }
    let controller = after(lines, CONTROLLER_MARKER).context("vfsd logged no boot controller")?;
    if !controller.starts_with("PCI ")
    {
        bail!("the boot controller has no PCI location: {controller}");
    }
    let boot_disk = after(lines, BOOT_DISK_MARKER).context("vfsd logged no boot disk")?;
    let boot_at = location(boot_disk).context("the boot disk line names no location")?;
    if boot_at != controller
    {
        bail!("the boot disk is at {boot_at}, not at the boot controller, {controller}");
    }
    for (role, on) in ROLES.into_iter().zip(roles)
    {
        let marker = format!("{role}: partition ");
        if on == On::Untaken
        {
            if let Some(line) = after(lines, &marker)
            {
                bail!("{role} was taken off the disk its statement binds it to: {line}");
            }
            untaken(lines, role, controller)?;
            continue;
        }
        let line = after(lines, &marker)
            .with_context(|| format!("vfsd logged no partition for {role}"))?;
        let at = location(line).with_context(|| format!("{role}: no location in {line}"))?;
        let named = line.starts_with("named by the storage statement");
        match on
        {
            On::BootDisk if named || at != controller =>
            {
                bail!("{role} is not on the boot disk ({controller}): {line}")
            }
            On::Named if !named || at == controller =>
            {
                bail!("{role} is not the statement's partition on the second disk: {line}")
            }
            On::BootDisk | On::Named | On::Untaken =>
            {}
        }
    }
    Ok(())
}

/// Check that `role` took no partition for the reason the moved boot
/// stages: vfsd's line places the named partition on a disk at another
/// location than the one the statement binds it to, neither being the boot
/// controller's; for swap, swapd logged that it has none.
fn untaken(lines: &[String], role: &str, controller: &str) -> Result<()>
{
    let line = after(lines, &format!("{role}{ELSEWHERE_MARKER}"))
        .with_context(|| format!("vfsd logged no sighting of {role}'s named partition"))?;
    let (bound, seen) = line
        .split_once("; seen on disk ")
        .and_then(|(bound, rest)| Some((bound, location(rest.strip_suffix("; not taken")?)?)))
        .with_context(|| format!("{role}: no bound disk and sighting in {line}"))?;
    if !bound.starts_with("PCI ") || bound == seen || bound == controller || seen == controller
    {
        bail!(
            "{role}: the named partition is not seen off its disk, apart from the boot disk: {line}"
        );
    }
    if role == "swap" && !lines.iter().any(|line| line.contains(NO_SWAP_MARKER))
    {
        bail!("swapd did not log that it has no swap partition");
    }
    Ok(())
}

/// The text after `marker` on the first of `lines` that holds it.
fn after<'a>(lines: &'a [String], marker: &str) -> Option<&'a str>
{
    lines
        .iter()
        .find_map(|line| line.split_once(marker).map(|(_, rest)| rest.trim_end()))
}

/// The location a vfsd line ends in: the text after its last ` at `.
fn location(line: &str) -> Option<&str>
{
    line.rsplit_once(" at ").map(|(_, at)| at)
}

#[cfg(test)]
mod tests
{
    use super::*;

    fn lines(text: &[&str]) -> Vec<String>
    {
        text.iter().map(|line| format!("[vfsd] {line}")).collect()
    }

    const CONTROLLER: &str = "boot controller: PCI 0000:00:10.0";
    const BOOT_DISK: &str = "boot disk: disk 0 at PCI 0000:00:10.0";
    const ROOT: &str =
        "root: partition on the boot disk at block 133120 on disk 0 at PCI 0000:00:10.0";
    const ESP: &str =
        "/esp: partition on the boot disk at block 2048 on disk 0 at PCI 0000:00:10.0";

    // Defect caught: a role given to the second disk, or a boot disk away
    // from the boot controller, read as a pass.
    #[test]
    fn a_role_on_another_disk_than_it_must_fails()
    {
        let on_boot = lines(&[
            CONTROLLER,
            BOOT_DISK,
            ROOT,
            ESP,
            "/data: partition on the boot disk at block 264192 on disk 0 at PCI 0000:00:10.0",
            "swap: partition on the boot disk at block 395264 on disk 0 at PCI 0000:00:10.0",
        ]);
        check(&on_boot, [On::BootDisk; 4]).unwrap();
        check(&on_boot, [On::BootDisk, On::BootDisk, On::Named, On::Named]).unwrap_err();

        let named = lines(&[
            CONTROLLER,
            BOOT_DISK,
            ROOT,
            ESP,
            "/data: partition named by the storage statement at block 2048 on disk 1 at PCI 0000:00:12.0",
            "swap: partition named by the storage statement at block 133120 on disk 1 at PCI 0000:00:12.0",
        ]);
        check(&named, [On::BootDisk, On::BootDisk, On::Named, On::Named]).unwrap();
        check(&named, [On::BootDisk; 4]).unwrap_err();

        let stray = lines(&[
            CONTROLLER,
            BOOT_DISK,
            "root: partition on the boot disk at block 133120 on disk 1 at PCI 0000:00:12.0",
            ESP,
            "/data: partition on the boot disk at block 264192 on disk 0 at PCI 0000:00:10.0",
            "swap: partition on the boot disk at block 395264 on disk 0 at PCI 0000:00:10.0",
        ]);
        check(&stray, [On::BootDisk; 4]).unwrap_err();

        let elsewhere = lines(&[
            CONTROLLER,
            "boot disk: disk 1 at PCI 0000:00:12.0",
            ROOT,
            ESP,
        ]);
        check(&elsewhere, [On::BootDisk; 4]).unwrap_err();
    }

    // Defect caught: a role taken from a disk at another location than its
    // statement binds it to, or untaken with no line naming where its
    // partition was seen, read as the moved boot's pass.
    #[test]
    fn a_role_named_off_its_disk_must_be_untaken_and_seen()
    {
        let moved = [On::BootDisk, On::BootDisk, On::Untaken, On::Untaken];
        let mut untaken = lines(&[
            CONTROLLER,
            BOOT_DISK,
            ROOT,
            ESP,
            "/data: no partition named by the storage statement: not on PCI 0000:00:12.0; seen on disk 1 at PCI 0000:00:11.0; not taken",
            "swap: no partition named by the storage statement: not on PCI 0000:00:12.0; seen on disk 1 at PCI 0000:00:11.0; not taken",
        ]);
        untaken.push("[swapd] no swap partition; swap stays in RAM".into());
        check(&untaken, moved).unwrap();
        check(&untaken[..untaken.len() - 1], moved).unwrap_err();
        check(&untaken, [On::BootDisk; 4]).unwrap_err();

        let taken = lines(&[
            CONTROLLER,
            BOOT_DISK,
            ROOT,
            ESP,
            "/data: partition named by the storage statement at block 2048 on disk 1 at PCI 0000:00:11.0",
            "swap: no partition named by the storage statement: not on PCI 0000:00:12.0; seen on disk 1 at PCI 0000:00:11.0; not taken",
            "[swapd] no swap partition; swap stays in RAM",
        ]);
        check(&taken, moved).unwrap_err();

        let unseen = lines(&[
            CONTROLLER,
            BOOT_DISK,
            ROOT,
            ESP,
            "/data: no partition named by the storage statement on PCI 0000:00:12.0: none found",
            "swap: no partition named by the storage statement: not on PCI 0000:00:12.0; seen on disk 1 at PCI 0000:00:11.0; not taken",
            "[swapd] no swap partition; swap stays in RAM",
        ]);
        check(&unseen, moved).unwrap_err();
    }

    // Defect caught: a boot with no boot disk, or a role vfsd logged no
    // partition for, read as a pass.
    #[test]
    fn no_boot_disk_or_a_missing_role_fails()
    {
        let none = lines(&[
            CONTROLLER,
            "no boot disk: no disk at the reported location; no disk takes a storage role",
        ]);
        check(&none, [On::BootDisk; 4]).unwrap_err();
        let missing = lines(&[CONTROLLER, BOOT_DISK, ROOT, ESP]);
        check(&missing, [On::BootDisk; 4]).unwrap_err();
    }
}
