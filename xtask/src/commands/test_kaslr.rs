// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// commands/test_kaslr.rs

//! KASLR randomization test (#252). Both arches.
//!
//! Proves the kernel image base and direct-map base are randomized at boot,
//! and that the `\EFI\seraph\nokaslr` override knob forces the deterministic
//! layout:
//!
//! 1. **Boot A / Boot B** with KASLR enabled: scrape the kernel's serial-only
//!    `kaslr: slide=… image_base=… dm_base=…` line and assert the joint
//!    `(slide, dm_base)` differs between the two boots (a single-dimension
//!    collision is ~1/1000; the joint compare plus one retry bounds a false
//!    failure at ~1e-8).
//! 2. **Boot C** with the `nokaslr` knob staged: assert `slide == 0`, the
//!    image at its link base, and the direct map at the mode floor.
//!
//! A pure runner: requires a populated sysroot with the ktest bundle composed
//! (`cargo xtask compose-bundle --harness ktest`). The kaslr line is emitted
//! in Phase 1, long before the harness runs, so the test does not depend on
//! ktest completing.

use std::io::BufReader;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail};

use crate::arch::Arch;
use crate::cli::TestKaslrArgs;
use crate::commands::mkdisk::stage_nokaslr_knob;
use crate::context::Context;
use crate::firmware::find_ovmf_code;
use crate::qemu::{
    GdbMode, QemuLaunchSpec, build_qemu_argv, prepare_riscv_firmware, validate_sysroot_for_launch,
};
use crate::util::{require_tool, step};

/// Prefix of the kernel's serial-only KASLR diagnostic line.
const KASLR_MARKER: &str = "kaslr: slide=";

/// Wall-clock budget per boot: only Phase 1 is needed, but allow for slow
/// firmware / TCG startup.
const TIMEOUT: Duration = Duration::from_mins(2);

/// The kernel's link-time image base (`KERNEL_VBASE`), mirrored from
/// `boot_protocol::layout` for the knob assertion (the per-mode direct-map
/// floors are in [`mode_floor`]).
const KERNEL_LINK_BASE: u64 = 0xFFFF_FFFF_8000_0000;

/// Parsed KASLR layout from one boot's serial line.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
struct Layout
{
    slide: u64,
    image_base: u64,
    dm_base: u64,
}

struct Guest
{
    child: Child,
    lines: mpsc::Receiver<String>,
    reader: Option<thread::JoinHandle<()>>,
}

impl Guest
{
    fn launch(
        qemu_binary: &Path,
        ctx: &Context,
        args: &TestKaslrArgs,
        firmware_code: &Path,
        firmware_vars: Option<&Path>,
    ) -> Result<Self>
    {
        let disk_path = ctx.disk_image();
        let spec = QemuLaunchSpec {
            arch: args.arch,
            disk_path: &disk_path,
            firmware_code_path: firmware_code,
            firmware_vars_path: firmware_vars,
            cpus: args.cpus,
            mem_mib: args.mem,
            headless: true,
            gdb: GdbMode::Off,
            qmp_socket: None,
            // x86-64 launches exercise the snapshot-reseed consumer by default;
            // irrelevant to KASLR but harmless.
            vmgenid_guid: if args.arch == Arch::X86_64
            {
                Some("auto")
            }
            else
            {
                None
            },
            incoming: None,
            riscv_mmu: args.riscv_mmu,
        };
        let qemu_args = build_qemu_argv(&spec)?;

        let mut child = Command::new(qemu_binary)
            .args(&qemu_args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .with_context(|| format!("spawning {}", qemu_binary.display()))?;
        let stdout = child.stdout.take().context("QEMU stdout unavailable")?;

        let (tx, rx) = mpsc::channel::<String>();
        let reader = thread::spawn(move || {
            let buf = BufReader::new(stdout);
            for line in std::io::BufRead::lines(buf)
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

        Ok(Self {
            child,
            lines: rx,
            reader: Some(reader),
        })
    }

    /// Echo serial lines until one contains `KASLR_MARKER`, parse it, and
    /// return the layout.
    fn scrape_layout(&mut self, deadline: Instant) -> Result<Layout>
    {
        loop
        {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero()
            {
                bail!("timed out waiting for the kaslr line");
            }
            let Ok(line) = self.lines.recv_timeout(remaining)
            else
            {
                bail!("serial stream ended before the kaslr line");
            };
            println!("{line}");
            if let Some(layout) = parse_kaslr_line(&line)
            {
                return Ok(layout);
            }
        }
    }

    fn shutdown(mut self)
    {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(r) = self.reader.take()
        {
            let _ = r.join();
        }
    }
}

/// Parse `… kaslr: slide=0x… image_base=0x… dm_base=0x…` into a [`Layout`].
fn parse_kaslr_line(line: &str) -> Option<Layout>
{
    let rest = line.split_once(KASLR_MARKER)?.1;
    let mut fields = rest.split_whitespace();
    let slide = parse_hex_field(fields.next()?)?;
    let image_base = parse_hex_field(fields.next()?.strip_prefix("image_base=")?)?;
    let dm_base = parse_hex_field(fields.next()?.strip_prefix("dm_base=")?)?;
    Some(Layout {
        slide,
        image_base,
        dm_base,
    })
}

/// Parse `0x…` (optionally still carrying a `key=` prefix already stripped).
fn parse_hex_field(field: &str) -> Option<u64>
{
    let hex = field.strip_prefix("0x")?;
    u64::from_str_radix(hex, 16).ok()
}

pub fn run(ctx: &Context, args: &TestKaslrArgs) -> Result<()>
{
    validate_sysroot_for_launch(ctx, args.arch)?;
    let qemu_binary = require_tool(args.arch.qemu_binary())?;

    // Resolve firmware once; riscv64 needs a writable vars pflash.
    let (code, vars) = match args.arch
    {
        Arch::X86_64 => (find_ovmf_code()?, None),
        Arch::Riscv64 =>
        {
            let (c, v) = prepare_riscv_firmware(ctx)?;
            (c, Some(v))
        }
    };
    let vars_ref = vars.as_deref();

    let scrape = |label: &str| -> Result<Layout> {
        step(&format!("kaslr test: {label}"));
        let mut guest = Guest::launch(&qemu_binary, ctx, args, &code, vars_ref)?;
        let res = guest.scrape_layout(Instant::now() + TIMEOUT);
        guest.shutdown();
        res.with_context(|| label.to_string())
    };

    // ── Two-boot-differs, with one retry on a joint collision ───────────────
    let a = scrape("boot A (KASLR on)")?;
    let mut b = scrape("boot B (KASLR on)")?;
    if (a.slide, a.dm_base) == (b.slide, b.dm_base)
    {
        step("kaslr test: joint collision — retrying boot B once");
        b = scrape("boot B retry (KASLR on)")?;
    }
    if (a.slide, a.dm_base) == (b.slide, b.dm_base)
    {
        bail!("KASLR did not randomize: boot A {a:?} == boot B {b:?} on both slide and dm_base");
    }
    step(&format!(
        "kaslr test: randomized OK (A slide={:#x} dm={:#x}; B slide={:#x} dm={:#x})",
        a.slide, a.dm_base, b.slide, b.dm_base
    ));

    // ── Knob: deterministic layout ──────────────────────────────────────────
    // Stage the knob, always restore it, even on failure.
    stage_nokaslr_knob(ctx, true).context("staging nokaslr knob")?;
    crate::disk::create_disk_image(ctx, args.arch).context("repacking disk with knob")?;
    let knob_result = scrape("boot C (--no-kaslr)");
    // Always restore first and surface its failure ahead of the boot-C result:
    // leaving the knob staged would silently disable KASLR for later runs, so a
    // failed restore is the more urgent error to report.
    stage_nokaslr_knob(ctx, false)
        .and_then(|()| crate::disk::create_disk_image(ctx, args.arch))
        .context("restoring KASLR-enabled disk")?;
    let c = knob_result?;

    if c.slide != 0 || c.image_base != KERNEL_LINK_BASE
    {
        bail!("nokaslr knob did not disable image randomization: {c:?}");
    }
    if c.dm_base != mode_floor(args)
    {
        bail!(
            "nokaslr knob direct map {:#x} is not the mode floor {:#x}",
            c.dm_base,
            mode_floor(args)
        );
    }
    step("kaslr test: --no-kaslr deterministic layout OK");

    step("KASLR test: PASS (randomized image + direct-map base; knob deterministic)");
    Ok(())
}

/// The deterministic direct-map floor for the launch's arch/mode, matching
/// the bootloader's `default_direct_map_base`.
fn mode_floor(args: &TestKaslrArgs) -> u64
{
    use crate::qemu::RiscvMmu;
    match args.arch
    {
        Arch::X86_64 => 0xFFFF_8000_0000_0000,
        Arch::Riscv64 => match args.riscv_mmu
        {
            RiscvMmu::Sv39 => 0xFFFF_FFC0_0000_0000,
            RiscvMmu::Sv48 => 0xFFFF_8000_0000_0000,
            RiscvMmu::Sv57 => 0xFF00_0000_0000_0000,
        },
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn parses_a_real_line()
    {
        let line = "[--------] kernel: kaslr: slide=0x1f200000 \
                    image_base=0xffffffff9f200000 dm_base=0xfffffabbc0000000";
        let l = parse_kaslr_line(line).expect("parse");
        assert_eq!(l.slide, 0x1f20_0000);
        assert_eq!(l.image_base, 0xffff_ffff_9f20_0000);
        assert_eq!(l.dm_base, 0xffff_fabb_c000_0000);
    }

    #[test]
    fn parses_zero_slide_knob_line()
    {
        let line = "kaslr: slide=0x0 image_base=0xffffffff80000000 dm_base=0xff00000000000000";
        let l = parse_kaslr_line(line).expect("parse");
        assert_eq!(l.slide, 0);
        assert_eq!(l.image_base, KERNEL_LINK_BASE);
        assert_eq!(l.dm_base, 0xff00_0000_0000_0000);
    }

    #[test]
    fn ignores_non_kaslr_lines()
    {
        assert!(parse_kaslr_line("kernel: Phase 1: Early Console").is_none());
    }
}
