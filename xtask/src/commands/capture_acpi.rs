// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/commands/capture_acpi.rs

//! `capture-acpi`: refresh the ACPI table fixtures of `shared/aml` from one
//! QEMU configuration.
//!
//! The firmware boots alone, on a blank disk, in the tree's launch of the
//! configuration's architecture with the test devices attached. Once it
//! reaches its boot options, by which point it has installed the tables QEMU
//! generated, the command stops the guest and saves its RAM over QMP
//! (`stop`, `pmemsave`), and QEMU quits. The capture is then pure: find every
//! checksum-valid RSDP in the RAM image, walk its XSDT (its RSDT when it has
//! none) with every table's checksum checked, take the DSDT from the FADT,
//! and write the DSDT and the SSDTs, in XSDT order, with a note of the
//! capture. Every RSDP the walk accepts must give the same tables: a stale
//! copy the firmware left behind is no different table set.

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use anyhow::{Context as _, Result, bail};

use crate::arch::Arch;
use crate::cli::{AcpiConfig, CaptureAcpiArgs};
use crate::context::Context;
use crate::firmware::find_ovmf_code;
use crate::guest::Guest;
use crate::qemu::{
    GdbMode, Iommu, QemuDisplay, QemuLaunchSpec, RiscvMmu, RiscvZkr, X86Paging, build_qemu_argv,
    prepare_riscv_firmware,
};
use crate::qmp;
use crate::util::{require_tool, step};

/// vCPUs and RAM of the capture, those of the tree's default boot: the
/// tables describe both (the processor objects, the PCI host bridge's
/// 32-bit window above RAM).
const CPUS: u32 = 4;
const MEM_MIB: u32 = 512;

/// Serial lines the firmware prints when it tries its boot options, after it
/// has installed the ACPI tables: OVMF's release build (`BdsDxe: loading
/// Boot0001 ...`) and the riscv64 firmware's debug build (`[Bds]Booting ...`).
const BOOT_OPTION_MARKERS: &[&str] = &["BdsDxe: ", "[Bds]Booting "];

/// Size of the blank disk the firmware finds nothing to boot on.
const BLANK_DISK_BYTES: u64 = 1 << 20;

/// The note written beside the tables.
const NOTE_FILE: &str = "capture.txt";

/// Length of an ACPI system description table header.
const SDT_HEADER_LEN: usize = 36;

/// Length of the ACPI 1.0 part of the RSDP, which its checksum covers.
const RSDP_V1_LEN: usize = 20;

/// Length of an ACPI 2.0 RSDP, which its extended checksum covers.
const RSDP_V2_LEN: usize = 36;

/// FADT offsets of the 32-bit `DSDT` and the 64-bit `X_DSDT` pointers.
const FADT_DSDT: usize = 40;
const FADT_X_DSDT: usize = 140;

/// The configuration's name: its fixture directory and its `--config` value.
const fn config_name(config: AcpiConfig) -> &'static str
{
    match config
    {
        AcpiConfig::X86Default => "x86-default",
        AcpiConfig::X86Rootport => "x86-rootport",
        AcpiConfig::X86RootportNative => "x86-rootport-native",
        AcpiConfig::Riscv64Rootport => "riscv64-rootport",
    }
}

const fn config_arch(config: AcpiConfig) -> Arch
{
    match config
    {
        AcpiConfig::X86Default | AcpiConfig::X86Rootport | AcpiConfig::X86RootportNative =>
        {
            Arch::X86_64
        }
        AcpiConfig::Riscv64Rootport => Arch::Riscv64,
    }
}

/// The arguments the configuration adds to the tree's launch.
const fn config_args(config: AcpiConfig) -> &'static [&'static str]
{
    match config
    {
        AcpiConfig::X86Default => &[],
        AcpiConfig::X86Rootport => &["-device", "pcie-root-port,id=rp0,chassis=1,addr=0x1c"],
        AcpiConfig::X86RootportNative => &[
            "-device",
            "pcie-root-port,id=rp0,chassis=1,addr=0x1c",
            "-global",
            "ICH9-LPC.acpi-pci-hotplug-with-bridge-support=off",
        ],
        AcpiConfig::Riscv64Rootport => &["-device", "pcie-root-port,id=rp0,chassis=1"],
    }
}

/// Guest-physical address of the first byte of RAM.
const fn ram_base(arch: Arch) -> u64
{
    match arch
    {
        Arch::X86_64 => 0,
        Arch::Riscv64 => 0x8000_0000,
    }
}

pub fn run(ctx: &Context, args: &CaptureAcpiArgs) -> Result<()>
{
    let name = config_name(args.config);
    let arch = config_arch(args.config);
    let out = args.out.clone().unwrap_or_else(|| {
        ctx.root
            .join("shared")
            .join("aml")
            .join("fixtures")
            .join(name)
    });
    let qemu_binary = require_tool(arch.qemu_binary())?;
    let qemu_version = qemu_version(&qemu_binary)?;

    let work = ctx.target_dir.join("xtask").join("capture-acpi").join(name);
    fs::create_dir_all(&work).with_context(|| format!("creating {}", work.display()))?;
    let disk = work.join("blank.img");
    // Beside `work`, not in it: a UNIX socket's path is under 108 bytes.
    // One per configuration, as `work` is, so captures of two
    // configurations run side by side never reach each other's QEMU.
    let sock = ctx
        .target_dir
        .join("xtask")
        .join(format!("acpi-{name}.sock"));
    let dump = work.join("memory.bin");
    for p in [&sock, &dump]
    {
        let _ = fs::remove_file(p);
    }
    fs::File::create(&disk)
        .and_then(|f| f.set_len(BLANK_DISK_BYTES))
        .with_context(|| format!("creating {}", disk.display()))?;

    let (code, vars) = firmware(ctx, arch, &work)?;
    let spec = QemuLaunchSpec {
        arch,
        disk_path: &disk,
        disk_block_size: 512,
        second_disk: None,
        firmware_code_path: &code,
        firmware_vars_path: vars.as_deref(),
        cpus: CPUS,
        mem_mib: MEM_MIB,
        display: QemuDisplay::Headless,
        gdb: GdbMode::Off,
        qmp_socket: Some(&sock),
        vmgenid_guid: match arch
        {
            Arch::X86_64 => Some("auto"),
            Arch::Riscv64 => None,
        },
        incoming: None,
        riscv_mmu: RiscvMmu::Sv48,
        riscv_zkr: RiscvZkr::On,
        x86_paging: X86Paging::Four,
        iommu: Iommu::Attached,
        debug_port: None,
        test_devices: true,
    };
    let mut qemu_args = build_qemu_argv(&spec)?;
    qemu_args.extend(config_args(args.config).iter().map(|a| (*a).to_owned()));

    let base = ram_base(arch);
    // Held until the command returns, after its QEMU has exited.
    let _host = crate::host_lock::admit_boot(ctx, &args.host, CPUS, 1)?;
    step(&format!(
        "capture-acpi {name}: booting the firmware to its boot options"
    ));
    save_ram(
        &qemu_binary,
        &qemu_args,
        Duration::from_secs(args.timeout),
        base,
        &sock,
        &dump,
    )?;

    let memory = fs::read(&dump).with_context(|| format!("reading {}", dump.display()))?;
    let tables = find_tables(&Memory {
        base,
        bytes: &memory,
    })?;
    let mut host_paths = vec![
        (disk.as_path(), "<disk>"),
        (code.as_path(), "<firmware-code>"),
        (sock.as_path(), "<qmp-socket>"),
    ];
    if let Some(v) = &vars
    {
        host_paths.push((v.as_path(), "<firmware-vars>"));
    }
    let launch = Launch {
        command: format!("cargo xtask capture-acpi --config {name}"),
        qemu_version,
        firmware: file_name(&code),
        argv: redact(&qemu_args, &host_paths),
    };
    let written = write_fixtures(&out, &tables, &launch)?;
    for p in [&dump, &sock, &disk]
    {
        let _ = fs::remove_file(p);
    }
    step(&format!(
        "capture-acpi {name}: wrote {} to {}",
        written.join(", "),
        out.display()
    ));
    Ok(())
}

/// Boot QEMU with `qemu_args` until the firmware reaches its boot options,
/// at most `timeout`, then save the guest's RAM, which starts at
/// guest-physical `base`, to `dump` over the QMP socket `sock`, and quit.
fn save_ram(
    qemu_binary: &Path,
    qemu_args: &[String],
    timeout: Duration,
    base: u64,
    sock: &Path,
    dump: &Path,
) -> Result<()>
{
    let child = Command::new(qemu_binary)
        .args(qemu_args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| format!("spawning {}", qemu_binary.display()))?;
    // Every `?` below drops the live `Guest`, which kills and reaps its QEMU.
    let mut guest = Guest::from_child(child)?;
    guest
        .wait_for_any(BOOT_OPTION_MARKERS, timeout)
        .context("waiting for the firmware's boot options")?;
    step("capture-acpi: saving guest RAM");
    let size = u64::from(MEM_MIB)
        .checked_mul(1 << 20)
        .context("guest RAM size overflows")?;
    qmp::save_memory(sock, base, size, dump).context("saving guest RAM")?;
    qmp::quit(sock).context("quitting QEMU")?;
    guest.wait_exit(Duration::from_secs(30))
}

/// The firmware's code image, and on riscv64 a fresh copy of its variable
/// store in `work` (x86 runs with volatile NVRAM).
fn firmware(ctx: &Context, arch: Arch, work: &Path) -> Result<(PathBuf, Option<PathBuf>)>
{
    match arch
    {
        Arch::X86_64 => Ok((find_ovmf_code()?, None)),
        Arch::Riscv64 =>
        {
            let (code, template) = prepare_riscv_firmware(ctx)?;
            let vars = work.join("VARS.fd");
            fs::copy(&template, &vars)
                .with_context(|| format!("copying {} to {}", template.display(), vars.display()))?;
            Ok((code, Some(vars)))
        }
    }
}

/// The first line of `qemu --version`.
fn qemu_version(qemu: &Path) -> Result<String>
{
    let out = Command::new(qemu)
        .arg("--version")
        .output()
        .with_context(|| format!("running {} --version", qemu.display()))?;
    let text = String::from_utf8_lossy(&out.stdout);
    Ok(text.lines().next().unwrap_or_default().trim().to_owned())
}

/// The final component of `path`, or the whole path when it has none.
fn file_name(path: &Path) -> String
{
    path.file_name()
        .unwrap_or(path.as_os_str())
        .to_string_lossy()
        .into_owned()
}

/// `argv` as one line, each host path of `paths` replaced by its placeholder,
/// so the note carries no path of the host it was captured on.
fn redact(argv: &[String], paths: &[(&Path, &str)]) -> String
{
    argv.iter()
        .map(|a| {
            paths.iter().fold(a.clone(), |acc, (path, placeholder)| {
                acc.replace(path.to_string_lossy().as_ref(), placeholder)
            })
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// What the note records of the launch.
struct Launch
{
    command: String,
    qemu_version: String,
    firmware: String,
    argv: String,
}

/// Replace the `.aml` files of `out` with the tables and write the note;
/// returns the names written.
fn write_fixtures(out: &Path, tables: &Tables, launch: &Launch) -> Result<Vec<String>>
{
    fs::create_dir_all(out).with_context(|| format!("creating {}", out.display()))?;
    for entry in fs::read_dir(out).with_context(|| format!("reading {}", out.display()))?
    {
        let path = entry?.path();
        if path
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("aml"))
        {
            fs::remove_file(&path).with_context(|| format!("removing {}", path.display()))?;
        }
    }
    let files = fixture_files(tables);
    for (file, bytes) in &files
    {
        let path = out.join(file);
        fs::write(&path, bytes).with_context(|| format!("writing {}", path.display()))?;
    }
    let note_path = out.join(NOTE_FILE);
    fs::write(&note_path, note(tables, &files, launch))
        .with_context(|| format!("writing {}", note_path.display()))?;
    Ok(files.into_iter().map(|(f, _)| f).collect())
}

/// The fixture files of `tables`: `DSDT.aml`, then `SSDT1.aml`, `SSDT2.aml`,
/// ... in XSDT order, the order a loader loads them in.
fn fixture_files(tables: &Tables) -> Vec<(String, &[u8])>
{
    core::iter::once(("DSDT.aml".to_owned(), tables.dsdt.as_slice()))
        .chain(
            tables
                .ssdts
                .iter()
                .zip(1u32..)
                .map(|(t, i)| (format!("SSDT{i}.aml"), t.as_slice())),
        )
        .collect()
}

/// The note of a capture: how to repeat it and what it found.
fn note(tables: &Tables, files: &[(String, &[u8])], launch: &Launch) -> String
{
    let mut s = String::new();
    // Writing to a `String` cannot fail.
    let _ = writeln!(
        s,
        "ACPI tables of a QEMU guest, written by `{}`.\n\
         Regenerate them with that command; do not edit them.\n\
         \n\
         QEMU: {}\n\
         Firmware: {}\n\
         QEMU arguments: {}\n\
         \n\
         Root table entries: {}\n\
         Files:",
        launch.command,
        launch.qemu_version,
        launch.firmware,
        launch.argv,
        tables.signatures.join(" "),
    );
    for (file, bytes) in files
    {
        let _ = writeln!(s, "  {file} ({} bytes)", bytes.len());
    }
    s
}

// ── Table walk ────────────────────────────────────────────────────────────────

/// A RAM image of the guest: `bytes` hold guest-physical `base` onward.
struct Memory<'a>
{
    base: u64,
    bytes: &'a [u8],
}

impl Memory<'_>
{
    /// `len` bytes at guest-physical `addr`, or `None` outside the image.
    fn at(&self, addr: u64, len: usize) -> Option<&[u8]>
    {
        let start = usize::try_from(addr.checked_sub(self.base)?).ok()?;
        self.bytes.get(start..start.checked_add(len)?)
    }

    /// The system description table at `addr`, its length and checksum
    /// checked.
    fn table(&self, addr: u64) -> Result<&[u8]>
    {
        let header = self
            .at(addr, SDT_HEADER_LEN)
            .with_context(|| format!("table at {addr:#x} lies outside RAM"))?;
        let len = le_u32(header, 4).and_then(|l| usize::try_from(l).ok());
        let Some(len) = len.filter(|l| *l >= SDT_HEADER_LEN)
        else
        {
            bail!("table at {addr:#x} has a length below its header's");
        };
        let table = self
            .at(addr, len)
            .with_context(|| format!("table at {addr:#x} runs past RAM"))?;
        if !checksum_ok(table)
        {
            bail!("table {} at {addr:#x} fails its checksum", signature(table));
        }
        Ok(table)
    }
}

/// The tables a capture writes.
#[derive(Debug, PartialEq, Eq)]
struct Tables
{
    /// The signatures of the XSDT's (or RSDT's) entries, in order.
    signatures: Vec<String>,
    dsdt: Vec<u8>,
    /// The SSDTs, in XSDT order.
    ssdts: Vec<Vec<u8>>,
}

/// The tables of `memory`: those of every RSDP whose walk succeeds, which
/// must agree.
fn find_tables(memory: &Memory) -> Result<Tables>
{
    let rsdps = find_rsdps(memory);
    if rsdps.is_empty()
    {
        bail!("no RSDP with a valid checksum in guest RAM");
    }
    let mut found: Option<Tables> = None;
    let mut errors = Vec::new();
    for rsdp in rsdps
    {
        match walk(memory, rsdp)
        {
            Ok(t) => match &found
            {
                None => found = Some(t),
                Some(f) if *f == t =>
                {}
                Some(_) => bail!("the RSDPs of guest RAM describe different tables"),
            },
            Err(e) => errors.push(format!("RSDP at {rsdp:#x}: {e:#}")),
        }
    }
    found.with_context(|| format!("no RSDP's tables walk cleanly: {}", errors.join("; ")))
}

/// Guest-physical addresses of every RSDP in `memory`: the signature on a
/// 16-byte boundary, the checksum valid, and from revision 2 the extended
/// checksum too.
fn find_rsdps(memory: &Memory) -> Vec<u64>
{
    let (chunks, _) = memory.bytes.as_chunks::<16>();
    chunks
        .iter()
        .zip((memory.base..).step_by(16))
        .filter(|(c, addr)| c.starts_with(b"RSD PTR ") && rsdp_valid(memory, *addr))
        .map(|(_, addr)| addr)
        .collect()
}

/// Whether the RSDP at `addr` passes its checksum and, from revision 2, its
/// extended checksum over the length it states.
fn rsdp_valid(memory: &Memory, addr: u64) -> bool
{
    let Some(v1) = memory.at(addr, RSDP_V1_LEN)
    else
    {
        return false;
    };
    if !checksum_ok(v1)
    {
        return false;
    }
    if v1.get(15).is_some_and(|revision| *revision < 2)
    {
        return true;
    }
    let len = memory
        .at(addr, RSDP_V2_LEN)
        .and_then(|v2| le_u32(v2, 20))
        .and_then(|l| usize::try_from(l).ok())
        .filter(|l| *l >= RSDP_V2_LEN);
    len.and_then(|l| memory.at(addr, l))
        .is_some_and(checksum_ok)
}

/// Walk the RSDP at `rsdp`: its XSDT when it has one (revision 2 and a
/// non-zero address), its RSDT otherwise.
fn walk(memory: &Memory, rsdp: u64) -> Result<Tables>
{
    let v1 = memory.at(rsdp, RSDP_V1_LEN).context("RSDP outside RAM")?;
    let revision = v1.get(15).copied().unwrap_or_default();
    let xsdt = if revision >= 2
    {
        memory
            .at(rsdp, RSDP_V2_LEN)
            .and_then(|v2| le_u64(v2, 24))
            .unwrap_or_default()
    }
    else
    {
        0
    };
    let (root, entry_len) = if xsdt == 0
    {
        (u64::from(le_u32(v1, 16).unwrap_or_default()), 4)
    }
    else
    {
        (xsdt, 8)
    };
    let root_table = memory.table(root)?;
    let entries = root_table.get(SDT_HEADER_LEN..).unwrap_or_default();
    let mut signatures = Vec::new();
    let mut dsdt = None;
    let mut ssdts = Vec::new();
    for entry in entries.chunks(entry_len)
    {
        let addr = match entry_len
        {
            4 => le_u32(entry, 0).map(u64::from),
            _ => le_u64(entry, 0),
        }
        .with_context(|| format!("root table at {root:#x} ends inside an entry"))?;
        let table = memory.table(addr)?;
        let sig = signature(table);
        if sig == "FACP"
        {
            dsdt = Some(fadt_dsdt(memory, table)?);
        }
        else if sig == "SSDT"
        {
            ssdts.push(table.to_vec());
        }
        signatures.push(sig);
    }
    let dsdt = dsdt.context("the root table lists no FADT")?;
    Ok(Tables {
        signatures,
        dsdt,
        ssdts,
    })
}

/// The DSDT the FADT `fadt` points to: `X_DSDT` when the FADT is long
/// enough to hold it and it is non-zero, the 32-bit `DSDT` otherwise.
fn fadt_dsdt(memory: &Memory, fadt: &[u8]) -> Result<Vec<u8>>
{
    let x_dsdt = le_u64(fadt, FADT_X_DSDT).unwrap_or_default();
    let addr = if x_dsdt == 0
    {
        u64::from(le_u32(fadt, FADT_DSDT).context("FADT too short for its DSDT")?)
    }
    else
    {
        x_dsdt
    };
    let dsdt = memory.table(addr)?;
    if signature(dsdt) != "DSDT"
    {
        bail!(
            "the FADT's DSDT at {addr:#x} is a {} table",
            signature(dsdt)
        );
    }
    Ok(dsdt.to_vec())
}

/// Whether the bytes of `table` sum to zero, modulo 256.
fn checksum_ok(table: &[u8]) -> bool
{
    table.iter().fold(0u8, |sum, b| sum.wrapping_add(*b)) == 0
}

/// The four-byte signature of a table, as text.
fn signature(table: &[u8]) -> String
{
    String::from_utf8_lossy(table.get(..4).unwrap_or_default()).into_owned()
}

fn le_u32(bytes: &[u8], at: usize) -> Option<u32>
{
    Some(u32::from_le_bytes(
        bytes.get(at..at.checked_add(4)?)?.try_into().ok()?,
    ))
}

fn le_u64(bytes: &[u8], at: usize) -> Option<u64>
{
    Some(u64::from_le_bytes(
        bytes.get(at..at.checked_add(8)?)?.try_into().ok()?,
    ))
}

#[cfg(test)]
mod tests
{
    use clap::ValueEnum as _;

    use super::*;

    /// Guest-physical base of the test images.
    const BASE: u64 = 0x10_0000;

    /// A table with signature `sig` and `body` after its header, its length
    /// and checksum set.
    fn sdt(sig: [u8; 4], body: &[u8]) -> Vec<u8>
    {
        let mut t = vec![0u8; SDT_HEADER_LEN];
        t.splice(..4, sig);
        t.extend_from_slice(body);
        let len = u32::try_from(t.len()).unwrap().to_le_bytes();
        t.splice(4..8, len);
        fix_checksum(&mut t, 9);
        t
    }

    /// Set the byte at `at` so the bytes of `t` sum to zero.
    fn fix_checksum(t: &mut [u8], at: usize)
    {
        t[at] = 0;
        let sum = t.iter().fold(0u8, |s, b| s.wrapping_add(*b));
        t[at] = 0u8.wrapping_sub(sum);
    }

    /// An RSDP of `revision` pointing to `rsdt` and, from revision 2, to
    /// `xsdt`.
    fn rsdp(revision: u8, rsdt: u32, xsdt: u64) -> Vec<u8>
    {
        let mut r = vec![0u8; RSDP_V2_LEN];
        r.splice(..8, *b"RSD PTR ");
        r[15] = revision;
        r.splice(16..20, rsdt.to_le_bytes());
        r.splice(20..24, u32::try_from(RSDP_V2_LEN).unwrap().to_le_bytes());
        r.splice(24..32, xsdt.to_le_bytes());
        fix_checksum(&mut r[..RSDP_V1_LEN], 8);
        fix_checksum(&mut r, 32);
        r
    }

    /// A FADT `len` bytes long pointing to `dsdt` and `x_dsdt`.
    fn fadt(len: usize, dsdt: u32, x_dsdt: u64) -> Vec<u8>
    {
        let mut body = vec![0u8; len - SDT_HEADER_LEN];
        body.splice(
            FADT_DSDT - SDT_HEADER_LEN..FADT_DSDT - SDT_HEADER_LEN + 4,
            dsdt.to_le_bytes(),
        );
        if len >= FADT_X_DSDT + 8
        {
            body.splice(
                FADT_X_DSDT - SDT_HEADER_LEN..FADT_X_DSDT - SDT_HEADER_LEN + 8,
                x_dsdt.to_le_bytes(),
            );
        }
        sdt(*b"FACP", &body)
    }

    /// A RAM image under construction: tables placed at 16-byte aligned
    /// offsets.
    struct Image
    {
        bytes: Vec<u8>,
    }

    impl Image
    {
        fn new() -> Self
        {
            // The low 0x100 bytes are left for the RSDP.
            Self {
                bytes: vec![0u8; 0x100],
            }
        }

        /// Append `t`; returns its guest-physical address.
        fn place(&mut self, t: &[u8]) -> u64
        {
            let addr = BASE + u64::try_from(self.bytes.len()).unwrap();
            self.bytes.extend_from_slice(t);
            self.bytes.resize(self.bytes.len().next_multiple_of(16), 0);
            addr
        }

        /// Write `t` at guest-physical `addr`.
        fn put(&mut self, addr: u64, t: &[u8])
        {
            let at = usize::try_from(addr - BASE).unwrap();
            self.bytes[at..at + t.len()].copy_from_slice(t);
        }

        fn memory(&self) -> Memory<'_>
        {
            Memory {
                base: BASE,
                bytes: &self.bytes,
            }
        }
    }

    /// The tables of a q35-like layout: a FADT (long, with `X_DSDT`), a
    /// MADT, and two SSDTs, listed by an XSDT and an RSDT.
    struct Layout
    {
        image: Image,
        dsdt: Vec<u8>,
        ssdts: [Vec<u8>; 2],
        xsdt: u64,
        rsdt: u32,
    }

    fn layout(fadt_len: usize) -> Layout
    {
        let mut image = Image::new();
        let dsdt = sdt(*b"DSDT", &[0x10, 0x05, 0x5C, 0x5F, 0x53, 0x42, 0x5F]);
        let dsdt_at = image.place(&dsdt);
        let fadt_at = image.place(&fadt(fadt_len, u32::try_from(dsdt_at).unwrap(), dsdt_at));
        let apic_at = image.place(&sdt(*b"APIC", &[0; 8]));
        let ssdts = [sdt(*b"SSDT", &[0xA3]), sdt(*b"SSDT", &[0xA3, 0xA3])];
        let s1 = image.place(&ssdts[0]);
        let s2 = image.place(&ssdts[1]);
        let order = [fadt_at, s1, apic_at, s2];
        let xsdt_body: Vec<u8> = order.iter().flat_map(|a| a.to_le_bytes()).collect();
        let xsdt = image.place(&sdt(*b"XSDT", &xsdt_body));
        let rsdt_body: Vec<u8> = order
            .iter()
            .flat_map(|a| u32::try_from(*a).unwrap().to_le_bytes())
            .collect();
        let rsdt = u32::try_from(image.place(&sdt(*b"RSDT", &rsdt_body))).unwrap();
        Layout {
            image,
            dsdt,
            ssdts,
            xsdt,
            rsdt,
        }
    }

    fn expected(l: &Layout) -> Tables
    {
        Tables {
            signatures: ["FACP", "SSDT", "APIC", "SSDT"].map(String::from).to_vec(),
            dsdt: l.dsdt.clone(),
            ssdts: l.ssdts.to_vec(),
        }
    }

    #[test]
    fn config_names_are_their_cli_values()
    {
        for c in AcpiConfig::value_variants()
        {
            let value = c.to_possible_value().unwrap();
            assert_eq!(value.get_name(), config_name(*c));
        }
    }

    #[test]
    fn an_xsdt_gives_the_fadt_dsdt_and_the_ssdts_in_order()
    {
        let mut l = layout(244);
        let r = rsdp(2, l.rsdt, l.xsdt);
        l.image.put(BASE + 0x40, &r);
        assert_eq!(find_tables(&l.image.memory()).unwrap(), expected(&l));
    }

    #[test]
    fn a_revision_0_rsdp_walks_the_rsdt()
    {
        let mut l = layout(244);
        // The XSDT field is past a revision-0 RSDP and is not read.
        let r = rsdp(0, l.rsdt, 0xDEAD_0000);
        l.image.put(BASE + 0x40, &r);
        assert_eq!(find_tables(&l.image.memory()).unwrap(), expected(&l));
    }

    #[test]
    fn a_short_fadt_gives_its_32_bit_dsdt()
    {
        // An ACPI 1.0 FADT is 116 bytes: no `X_DSDT`.
        let mut l = layout(116);
        let r = rsdp(2, l.rsdt, l.xsdt);
        l.image.put(BASE + 0x40, &r);
        assert_eq!(find_tables(&l.image.memory()).unwrap(), expected(&l));
    }

    #[test]
    fn rsdps_off_alignment_or_with_bad_checksums_are_not_found()
    {
        let mut l = layout(244);
        let mut bad = rsdp(2, l.rsdt, l.xsdt);
        bad[8] = bad[8].wrapping_add(1);
        l.image.put(BASE + 0x40, &bad);
        let mut bad_ext = rsdp(2, l.rsdt, l.xsdt);
        bad_ext[32] = bad_ext[32].wrapping_add(1);
        l.image.put(BASE + 0x80, &bad_ext);
        l.image.put(BASE + 0xC8, &rsdp(2, l.rsdt, l.xsdt));
        assert_eq!(find_rsdps(&l.image.memory()), Vec::<u64>::new());
        find_tables(&l.image.memory()).unwrap_err();
    }

    #[test]
    fn rsdps_that_agree_give_one_table_set_and_a_broken_one_is_passed_over()
    {
        let mut l = layout(244);
        l.image.put(BASE + 0x40, &rsdp(2, l.rsdt, l.xsdt));
        l.image.put(BASE + 0x80, &rsdp(0, l.rsdt, 0));
        // A stale RSDP whose XSDT lies outside RAM.
        l.image.put(BASE + 0xC0, &rsdp(2, 0, 0xFFFF_0000));
        assert_eq!(
            find_rsdps(&l.image.memory()),
            vec![BASE + 0x40, BASE + 0x80, BASE + 0xC0]
        );
        assert_eq!(find_tables(&l.image.memory()).unwrap(), expected(&l));
    }

    #[test]
    fn rsdps_that_disagree_fail_the_capture()
    {
        let mut l = layout(244);
        l.image.put(BASE + 0x40, &rsdp(2, l.rsdt, l.xsdt));
        // A second root table listing the FADT alone.
        let fadt_at = BASE + u64::try_from(0x100 + l.dsdt.len().next_multiple_of(16)).unwrap();
        let other = l.image.place(&sdt(*b"XSDT", &fadt_at.to_le_bytes()));
        l.image.put(BASE + 0x80, &rsdp(2, 0, other));
        let err = find_tables(&l.image.memory()).unwrap_err();
        assert!(format!("{err:#}").contains("different tables"), "{err:#}");
    }

    #[test]
    fn a_table_with_a_bad_checksum_fails_the_walk()
    {
        let mut l = layout(244);
        l.image.put(BASE + 0x40, &rsdp(2, l.rsdt, l.xsdt));
        // The second SSDT's body byte, flipped.
        let mut s2 = l.ssdts[1].clone();
        s2[SDT_HEADER_LEN] ^= 1;
        let s2_at = l
            .image
            .bytes
            .windows(s2.len())
            .position(|w| w == l.ssdts[1].as_slice())
            .unwrap();
        l.image.put(BASE + u64::try_from(s2_at).unwrap(), &s2);
        let err = find_tables(&l.image.memory()).unwrap_err();
        assert!(format!("{err:#}").contains("SSDT"), "{err:#}");
        assert!(format!("{err:#}").contains("checksum"), "{err:#}");
    }

    #[test]
    fn a_root_table_without_a_fadt_fails_the_walk()
    {
        let mut l = layout(244);
        let apic = l.image.place(&sdt(*b"APIC", &[]));
        let xsdt = l.image.place(&sdt(*b"XSDT", &apic.to_le_bytes()));
        l.image.put(BASE + 0x40, &rsdp(2, 0, xsdt));
        let err = find_tables(&l.image.memory()).unwrap_err();
        assert!(format!("{err:#}").contains("no FADT"), "{err:#}");
    }

    #[test]
    fn fixture_files_name_the_ssdts_in_xsdt_order()
    {
        let t = Tables {
            signatures: Vec::new(),
            dsdt: vec![1],
            ssdts: vec![vec![2], vec![3]],
        };
        let names: Vec<String> = fixture_files(&t).into_iter().map(|(n, _)| n).collect();
        assert_eq!(names, ["DSDT.aml", "SSDT1.aml", "SSDT2.aml"]);
    }

    #[test]
    fn redact_replaces_every_host_path()
    {
        let argv = [
            "-drive".to_owned(),
            "if=none,id=hd0,format=raw,file=/h/w/blank.img".to_owned(),
            "-qmp".to_owned(),
            "unix:/h/w/qmp.sock,server,nowait".to_owned(),
        ];
        let line = redact(
            &argv,
            &[
                (Path::new("/h/w/blank.img"), "<disk>"),
                (Path::new("/h/w/qmp.sock"), "<qmp-socket>"),
            ],
        );
        assert_eq!(
            line,
            "-drive if=none,id=hd0,format=raw,file=<disk> -qmp unix:<qmp-socket>,server,nowait"
        );
    }
}
