// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/qemu.rs

//! Shared QEMU argv construction and per-launch pflash cache for RISC-V.
//!
//! Every command that launches QEMU (`run`, `run-parallel`, `test-kaslr`,
//! `test-terminal`, `test-vmgenid`) produces its command line from the same
//! source of truth (`build_qemu_argv`). Firmware discovery lives in
//! `firmware::{find_ovmf_code, find_riscv_firmware}`; the padding +
//! caching of RISC-V pflash images stays here in `prepare_riscv_firmware`.
//! Acceleration-backend selection lives in `accel::detect_for_arch`. The
//! interactive launch loop (stdout filtering, terminal restore) stays in
//! `commands/run.rs`; `run-parallel` spawns QEMU directly against per-slot
//! log files.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context as _, Result, bail};
use clap::ValueEnum;

use crate::accel::{self, Accel};
use crate::arch::Arch;
use crate::context::Context;
use crate::firmware;
use crate::sysroot;

/// QEMU virt machine requires pflash images to be exactly 32 MiB.
const PFLASH_SIZE: u64 = 32 * 1024 * 1024;

/// GDB stub exposure for a QEMU launch.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum GdbMode
{
    /// No gdbstub.
    Off,
    /// Expose the gdbstub (`-s`, `tcp::1234`) without pausing the guest, so a
    /// host debugger can attach after a hang is observed.
    Listen,
    /// Expose the gdbstub and freeze at the first instruction (`-s -S`).
    Freeze,
}

/// Guest RISC-V paging mode ceiling for a QEMU launch.
///
/// Selects which `svNN` satp modes the guest CPU advertises (DTB `mmu-type`
/// plus the satp write-probe both follow it); the kernel negotiates the
/// highest advertised mode it supports at boot. QEMU >= 8.0 defaults the
/// rv64 CPU to sv57, so the sv48 default here pins the guest to the
/// project's standing Sv48 baseline rather than QEMU's.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum RiscvMmu
{
    /// Cap the guest at Sv39 (`sv57=off,sv48=off`).
    Sv39,
    /// Cap the guest at Sv48 (`sv57=off`) — the default.
    Sv48,
    /// Enable Sv57 (`sv57=on`, explicit against QEMU default drift).
    Sv57,
}

impl RiscvMmu
{
    /// `-cpu` property suffix that pins the guest's satp-mode ceiling.
    fn cpu_satp_props(self) -> &'static str
    {
        match self
        {
            Self::Sv39 => ",sv57=off,sv48=off",
            Self::Sv48 => ",sv57=off",
            Self::Sv57 => ",sv57=on",
        }
    }
}

/// Guest x86-64 paging depth for a QEMU launch.
///
/// Pins the guest CPU's `la57` property on every accelerator, so the CPUID
/// LA57 bit the bootloader reads (and with it the depth the kernel recovers
/// from `CR4.LA57`) is the one the run asks for. The 4-level default keeps a
/// TCG `-cpu max` guest, which otherwise advertises LA57, on 4-level paging.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum X86Paging
{
    /// 4-level paging (`la57=off`) — the default.
    #[value(name = "4")]
    Four,
    /// 5-level paging (`la57=on`).
    #[value(name = "5")]
    Five,
}

impl X86Paging
{
    /// `-cpu` property suffix that pins the guest's LA57 bit.
    fn cpu_la57_prop(self) -> &'static str
    {
        match self
        {
            Self::Four => ",la57=off",
            Self::Five => ",la57=on",
        }
    }
}

/// The DMA test device every launch attaches: QEMU's `edu` (PCI
/// `1234:11e8`), with its default 28-bit DMA mask.
const EDU_DEVICE: &str = "edu";

/// The RISC-V IOMMU as a PCI function, pinned at 00:01.0, the lowest slot
/// past the host bridge. `off=off` leaves it in Bare mode out of reset,
/// passing DMA through untranslated until it is programmed; its default, Off
/// mode, blocks all DMA, so the firmware could not read the boot disk. QEMU's
/// ACPI RIMT describes the IOMMU as translating only the requester IDs above
/// its own, while QEMU translates every function of the bus, so a device on
/// a lower slot would be translated with no firmware description devmgr
/// could confine it by; at 00:01.0 every other function lies above it.
const RISCV_IOMMU_DEVICE: &str = "riscv-iommu-pci,off=off,addr=0x01";

/// Whether a QEMU launch attaches the machine's IOMMU (`--iommu`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Iommu
{
    /// `intel-iommu` on q35, `riscv-iommu-pci` on `virt`, with every
    /// `virtio-pci` device a driver of the system binds behind it
    /// (`iommu_platform=on`) — the default.
    Attached,
    /// No IOMMU: the no-IOMMU variant, the no-iommu device cell of the local
    /// and release host runs, in which devmgr runs every device unconfined.
    Absent,
}

impl Iommu
{
    /// The `virtio-pci` device property that puts the device behind the
    /// IOMMU (`iommu_platform=on`, so it offers `VIRTIO_F_ACCESS_PLATFORM`
    /// and its DMA is translated); empty with no IOMMU. Without it QEMU's
    /// `virtio-pci` devices reach memory directly, past the IOMMU.
    fn virtio_property(self) -> &'static str
    {
        match self
        {
            Self::Attached => ",iommu_platform=on",
            Self::Absent => "",
        }
    }
}

/// A second disk for a QEMU launch: its image, the logical block size its
/// device presents, and whether it shares the first disk's `INTx` line.
pub struct SecondDisk<'a>
{
    pub path: &'a Path,
    /// Logical and physical block size of the `virtio-blk-pci` device, in
    /// bytes.
    pub block_size: u32,
    /// Place the device at `SHARED_LINE_SECOND_DISK_SLOT`, on the first
    /// disk's `INTx` line on both machines, rather than at
    /// `SECOND_DISK_SLOT`, on a line of its own.
    pub shared_line: bool,
}

/// Specification for one QEMU launch.
///
/// `firmware_code_path` is the readonly pflash (OVMF on x86, `RISCV_VIRT_CODE`
/// on riscv64). `firmware_vars_path` is the writable pflash and is only used
/// on riscv64 — x86 runs with volatile NVRAM and leaves the field `None`.
pub struct QemuLaunchSpec<'a>
{
    pub arch: Arch,
    pub disk_path: &'a Path,
    /// Logical and physical block size the disk's `virtio-blk-pci` device
    /// presents, in bytes; launch sites read it from the image
    /// ([`crate::disk::logical_block_size`]) so the device matches its GPT.
    pub disk_block_size: u32,
    /// A second disk attached as its own `virtio-blk-pci` device (drive
    /// `hd1`), or `None` for the single-disk default.
    pub second_disk: Option<SecondDisk<'a>>,
    pub firmware_code_path: &'a Path,
    pub firmware_vars_path: Option<&'a Path>,
    pub cpus: u32,
    /// Guest memory size in MiB.
    pub mem_mib: u32,
    pub headless: bool,
    pub gdb: GdbMode,
    /// When set, expose a QMP control socket at this path
    /// (`-qmp unix:<path>,server,nowait`) so a host harness can drive the
    /// guest — the interactive-input test injects keys this way.
    pub qmp_socket: Option<&'a Path>,
    /// VMGENID device GUID (`-device vmgenid,guid=<value>`; `"auto"` =
    /// host-random). `x86_64` only — the `riscv64` `virt` machine has no
    /// VMGENID ACPI support in QEMU — and launch sites pass `Some("auto")` by
    /// default so every `x86_64` boot exercises the kernel's snapshot-reseed
    /// consumer.
    pub vmgenid_guid: Option<&'a str>,
    /// Inbound migration URI (`-incoming <uri>`); the snapshot-resume test
    /// restores a migrate-to-file state through this.
    pub incoming: Option<&'a str>,
    /// Guest paging-mode ceiling; riscv64 only, ignored on `x86_64`.
    pub riscv_mmu: RiscvMmu,
    /// Guest paging depth; `x86_64` only, ignored on riscv64.
    pub x86_paging: X86Paging,
    /// Whether the machine's IOMMU is attached; every launch site attaches it
    /// unless the run asks for the no-IOMMU variant (`--iommu absent`).
    pub iommu: Iommu,
}

/// The device arguments a launch passes before every other device: the
/// RISC-V IOMMU when attached, so it takes its pinned slot before any
/// auto-placed device can (`RISCV_IOMMU_DEVICE`); none on q35, whose
/// `intel-iommu` is no PCI function (`extend_x86` adds it).
fn leading_devices(spec: &QemuLaunchSpec) -> Vec<String>
{
    if spec.arch == Arch::Riscv64 && spec.iommu == Iommu::Attached
    {
        vec!["-device".into(), RISCV_IOMMU_DEVICE.into()]
    }
    else
    {
        Vec::new()
    }
}

/// Construct the full QEMU argv for a launch spec.
///
/// Pairs with `Arch::qemu_binary()` for the binary name. The returned vector
/// is suitable for `Command::new(binary).args(&argv)`.
pub fn build_qemu_argv(spec: &QemuLaunchSpec) -> Result<Vec<String>>
{
    // The boot protocol caps a BootInfo's CPU count at MAX_CPUS; a guest with
    // more vCPUs than that would boot with the surplus dropped.
    let max_cpus = boot_protocol::MAX_CPUS;
    if spec.cpus == 0 || usize::try_from(spec.cpus).map_or(true, |c| c > max_cpus)
    {
        bail!(
            "--cpus {} out of range: must be 1..={} (boot-protocol MAX_CPUS)",
            spec.cpus,
            max_cpus
        );
    }
    if spec.mem_mib == 0
    {
        bail!("--mem 0 is not a bootable guest memory size");
    }
    check_block_size(spec.disk_block_size)?;

    let mut args: Vec<String> = vec![
        "-m".into(),
        format!("{}M", spec.mem_mib),
        "-smp".into(),
        spec.cpus.to_string(),
    ];
    args.extend(leading_devices(spec));
    args.extend([
        "-drive".into(),
        format!(
            "if=none,id=hd0,format=raw,file={}",
            spec.disk_path.display()
        ),
        "-device".into(),
        blk_device(
            "hd0",
            spec.disk_block_size,
            spec.second_disk.as_ref().map(|_| FIRST_DISK_SLOT),
            spec.iommu,
        ),
    ]);

    if let Some(second) = &spec.second_disk
    {
        check_block_size(second.block_size)?;
        args.extend([
            "-drive".into(),
            format!("if=none,id=hd1,format=raw,file={}", second.path.display()),
            "-device".into(),
            blk_device(
                "hd1",
                second.block_size,
                Some(
                    if second.shared_line
                    {
                        SHARED_LINE_SECOND_DISK_SLOT
                    }
                    else
                    {
                        SECOND_DISK_SLOT
                    },
                ),
                spec.iommu,
            ),
        ]);
    }

    args.extend([
        // Keyboard back-end for the virtio-input driver. PCI on both arches
        // (the riscv64 `virt` machine has a PCIe bridge, same as virtio-blk).
        // `id=kbd0` lets the QMP interactive-test harness target it.
        "-device".into(),
        format!(
            "virtio-keyboard-pci,disable-legacy=on,id=kbd0{}",
            spec.iommu.virtio_property()
        ),
        // Boot-entropy source (KASLR, #252). The firmware's RNG driver binds
        // this device and exposes EFI_RNG_PROTOCOL, which the bootloader draws
        // from for the KASLR slide / direct-map base and the pool seed. On
        // riscv64 it is the only such source (EDK2 hands the bootloader ACPI,
        // not a DTB, so /chosen/rng-seed never reaches it); on x86-64 it backs
        // OVMF's EFI_RNG_PROTOCOL alongside RDRAND. It stays outside the
        // IOMMU: QEMU's transitional `virtio-rng-pci` cannot take
        // `iommu_platform=on`, and only the firmware drives it, before any
        // driver of the system runs.
        "-device".into(),
        "virtio-rng-pci".into(),
        "-serial".into(),
        "stdio".into(),
        "-no-reboot".into(),
    ]);

    if spec.headless
    {
        args.extend(["-display".into(), "none".into()]);
    }

    if let Some(sock) = spec.qmp_socket
    {
        args.extend([
            "-qmp".into(),
            format!("unix:{},server,nowait", sock.display()),
        ]);
    }

    if let Some(uri) = spec.incoming
    {
        args.extend(["-incoming".into(), uri.into()]);
    }

    match spec.gdb
    {
        GdbMode::Off =>
        {}
        GdbMode::Listen => args.push("-s".into()),
        GdbMode::Freeze => args.extend(["-s".into(), "-S".into()]),
    }

    let accel = accel::detect_for_arch(spec.arch);
    match spec.arch
    {
        Arch::X86_64 => extend_x86(&mut args, spec, accel, host_cpu_has_la57())?,
        Arch::Riscv64 => extend_riscv(&mut args, spec)?,
    }

    Ok(args)
}

/// PCI slots of the two disks of a two-disk launch (a single disk takes
/// QEMU's next free slot). On `x86_64` OVMF programs a slot's `INTA` line
/// from `{10, 10, 11, 11}` indexed by `(slot + 1) % 4`, which pairs adjacent
/// slots, and on riscv64 the `virt` host swizzles `INTA` onto PLIC source
/// `32 + slot % 4`. `SECOND_DISK_SLOT`, two slots past the first, avoids
/// the share on both machines, so the ordinary two-disk boots give each disk
/// a line of its own. `SHARED_LINE_SECOND_DISK_SLOT`, four slots past the
/// first, lands on the first disk's line on both machines (the same index
/// into OVMF's table, the same PLIC source), which the shared-line boot
/// stages on purpose. Every slot sits below 25, past which q35 routes every
/// slot to one line, above the slots auto-placed devices take, and clear of
/// q35's built-in slot 0x1f.
const FIRST_DISK_SLOT: u8 = 0x10;
const SECOND_DISK_SLOT: u8 = FIRST_DISK_SLOT + 2;
const SHARED_LINE_SECOND_DISK_SLOT: u8 = FIRST_DISK_SLOT + 4;

/// The `virtio-blk-pci` device for `drive`, presenting `block_size`-byte
/// logical and physical blocks (QEMU requires the physical size to be at
/// least the logical), at PCI slot `slot` when one is given, behind the
/// IOMMU when `iommu` attaches one.
fn blk_device(drive: &str, block_size: u32, slot: Option<u8>, iommu: Iommu) -> String
{
    let addr = slot.map_or_else(String::new, |slot| format!(",addr={slot:#04x}"));
    format!(
        "virtio-blk-pci,drive={drive},disable-legacy=on{},logical_block_size={block_size},\
         physical_block_size={block_size}{addr}",
        iommu.virtio_property()
    )
}

/// Refuse a device block size below 512 bytes or not a power of two, which
/// QEMU refuses at launch. Its upper bound, which varies by QEMU version, is
/// left to QEMU; a size the guest's driver refuses (above its
/// `MAX_BLOCK_SIZE`) is a valid launch.
fn check_block_size(block_size: u32) -> Result<()>
{
    if !block_size.is_power_of_two() || block_size < 512
    {
        bail!("block size {block_size} out of range: must be a power of two of at least 512");
    }
    Ok(())
}

/// Whether the host CPU reports LA57 (`CPUID.(EAX=07H,ECX=0):ECX[16]`),
/// which a native accelerator needs to give an `x86_64` guest 5-level paging.
#[cfg(target_arch = "x86_64")]
fn host_cpu_has_la57() -> bool
{
    let max_leaf = std::arch::x86_64::__cpuid_count(0, 0).eax;
    max_leaf >= 7 && std::arch::x86_64::__cpuid_count(7, 0).ecx & (1 << 16) != 0
}

/// A host that is not `x86_64` runs an `x86_64` guest under TCG only, where
/// the host CPU's features do not reach the guest.
#[cfg(not(target_arch = "x86_64"))]
fn host_cpu_has_la57() -> bool
{
    false
}

/// Refuse a 5-level request a native accelerator cannot honour.
///
/// A native accelerator passes the host CPU's paging features through, and
/// QEMU drops a requested `la57=on` the host lacks with a warning only, so
/// the guest would boot 4-level while the run claims 5. TCG emulates LA57 on
/// any host.
fn check_x86_paging(paging: X86Paging, accel: Accel, host_has_la57: bool) -> Result<()>
{
    if paging == X86Paging::Five && accel != Accel::Tcg && !host_has_la57
    {
        bail!(
            "--x86-paging 5 needs LA57, which this host's CPU does not report, so the \
             {accel:?} accelerator cannot provide it; boot 5-level under TCG instead: \
             SERAPH_ACCEL=tcg cargo xtask <command> --x86-paging 5"
        );
    }
    Ok(())
}

fn extend_x86(
    args: &mut Vec<String>,
    spec: &QemuLaunchSpec,
    accel: Accel,
    host_has_la57: bool,
) -> Result<()>
{
    check_x86_paging(spec.x86_paging, accel, host_has_la57)?;
    let la57 = spec.x86_paging.cpu_la57_prop();
    args.extend(["-machine".into(), "q35".into()]);

    // VT-d DMA remapping. Interrupt remapping stays off: it needs
    // `kernel-irqchip=split` under KVM, which QEMU otherwise refuses, and
    // message-signaled interrupts, which the system does not use yet.
    if spec.iommu == Iommu::Attached
    {
        args.extend(["-device".into(), "intel-iommu,intremap=off".into()]);
    }
    // QEMU's `edu` device, whose DMA engine svctest's DMA confinement phase
    // drives through the test-only `test-dma` driver: behind the IOMMU when
    // one is attached, unconfined otherwise. No production driver binds it.
    args.extend(["-device".into(), EDU_DEVICE.into()]);

    if let Some(guid) = spec.vmgenid_guid
    {
        args.extend(["-device".into(), format!("vmgenid,guid={guid}")]);
    }

    match accel
    {
        Accel::Kvm =>
        {
            // -cpu host inherits the development host's microarchitecture;
            // the kernel asserts x86-64-v3 in early init, so the host must
            // advertise AVX2/BMI2/FMA (Haswell+ / Excavator+).
            args.extend(["-enable-kvm".into(), "-cpu".into(), format!("host{la57}")]);
        }
        Accel::Hvf =>
        {
            // macOS Hypervisor.framework. Same -cpu host rationale as KVM;
            // HVF passes host features through to the guest natively.
            args.extend([
                "-accel".into(),
                "hvf".into(),
                "-cpu".into(),
                format!("host{la57}"),
            ]);
        }
        Accel::Whpx =>
        {
            // Windows Hyper-V Platform. WHPX does not expose -cpu host the
            // same way KVM/HVF do; -cpu max,migratable=no is the documented
            // QEMU recipe and exposes the same x86-64-v3 baseline TCG does.
            args.extend([
                "-accel".into(),
                "whpx".into(),
                "-cpu".into(),
                format!("max,migratable=no{la57}"),
            ]);
        }
        Accel::Nvmm =>
        {
            args.extend([
                "-accel".into(),
                "nvmm".into(),
                "-cpu".into(),
                format!("max,migratable=no{la57}"),
            ]);
        }
        Accel::Tcg =>
        {
            // TCG fallback: `-cpu max,migratable=no` advertises every
            // feature QEMU can emulate (including x86-64-v3) so userspace
            // SIMD codegen executes correctly under non-KVM runs (CI,
            // KVM-less containers).
            args.extend([
                "-accel".into(),
                "tcg,thread=multi".into(),
                "-cpu".into(),
                format!("max,migratable=no{la57}"),
            ]);
        }
    }

    args.extend([
        "-drive".into(),
        format!(
            "if=pflash,format=raw,readonly=on,file={}",
            spec.firmware_code_path.display()
        ),
    ]);

    // Non-headless x86-64 uses the q35 default adapter (QEMU std VGA) — the
    // same device riscv64 selects explicitly via `-device VGA`. Headless drops
    // it so no framebuffer is advertised.
    if spec.headless
    {
        args.extend(["-vga".into(), "none".into()]);
    }
    Ok(())
}

fn extend_riscv(args: &mut Vec<String>, spec: &QemuLaunchSpec) -> Result<()>
{
    let vars_path = spec
        .firmware_vars_path
        .context("riscv64 launch requires firmware_vars_path")?;

    args.extend(["-machine".into(), "virt".into()]);
    // Pin the CPU model to a baseline that advertises the RVA23 features the
    // system requires: V (Vector) plus the Zba/Zbb/Zbs bitmanip set for
    // userspace, and the supervisor paging extensions Svpbmt/Svinval/Svnapot
    // that the kernel's boot gate refuses to run without (explicit `=on`
    // pins against QEMU default drift). RVA23 also mandates Zfa, Zfhmin,
    // Zihintntl, Zicond, Zimop, Zcmop, Zcb, Zvfhmin, Zvbb, Zvkt, Zkt — those
    // land as QEMU coverage broadens. Which QEMU versions this string targets,
    // and why the named `-cpu rva23s64` model is not used, are specified in
    // docs/build-system.md § QEMU and Firmware.
    //
    // The trailing satp-mode properties (`RiscvMmu::cpu_satp_props`) pin the
    // paging-mode ceiling the guest advertises via DTB `mmu-type`.
    args.extend([
        "-cpu".into(),
        format!(
            "rv64,v=true,zba=true,zbb=true,zbs=true,svpbmt=on,svinval=on,svnapot=on{}",
            spec.riscv_mmu.cpu_satp_props()
        ),
    ]);
    // Explicit multi-threaded TCG: `-smp 4` without this falls back to the
    // per-arch default, which can be single-threaded round-robin. SMP
    // correctness under real parallel execution needs genuine
    // multi-threaded emulation.
    args.extend(["-accel".into(), "tcg,thread=multi".into()]);
    args.extend([
        "-drive".into(),
        format!(
            "if=pflash,format=raw,readonly=on,file={}",
            spec.firmware_code_path.display()
        ),
        "-drive".into(),
        format!("if=pflash,format=raw,file={}", vars_path.display()),
    ]);

    // QEMU's `edu` device, whose DMA engine svctest's DMA confinement phase
    // drives through the test-only `test-dma` driver: behind the IOMMU when
    // one is attached (`RISCV_IOMMU_DEVICE`, added first), unconfined
    // otherwise. No production driver binds it.
    args.extend(["-device".into(), EDU_DEVICE.into()]);

    if !spec.headless
    {
        // The virt machine has no built-in display. Use QEMU std VGA — the
        // same adapter q35 gives x86-64 by default — so both arches present an
        // identical UEFI GOP (`QemuVideoDxe`, same mode table). Without a
        // graphical display backend QEMU falls back to VNC, so only add the
        // display devices when a backend is available.
        if let Some(backend) = preferred_display_backend(spec.arch.qemu_binary())
        {
            args.extend([
                "-device".into(),
                "VGA".into(),
                "-device".into(),
                "qemu-xhci".into(),
                "-device".into(),
                "usb-kbd".into(),
                "-display".into(),
                backend,
            ]);
        }
    }

    Ok(())
}

/// Resolve and cache riscv64 firmware.
///
/// Returns `(code_path, vars_template_path)`:
/// - `code_path` is the padded readonly pflash, cached under
///   `target/xtask/firmware/riscv/` and regenerated only when the distro
///   source is newer or the cached copy is missing/wrong-sized.
/// - `vars_template_path` is a fresh copy of the NVRAM template, overwritten
///   on every call. `run` uses this path directly as the writable pflash;
///   `run-parallel` copies it to per-slot VARS.fd files so concurrent QEMUs
///   don't race on the same NVRAM image.
///
/// Source discovery is delegated to `firmware::find_riscv_firmware`,
/// which is env-var-first and per-`cfg(target_os)` aware. This function
/// owns only the padding/caching that QEMU's `virt` machine requires
/// (exactly 32 MiB pflash images).
pub fn prepare_riscv_firmware(ctx: &Context) -> Result<(PathBuf, PathBuf)>
{
    let (src_code, src_vars) = firmware::find_riscv_firmware()?;

    let cache_dir = ctx.target_dir.join("xtask").join("firmware").join("riscv");
    std::fs::create_dir_all(&cache_dir)
        .with_context(|| format!("creating firmware cache {}", cache_dir.display()))?;

    let cached_code = cache_dir.join("RISCV_VIRT_CODE.32M.fd");
    let cached_vars = cache_dir.join("RISCV_VIRT_VARS.fd");

    if pflash_cache_stale(&cached_code, &src_code, PFLASH_SIZE)?
    {
        std::fs::copy(&src_code, &cached_code).with_context(|| {
            format!(
                "copying {} to {}",
                src_code.display(),
                cached_code.display()
            )
        })?;
        pad_file_to(&cached_code, PFLASH_SIZE)?;
    }

    std::fs::copy(&src_vars, &cached_vars).with_context(|| {
        format!(
            "copying {} to {}",
            src_vars.display(),
            cached_vars.display()
        )
    })?;
    pad_file_to(&cached_vars, PFLASH_SIZE)?;

    Ok((cached_code, cached_vars))
}

/// Validate that the sysroot is populated for `arch` and the disk image
/// exists.
///
/// Every launcher (`run`, `run-parallel`, and the `test-*` runners) is a
/// pure runner — it refuses to launch QEMU if the sysroot is missing
/// (pointing the caller at `cargo xtask build`) or stamped for the wrong
/// architecture (pointing the caller at `cargo xtask clean`).
pub fn validate_sysroot_for_launch(ctx: &Context, arch: Arch) -> Result<()>
{
    sysroot::check_arch(ctx, arch)?;

    let efi_name = arch.boot_efi_filename();
    let boot_efi = ctx.sysroot_efi_boot().join(efi_name);
    let kernel_bin = ctx.sysroot_efi_seraph().join("kernel");
    // Init (and modules) reach the ESP via the bootstrap bundle composed
    // by `cargo xtask build` (default-init) or `cargo xtask compose-bundle
    // --harness {init,ktest}`. Validate the bundle exists rather than any
    // individual binary.
    let bundle = ctx.sysroot_efi_seraph().join("bootstrap.bundle");
    let disk_img = ctx.disk_image();

    let missing = [
        ("bootloader", boot_efi),
        ("kernel", kernel_bin),
        ("bootstrap.bundle", bundle),
        ("disk image", disk_img),
    ];
    for (label, path) in missing
    {
        if !path.exists()
        {
            bail!(
                "{} not found: {} (run `cargo xtask build` first)",
                label,
                path.display()
            );
        }
    }
    Ok(())
}

/// Returns the preferred graphical display backend for the given QEMU binary,
/// or `None` if no graphical backend is available (e.g. headless server build).
///
/// Tries `gtk` first, then `sdl`. If neither is advertised by `qemu -display help`,
/// returns `None` so callers can skip adding display devices entirely (avoiding the
/// VNC fallback that QEMU starts when a display device exists but no backend is set).
fn preferred_display_backend(qemu_binary: &str) -> Option<String>
{
    let output = Command::new(qemu_binary)
        .args(["-display", "help"])
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .output()
        .ok()?;

    let text = String::from_utf8_lossy(&output.stdout).into_owned()
        + &String::from_utf8_lossy(&output.stderr);

    for backend in ["gtk", "sdl"]
    {
        if text.contains(backend)
        {
            return Some(backend.to_string());
        }
    }

    None
}

/// Returns true if `cached` is missing, wrong-sized, or older than `source`.
fn pflash_cache_stale(cached: &Path, source: &Path, target_size: u64) -> Result<bool>
{
    let Ok(cached_md) = std::fs::metadata(cached)
    else
    {
        return Ok(true);
    };
    if cached_md.len() != target_size
    {
        return Ok(true);
    }
    let source_md =
        std::fs::metadata(source).with_context(|| format!("stat {}", source.display()))?;
    match (source_md.modified(), cached_md.modified())
    {
        (Ok(s), Ok(c)) => Ok(s > c),
        _ => Ok(true),
    }
}

/// Extend a file with zero bytes until it reaches `target_size`.
fn pad_file_to(path: &Path, target_size: u64) -> Result<()>
{
    use std::io::{Seek, SeekFrom, Write};
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .with_context(|| format!("opening {} for padding", path.display()))?;
    let current = file
        .seek(SeekFrom::End(0))
        .with_context(|| format!("seeking {}", path.display()))?;
    if current < target_size
    {
        let padding = vec![
            0u8;
            usize::try_from(target_size - current)
                .context("firmware padding size exceeds usize")?
        ];
        file.write_all(&padding)
            .with_context(|| format!("padding {}", path.display()))?;
    }
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests
{
    use super::*;

    fn riscv_spec(cpus: u32, mem_mib: u32) -> QemuLaunchSpec<'static>
    {
        QemuLaunchSpec {
            arch: Arch::Riscv64,
            disk_path: Path::new("disk.img"),
            disk_block_size: 512,
            second_disk: None,
            firmware_code_path: Path::new("code.fd"),
            firmware_vars_path: Some(Path::new("vars.fd")),
            cpus,
            mem_mib,
            headless: true,
            gdb: GdbMode::Off,
            qmp_socket: None,
            vmgenid_guid: None,
            incoming: None,
            riscv_mmu: RiscvMmu::Sv48,
            x86_paging: X86Paging::Four,
            iommu: Iommu::Attached,
        }
    }

    fn cpu_arg(argv: &[String]) -> &str
    {
        let cpu = argv.iter().position(|a| a == "-cpu").unwrap();
        &argv[cpu + 1]
    }

    #[test]
    fn argv_reflects_riscv_mmu()
    {
        let argv = build_qemu_argv(&riscv_spec(1, 512)).unwrap();
        assert!(cpu_arg(&argv).ends_with(",sv57=off"));

        let mut spec = riscv_spec(1, 512);
        spec.riscv_mmu = RiscvMmu::Sv39;
        let argv = build_qemu_argv(&spec).unwrap();
        assert!(cpu_arg(&argv).ends_with(",sv57=off,sv48=off"));

        spec.riscv_mmu = RiscvMmu::Sv57;
        let argv = build_qemu_argv(&spec).unwrap();
        assert!(cpu_arg(&argv).ends_with(",sv57=on"));
    }

    #[test]
    fn riscv_cpu_advertises_required_paging_extensions()
    {
        // The kernel's boot gate refuses to run without these; losing them
        // from the -cpu string would kill every riscv64 QEMU run at boot.
        let argv = build_qemu_argv(&riscv_spec(1, 512)).unwrap();
        let cpu = cpu_arg(&argv);
        assert!(cpu.contains(",svpbmt=on"));
        assert!(cpu.contains(",svinval=on"));
        assert!(cpu.contains(",svnapot=on"));
    }

    #[test]
    fn argv_reflects_cpus_and_mem()
    {
        let argv = build_qemu_argv(&riscv_spec(4, 512)).unwrap();
        let m = argv.iter().position(|a| a == "-m").unwrap();
        assert_eq!(argv[m + 1], "512M");
        let smp = argv.iter().position(|a| a == "-smp").unwrap();
        assert_eq!(argv[smp + 1], "4");

        let argv = build_qemu_argv(&riscv_spec(512, 2048)).unwrap();
        let m = argv.iter().position(|a| a == "-m").unwrap();
        assert_eq!(argv[m + 1], "2048M");
        let smp = argv.iter().position(|a| a == "-smp").unwrap();
        assert_eq!(argv[smp + 1], "512");
    }

    #[test]
    fn cpus_out_of_range_rejected()
    {
        assert!(build_qemu_argv(&riscv_spec(0, 512)).is_err());
        let past = u32::try_from(boot_protocol::MAX_CPUS + 1).unwrap();
        assert!(build_qemu_argv(&riscv_spec(past, 512)).is_err());
    }

    #[test]
    fn mem_zero_rejected()
    {
        assert!(build_qemu_argv(&riscv_spec(4, 0)).is_err());
    }

    #[test]
    fn x86_vmgenid_and_incoming_reach_argv()
    {
        let spec = QemuLaunchSpec {
            arch: Arch::X86_64,
            disk_path: Path::new("disk.img"),
            disk_block_size: 512,
            second_disk: None,
            firmware_code_path: Path::new("code.fd"),
            firmware_vars_path: None,
            cpus: 4,
            mem_mib: 512,
            headless: true,
            gdb: GdbMode::Off,
            qmp_socket: None,
            vmgenid_guid: Some("auto"),
            incoming: Some("exec:cat state.bin"),
            riscv_mmu: RiscvMmu::Sv48,
            x86_paging: X86Paging::Four,
            iommu: Iommu::Attached,
        };
        let argv = build_qemu_argv(&spec).unwrap();
        assert!(argv.iter().any(|a| a == "vmgenid,guid=auto"));
        let inc = argv.iter().position(|a| a == "-incoming").unwrap();
        assert_eq!(argv[inc + 1], "exec:cat state.bin");
    }

    fn x86_spec(x86_paging: X86Paging) -> QemuLaunchSpec<'static>
    {
        QemuLaunchSpec {
            arch: Arch::X86_64,
            disk_path: Path::new("disk.img"),
            disk_block_size: 512,
            second_disk: None,
            firmware_code_path: Path::new("code.fd"),
            firmware_vars_path: None,
            cpus: 4,
            mem_mib: 512,
            headless: true,
            gdb: GdbMode::Off,
            qmp_socket: None,
            vmgenid_guid: None,
            incoming: None,
            riscv_mmu: RiscvMmu::Sv48,
            x86_paging,
            iommu: Iommu::Attached,
        }
    }

    #[test]
    fn x86_cpu_pins_la57_to_the_requested_depth_on_every_accelerator()
    {
        // A missing pin would let TCG's `-cpu max` (or an LA57 host under
        // KVM) boot 5-level when the run asks for 4, and the reverse.
        for accel in [Accel::Kvm, Accel::Hvf, Accel::Whpx, Accel::Nvmm, Accel::Tcg]
        {
            for (paging, prop) in [
                (X86Paging::Four, ",la57=off"),
                (X86Paging::Five, ",la57=on"),
            ]
            {
                let mut argv = Vec::new();
                extend_x86(&mut argv, &x86_spec(paging), accel, true).unwrap();
                assert!(cpu_arg(&argv).ends_with(prop), "{accel:?} {paging:?}");
            }
        }
    }

    #[test]
    fn five_level_is_refused_on_a_native_accelerator_without_host_la57()
    {
        let err = check_x86_paging(X86Paging::Five, Accel::Kvm, false).unwrap_err();
        assert!(err.to_string().contains("SERAPH_ACCEL=tcg"));
        assert!(check_x86_paging(X86Paging::Five, Accel::Kvm, true).is_ok());
        assert!(check_x86_paging(X86Paging::Five, Accel::Tcg, false).is_ok());
        assert!(check_x86_paging(X86Paging::Four, Accel::Kvm, false).is_ok());
    }

    /// The `virtio-blk-pci` device argument backed by `drive`.
    fn blk_device_arg<'a>(argv: &'a [String], drive: &str) -> Option<&'a str>
    {
        argv.iter()
            .find(|a| a.starts_with(&format!("virtio-blk-pci,drive={drive},")))
            .map(String::as_str)
    }

    #[test]
    fn disk_device_presents_the_image_block_size()
    {
        // A device at 512 under a 4Kn image would put the GPT header at the
        // wrong LBA, and the firmware would find no ESP.
        let mut spec = riscv_spec(1, 512);
        spec.disk_block_size = 4096;
        let argv = build_qemu_argv(&spec).unwrap();
        let dev = blk_device_arg(&argv, "hd0").unwrap();
        assert!(dev.contains(",logical_block_size=4096,"), "{dev}");
        assert!(dev.ends_with(",physical_block_size=4096"), "{dev}");
        assert!(blk_device_arg(&argv, "hd1").is_none());
    }

    #[test]
    fn second_disk_adds_its_own_drive_and_device()
    {
        let mut spec = riscv_spec(1, 512);
        spec.second_disk = Some(SecondDisk {
            path: Path::new("disk-data.img"),
            block_size: 8192,
            shared_line: false,
        });
        let argv = build_qemu_argv(&spec).unwrap();
        assert!(
            argv.iter()
                .any(|a| a == "if=none,id=hd1,format=raw,file=disk-data.img")
        );
        let dev = blk_device_arg(&argv, "hd1").unwrap();
        assert!(dev.contains(",logical_block_size=8192,"), "{dev}");
        assert!(blk_device_arg(&argv, "hd0").unwrap().contains("=512,"));
    }

    /// The PCI slot an `addr=` property in `device` pins.
    fn slot_of(device: &str) -> u8
    {
        let addr = device.split(",addr=").nth(1).unwrap();
        u8::from_str_radix(addr.trim_start_matches("0x"), 16).unwrap()
    }

    /// The two disks' slots of a two-disk launch, the second placed on the
    /// shared line or not.
    fn disk_slots(shared_line: bool) -> (u8, u8)
    {
        let mut spec = riscv_spec(1, 512);
        spec.second_disk = Some(SecondDisk {
            path: Path::new("disk-data.img"),
            block_size: 512,
            shared_line,
        });
        let argv = build_qemu_argv(&spec).unwrap();
        (
            slot_of(blk_device_arg(&argv, "hd0").unwrap()),
            slot_of(blk_device_arg(&argv, "hd1").unwrap()),
        )
    }

    /// OVMF's x86_64 line, from {10, 10, 11, 11} at (slot + 1) % 4.
    fn ovmf_line(slot: u8) -> u8
    {
        [10, 10, 11, 11][usize::from((slot + 1) % 4)]
    }

    /// riscv64 `virt`: INTA of a slot reaches PLIC source 32 + slot % 4.
    fn plic_source(slot: u8) -> u8
    {
        32 + slot % 4
    }

    #[test]
    fn two_disks_land_on_distinct_intx_lines_on_both_machines()
    {
        let (first, second) = disk_slots(false);
        assert_ne!(ovmf_line(first), ovmf_line(second));
        assert_ne!(plic_source(first), plic_source(second));
        // q35 routes every slot past 24 to one line.
        assert!(first <= 24 && second <= 24);
    }

    #[test]
    fn shared_line_disks_land_on_one_intx_line_on_both_machines()
    {
        let (first, second) = disk_slots(true);
        assert_ne!(first, second);
        assert_eq!(ovmf_line(first), ovmf_line(second));
        assert_eq!(plic_source(first), plic_source(second));
        // Below q35's every-slot-one-line range, so the share is the
        // swizzle's, not q35's fallback.
        assert!(first <= 24 && second <= 24);
    }

    #[test]
    fn a_single_disk_takes_the_next_free_slot()
    {
        let argv = build_qemu_argv(&riscv_spec(1, 512)).unwrap();
        assert!(!blk_device_arg(&argv, "hd0").unwrap().contains(",addr="));
    }

    #[test]
    fn block_size_qemu_cannot_present_is_refused()
    {
        for size in [0, 256, 1000]
        {
            let mut spec = riscv_spec(1, 512);
            spec.disk_block_size = size;
            assert!(build_qemu_argv(&spec).is_err(), "disk {size}");

            let mut spec = riscv_spec(1, 512);
            spec.second_disk = Some(SecondDisk {
                path: Path::new("second.img"),
                block_size: size,
                shared_line: false,
            });
            assert!(build_qemu_argv(&spec).is_err(), "second disk {size}");
        }
    }

    #[test]
    fn the_iommu_and_every_virtio_device_behind_it_follow_the_spec()
    {
        let virtio = |argv: &[String]| -> Vec<String> {
            argv.iter()
                .filter(|a| a.starts_with("virtio-"))
                .cloned()
                .collect()
        };
        for (mut spec, iommu_device) in [
            (riscv_spec(4, 512), RISCV_IOMMU_DEVICE),
            (x86_spec(X86Paging::Four), "intel-iommu,intremap=off"),
        ]
        {
            spec.second_disk = Some(SecondDisk {
                path: Path::new("second.img"),
                block_size: 512,
                shared_line: false,
            });
            let argv = build_qemu_argv(&spec).unwrap();
            assert!(argv.iter().any(|a| a == iommu_device));
            // The RISC-V IOMMU precedes every other device, so no
            // auto-placed one takes its slot.
            let first_device = argv.iter().position(|a| a == "-device").unwrap();
            assert_eq!(
                argv[first_device + 1] == RISCV_IOMMU_DEVICE,
                iommu_device == RISCV_IOMMU_DEVICE
            );
            // The DMA test device sits on both machines, with or without
            // the IOMMU.
            assert!(argv.iter().any(|a| a == EDU_DEVICE));
            // Both disks and the keyboard; the firmware-only RNG stays out.
            let devices = virtio(&argv);
            assert_eq!(devices.len(), 4);
            let behind = devices.iter().filter(|d| d.contains(",iommu_platform=on"));
            assert_eq!(behind.count(), 3);
            assert!(devices.iter().any(|d| d == "virtio-rng-pci"));

            spec.iommu = Iommu::Absent;
            let argv = build_qemu_argv(&spec).unwrap();
            assert!(!argv.iter().any(|a| a.contains("iommu")));
            assert!(argv.iter().any(|a| a == EDU_DEVICE));
            assert_eq!(virtio(&argv).len(), 4);
        }
    }

    #[test]
    fn riscv_ignores_vmgenid()
    {
        // The riscv64 virt machine has no VMGENID ACPI support in QEMU; a
        // vmgenid device in its argv would fail to realize at launch.
        let mut spec = riscv_spec(1, 512);
        spec.vmgenid_guid = Some("auto");
        let argv = build_qemu_argv(&spec).unwrap();
        assert!(!argv.iter().any(|a| a.starts_with("vmgenid")));
    }
}
