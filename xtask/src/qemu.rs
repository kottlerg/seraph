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

use crate::error::{Context as _, Result, bail};

use crate::accel::{self, Accel};
use crate::arch::Arch;
use crate::context::Context;
use crate::firmware;
use crate::sysroot;

/// QEMU virt machine requires pflash images to be exactly 32 MiB.
const PFLASH_SIZE: u64 = 32 * 1024 * 1024;

/// GDB stub exposure for a QEMU launch.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum GdbMode<'a>
{
    /// No gdbstub.
    Off,
    /// Expose the gdbstub (`-s`, `tcp::1234`) without pausing the guest, so a
    /// host debugger can attach after a hang is observed.
    Listen,
    /// Expose the gdbstub and freeze at the first instruction (`-s -S`).
    Freeze,
    /// Expose the gdbstub on a unix socket at this path, without pausing the
    /// guest (`-gdb unix:<path>,server=on,wait=off`): a host harness drives
    /// it, and a per-run path keeps concurrent boots off the shared TCP port.
    Unix(&'a Path),
}

crate::argparse::value_enum! {
    /// Guest RISC-V paging mode ceiling for a QEMU launch.
    ///
    /// Selects which `svNN` satp modes the guest CPU advertises (DTB `mmu-type`
    /// plus the satp write-probe both follow it); the kernel negotiates the
    /// highest advertised mode it supports at boot. QEMU >= 8.0 defaults the
    /// rv64 CPU to sv57, so the sv48 default here pins the guest to the
    /// project's standing Sv48 baseline rather than QEMU's.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum RiscvMmu
    {
        /// Cap the guest at Sv39 (`sv57=off,sv48=off`).
        Sv39,
        /// Cap the guest at Sv48 (`sv57=off`) — the default.
        Sv48,
        /// Enable Sv57 (`sv57=on`, explicit against QEMU default drift).
        Sv57,
    }
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

crate::argparse::value_enum! {
    /// Whether the guest RISC-V CPU implements the `Zkr` entropy source.
    ///
    /// With it, the firmware grants S-mode the `seed` CSR and the kernel's
    /// hardware RNG draws from it; without it, the kernel's probe of the CSR traps
    /// and the source is absent (core/kernel/docs/entropy.md § Sources and
    /// graceful degradation). Explicit both ways, against QEMU default drift.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum RiscvZkr
    {
        /// Implement `Zkr` (`zkr=on`) — the default.
        On,
        /// Leave `Zkr` out (`zkr=off`).
        Off,
    }
}

impl RiscvZkr
{
    /// `-cpu` property suffix that pins the guest's `Zkr`.
    fn cpu_zkr_prop(self) -> &'static str
    {
        match self
        {
            Self::On => ",zkr=on",
            Self::Off => ",zkr=off",
        }
    }
}

crate::argparse::value_enum! {
    /// Guest x86-64 paging depth for a QEMU launch.
    ///
    /// Pins the guest CPU's `la57` property on every accelerator, so the CPUID
    /// LA57 bit the bootloader reads (and with it the depth the kernel recovers
    /// from `CR4.LA57`) is the one the run asks for. The 4-level default keeps a
    /// TCG `-cpu max` guest, which otherwise advertises LA57, on 4-level paging.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum X86Paging
    {
        /// 4-level paging (`la57=off`) — the default.
        #[value(name = "4")]
        Four,
        /// 5-level paging (`la57=on`).
        #[value(name = "5")]
        Five,
    }
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

crate::argparse::value_enum! {
    /// Whether an x86-64 guest CPU offers CET supervisor shadow stacks.
    ///
    /// Pins the guest CPU's `cet-ss` property on every accelerator, so whether
    /// the kernel runs on shadow stacks is the run's choice and never the host's:
    /// `-cpu host` would otherwise pass `CET_SS` through wherever the host's KVM
    /// offers it. A QEMU without the property (the 10.2 of the CI image among
    /// them) cannot offer the feature at all, so the default gets no pin there
    /// and a request for the feature is refused ([`qemu_knows_cet_ss`]). The
    /// default leaves them off; the cet cell boots them on
    /// (`cargo xtask test-cet`, docs/testing.md "Coverage tiers").
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum X86ShadowStack
    {
        /// No `CET_SS` in the guest's CPUID (`cet-ss=off`) — the default.
        Off,
        /// `CET_SS` in the guest's CPUID, or no boot (`cet-ss=on,enforce`):
        /// QEMU refuses to start when the accelerator cannot provide it, which
        /// TCG never can, rather than booting without it.
        On,
    }
}

impl X86ShadowStack
{
    /// `-cpu` property suffix that pins the guest's `CET_SS` bit, given
    /// whether the QEMU launched knows the `cet-ss` property
    /// ([`X86Host::qemu_has_cet_ss`]): none for `Off` on a QEMU that does
    /// not, which cannot offer the feature.
    ///
    /// # Errors
    /// `On` on a QEMU without the property, which would refuse the launch.
    fn cpu_cet_ss_prop(self, host: X86Host) -> Result<&'static str>
    {
        match (self, host.qemu_has_cet_ss)
        {
            (Self::Off, true) => Ok(",cet-ss=off"),
            (Self::Off, false) => Ok(""),
            (Self::On, true) => Ok(",cet-ss=on,enforce"),
            (Self::On, false) => bail!(
                "--x86-shadow-stack on needs a QEMU whose x86-64 CPU has the cet-ss property, \
                 which {} does not list in `-cpu help`",
                Arch::X86_64.qemu_binary()
            ),
        }
    }
}

/// Whether the `x86_64` QEMU knows the `cet-ss` CPU property, read once per
/// process from `-cpu help`. A QEMU that cannot be run reads as not knowing
/// it; its launch then fails on its own.
fn qemu_knows_cet_ss() -> bool
{
    static KNOWS: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *KNOWS.get_or_init(|| {
        Command::new(Arch::X86_64.qemu_binary())
            .args(["-cpu", "help"])
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .is_ok_and(|out| lists_cpu_flag(&String::from_utf8_lossy(&out.stdout), "cet-ss"))
    })
}

/// Whether `flag` is among the CPUID flags of a QEMU's `-cpu help` output,
/// which lists them after its `Recognized CPUID flags:` heading.
fn lists_cpu_flag(help: &str, flag: &str) -> bool
{
    help.split_once("Recognized CPUID flags:")
        .is_some_and(|(_, flags)| flags.split_whitespace().any(|f| f == flag))
}

/// The host facts an `x86_64` launch's CPU model depends on.
#[derive(Clone, Copy, Debug)]
struct X86Host
{
    /// Whether the host CPU reports LA57 ([`host_cpu_has_la57`]).
    cpu_has_la57: bool,
    /// Whether the QEMU launched knows the `cet-ss` CPU property
    /// ([`qemu_knows_cet_ss`]).
    qemu_has_cet_ss: bool,
}

impl X86Host
{
    /// The facts of this host and its `x86_64` QEMU.
    fn probe() -> Self
    {
        Self {
            cpu_has_la57: host_cpu_has_la57(),
            qemu_has_cet_ss: qemu_knows_cet_ss(),
        }
    }
}

/// The DMA test device a test launch attaches (`--test-devices`): QEMU's
/// `edu` (PCI `1234:11e8`), its DMA mask widened from the default 28 bits to
/// 32, so its DMA engine reaches the interrupt addresses svctest's
/// forged-message phase writes (the riscv64 IMSIC files at `0x2800_0000`,
/// the `x86_64` interrupt range at `0xFEE0_0000`); a narrower mask truncates
/// them.
const EDU_DEVICE: &str = "edu,dma_mask=0xffffffff";

/// The DMA mask of [`EDU_DEVICE`], which a hot-added `edu` is given too
/// (`test-hotplug`).
pub const EDU_DMA_MASK: u64 = 0xFFFF_FFFF;

/// The QEMU `pci-testdev` functions (PCI `1b36:0005`) a test launch attaches
/// (`--test-devices`) for the test-only `test-fault` fixture, which takes its
/// role from the function's BAR 2 (`ipc::test_fault_labels`): two with no
/// BAR 2, which the fixture serves, one whose BAR 2 is `HANG_BAR_BYTES`
/// (`membar=4K`), on which it never reports ready, and one whose BAR 2 is
/// `ORPHAN_BAR_BYTES` (`membar=8K`), on which it refuses its bootstrap.
/// Pinned past the disks' slots ([`FIRST_DISK_SLOT`]), below 25, where q35
/// routes every slot to one line, and clear of q35's slot 0x1f; the fixture
/// takes no interrupt, so the lines they share are unused.
const TEST_FAULT_DEVICES: [&str; 4] = [
    "pci-testdev,addr=0x15",
    "pci-testdev,addr=0x16",
    "pci-testdev,addr=0x17,membar=4K",
    "pci-testdev,addr=0x18,membar=8K",
];

/// The arguments that attach the test devices of a test launch:
/// [`EDU_DEVICE`] and [`TEST_FAULT_DEVICES`]. No production driver binds
/// any of them.
fn test_device_args() -> Vec<String>
{
    core::iter::once(EDU_DEVICE)
        .chain(TEST_FAULT_DEVICES)
        .flat_map(|d| ["-device".to_string(), d.to_string()])
        .collect()
}

/// The id of the first PCI Express root port a hotplug launch attaches
/// ([`QemuLaunchSpec::hotplug_port`]), which `device_add` names as the bus of
/// the device it hot-adds, and the bus of a [`PortDisk`].
pub const HOTPLUG_PORT_ID: &str = "hotplug-port";

/// The first PCI Express root port a hotplug launch attaches, empty at boot
/// unless a [`PortDisk`] sits behind it: its own chassis and slot number,
/// pinned at slot `0x1c`, clear of every device a launch places.
const HOTPLUG_PORT_DEVICE: &str = "pcie-root-port,id=hotplug-port,chassis=1,slot=1,addr=0x1c";

/// The id of the second PCI Express root port a hotplug launch attaches,
/// which `device_add` names as the bus of the disk it hot-adds
/// (`test-hotplug`).
pub const HOTPLUG_DISK_PORT_ID: &str = "hotplug-disk-port";

/// The second PCI Express root port a hotplug launch attaches, empty at
/// boot, for a hot-added disk: its own chassis and slot number, pinned at
/// slot `0x1d`, beside [`HOTPLUG_PORT_DEVICE`].
const HOTPLUG_DISK_PORT_DEVICE: &str =
    "pcie-root-port,id=hotplug-disk-port,chassis=2,slot=2,addr=0x1d";

/// The q35 property that turns QEMU's ACPI PCI hotplug off, so the
/// firmware's `_OSC` grants the operating system native hotplug control.
const X86_NATIVE_HOTPLUG_GLOBAL: &str = "ICH9-LPC.acpi-pci-hotplug-with-bridge-support=off";

/// The interface of the TPM a launch attaches ([`build_qemu_argv_with_tpm`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TpmInterface
{
    /// The FIFO interface: QEMU's `tpm-tis` device, ACPI `TPM2` start
    /// method 6.
    Fifo,
    /// The CRB interface: QEMU's `tpm-crb` device, start method 7.
    Crb,
}

impl TpmInterface
{
    /// QEMU's device of this interface.
    pub const fn device(self) -> &'static str
    {
        match self
        {
            Self::Fifo => "tpm-tis",
            Self::Crb => "tpm-crb",
        }
    }
}

/// A TPM 2.0 a launch attaches ([`build_qemu_argv_with_tpm`]): QEMU's device of
/// `interface`, its backend the `swtpm` emulator whose control socket is
/// `socket` (`-tpmdev emulator`). QEMU places the device in the PC Client
/// TPM range at `0xFED4_0000` and publishes the ACPI `TPM2` table and the
/// `MSFT0101` device for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tpm<'a>
{
    pub interface: TpmInterface,
    pub socket: &'a Path,
}

/// The arguments that attach `tpm`: the character device on the emulator's
/// socket, the TPM backend over it, and the device.
fn tpm_args(tpm: Tpm<'_>) -> Vec<String>
{
    vec![
        "-chardev".into(),
        format!("socket,id=chrtpm,path={}", tpm.socket.display()),
        "-tpmdev".into(),
        "emulator,id=tpm0,chardev=chrtpm".into(),
        "-device".into(),
        format!("{},tpmdev=tpm0", tpm.interface.device()),
    ]
}

/// Who controls the hotplug of the root ports a launch attaches
/// ([`QemuLaunchSpec::hotplug_port`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HotplugControl
{
    /// The machine's default. On q35 QEMU's ACPI PCI hotplug drives the
    /// port, and `_OSC` withholds native control; riscv64 `virt` offers no
    /// ACPI hotplug, and its platform description table grants native
    /// control.
    Firmware,
    /// Native control: on q35 QEMU's ACPI PCI hotplug is turned off
    /// ([`X86_NATIVE_HOTPLUG_GLOBAL`]), so `_OSC` grants it; on riscv64 as
    /// [`HotplugControl::Firmware`].
    Native,
}

/// The hotplug root ports a launch attaches
/// ([`QemuLaunchSpec::hotplug_port`]): who controls their hotplug, and the
/// disk placed behind the first, if any.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HotplugPort<'a>
{
    pub control: HotplugControl,
    pub disk: Option<PortDisk<'a>>,
}

impl HotplugPort<'_>
{
    /// Empty ports under `control`, with no disk.
    #[must_use]
    pub const fn empty(control: HotplugControl) -> Self
    {
        Self {
            control,
            disk: None,
        }
    }
}

/// A disk a hotplug launch places behind its first root port
/// ([`HotplugPort`], [`HOTPLUG_PORT_ID`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortDisk<'a>
{
    /// The image at this path as the block node [`PORT_DISK_NODE`], its
    /// `virtio-blk-pci` device, id [`PORT_DISK_ID`], behind the port from
    /// boot. QEMU keeps a node made by `-blockdev` across the removal of its
    /// device, so the host can remove the device and add it again
    /// ([`port_disk_properties`]). Its device presents `block_size`-byte
    /// blocks.
    Data
    {
        path: &'a Path, block_size: u32
    },
    /// The boot disk itself: its `virtio-blk-pci` device, id
    /// [`PORT_DISK_ID`], sits behind the port from boot, so the host can
    /// remove it.
    Boot,
}

/// The id of the `virtio-blk-pci` device behind the first hotplug port, of the
/// boot disk ([`PortDisk::Boot`]) or the data disk ([`PortDisk::Data`]).
pub const PORT_DISK_ID: &str = "hotplug-disk";

/// The block node of a [`PortDisk::Data`] image, which its device names as
/// its drive.
pub const PORT_DISK_NODE: &str = "hotplug-disk-node";

/// The `device_add` properties of the `virtio-blk-pci` device a host adds
/// again on a [`PortDisk::Data`] node: those [`blk_device`] gives every
/// disk, `block_size`-byte blocks and behind the IOMMU when `iommu`
/// attaches one.
#[must_use]
pub fn port_disk_properties(
    block_size: u32,
    iommu: Iommu,
) -> Vec<(&'static str, crate::qmp::Property<'static>)>
{
    use crate::qmp::Property;
    let mut properties = vec![
        ("drive", Property::Text(PORT_DISK_NODE)),
        ("disable-legacy", Property::Text("on")),
        (
            "logical_block_size",
            Property::Number(u64::from(block_size)),
        ),
        (
            "physical_block_size",
            Property::Number(u64::from(block_size)),
        ),
    ];
    if iommu == Iommu::Attached
    {
        properties.push(("iommu_platform", Property::Flag(true)));
    }
    properties
}

/// The arguments that attach the hotplug root ports of `spec`, none when it
/// asks for none: the two ports, on q35 under native control the property
/// that turns ACPI PCI hotplug off, and the disk behind the first port: the
/// boot disk's device, or the data image's node and device, each after the
/// port it sits on.
fn hotplug_port_args(spec: &QemuLaunchSpec) -> Vec<String>
{
    let Some(port) = spec.hotplug_port
    else
    {
        return Vec::new();
    };
    let mut args = vec![
        "-device".to_string(),
        HOTPLUG_PORT_DEVICE.to_string(),
        "-device".to_string(),
        HOTPLUG_DISK_PORT_DEVICE.to_string(),
    ];
    if spec.arch == Arch::X86_64 && port.control == HotplugControl::Native
    {
        args.extend(["-global".to_string(), X86_NATIVE_HOTPLUG_GLOBAL.to_string()]);
    }
    match port.disk
    {
        None =>
        {}
        Some(PortDisk::Boot) => args.extend([
            "-device".to_string(),
            format!(
                "{},bus={HOTPLUG_PORT_ID},id={PORT_DISK_ID}",
                blk_device("hd0", spec.disk_block_size, None, spec.iommu, DiskLine::Own)
            ),
        ]),
        Some(PortDisk::Data { path, block_size }) =>
        {
            args.extend([
                "-blockdev".to_string(),
                format!(
                    "driver=raw,node-name={PORT_DISK_NODE},file.driver=file,file.filename={}",
                    path.display()
                ),
                "-device".to_string(),
                format!(
                    "{},bus={HOTPLUG_PORT_ID},id={PORT_DISK_ID}",
                    blk_device(PORT_DISK_NODE, block_size, None, spec.iommu, DiskLine::Own)
                ),
            ]);
        }
    }
    args
}

/// The block size of the data disk behind the first hotplug port of `spec`
/// ([`PortDisk::Data`]), if it has one.
fn port_disk_block_size(spec: &QemuLaunchSpec) -> Option<u32>
{
    match spec.hotplug_port?.disk?
    {
        PortDisk::Data { block_size, .. } => Some(block_size),
        PortDisk::Boot => None,
    }
}

/// Whether the boot disk's device sits behind the first hotplug port of `spec`
/// ([`PortDisk::Boot`]), which [`hotplug_port_args`] then places.
fn boot_disk_behind_port(spec: &QemuLaunchSpec) -> bool
{
    spec.hotplug_port
        .is_some_and(|port| port.disk == Some(PortDisk::Boot))
}

/// The RISC-V IOMMU as a PCI function, pinned at 00:01.0, the lowest slot
/// past the host bridge. `off=off` leaves it in Bare mode out of reset,
/// passing DMA through untranslated until it is programmed; its default, Off
/// mode, blocks all DMA, so the firmware could not read the boot disk. QEMU's
/// ACPI RIMT describes the IOMMU as translating only the requester IDs above
/// its own, while QEMU translates every function of the bus, so a device on
/// a lower slot would be translated with no firmware description devmgr
/// could confine it by; at 00:01.0 every other function lies above it.
const RISCV_IOMMU_DEVICE: &str = "riscv-iommu-pci,off=off,addr=0x01";

/// The VT-d IOMMU of an x86-64 launch that attaches one: DMA remapping, and
/// interrupt remapping (`intremap=on`) with 32-bit destinations offered
/// (`eim=on`), so devmgr turns interrupt remapping on and every message and
/// wired line reaches a CPU through a remapping entry.
const X86_IOMMU_DEVICE: &str = "intel-iommu,intremap=on,eim=on";

/// The q35 machine of a KVM launch with the IOMMU attached: interrupt
/// remapping needs the I/O APIC emulated by QEMU (`kernel-irqchip=split`),
/// which QEMU refuses `intremap=on` without. Under TCG and the other
/// accelerators QEMU emulates it in any case.
const X86_MACHINE_SPLIT_IRQCHIP: &str = "q35,kernel-irqchip=split";

crate::argparse::value_enum! {
    /// Whether a QEMU launch attaches the machine's IOMMU (`--iommu`).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
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

/// What a QEMU launch presents for display: QEMU std VGA (the adapter whose
/// UEFI GOP the bootloader hands the kernel as its framebuffer) with or
/// without a window, or no adapter at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QemuDisplay
{
    /// The adapter and a display window: on `x86_64` q35's default adapter
    /// with QEMU's default display; on riscv64 `-device VGA` with a
    /// `qemu-xhci`/`usb-kbd` pair and the `gtk` or `sdl` backend, added only
    /// when one is available (with no graphical backend QEMU would fall back
    /// to VNC).
    Window,
    /// The adapter with no window (`-display none`), so a headless host still
    /// boots with a GOP framebuffer and devmgr spawns the framebuffer driver:
    /// the framebuffer device cell (docs/testing.md "Coverage tiers").
    Framebuffer,
    /// No adapter and no window: no GOP, so no framebuffer driver runs.
    Headless,
}

crate::argparse::value_enum! {
    /// The display of a `run-parallel` launch (`--display`): never a window, since
    /// its guests run unattended and in parallel.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum BatchDisplay
    {
        /// No display adapter, the default ([`QemuDisplay::Headless`]).
        Headless,
        /// The adapter with no window ([`QemuDisplay::Framebuffer`]).
        Framebuffer,
    }
}

impl From<BatchDisplay> for QemuDisplay
{
    fn from(display: BatchDisplay) -> Self
    {
        match display
        {
            BatchDisplay::Headless => Self::Headless,
            BatchDisplay::Framebuffer => Self::Framebuffer,
        }
    }
}

/// The second disk's `INTx` line: its own slot's line, or the first disk's
/// line (the `--second-disk-shared-line` launch).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiskLine
{
    /// The line of the second disk's own slot.
    Own,
    /// The first disk's line.
    Shared,
}

/// A second disk for a QEMU launch: its image, the logical block size its
/// device presents, and whether it shares the first disk's `INTx` line.
pub struct SecondDisk<'a>
{
    pub path: &'a Path,
    /// Logical and physical block size of the `virtio-blk-pci` device, in
    /// bytes.
    pub block_size: u32,
    /// With [`DiskLine::Shared`], place the device at
    /// `SHARED_LINE_SECOND_DISK_SLOT`, on the first disk's `INTx` line on
    /// both machines, rather than at `SECOND_DISK_SLOT`, on a line of its
    /// own, and launch both disks with no MSI-X capability, so their driver
    /// is given the shared wired line.
    pub line: DiskLine,
}

impl<'a> SecondDisk<'a>
{
    /// The image at `path` on a line of its own, its device at the block
    /// size the image's GPT is laid out in.
    ///
    /// # Errors
    /// Fails as [`crate::disk::logical_block_size`] does.
    pub fn of_image(path: &'a Path) -> Result<Self>
    {
        Ok(Self {
            path,
            block_size: crate::disk::logical_block_size(path)?,
            line: DiskLine::Own,
        })
    }
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
    /// Logical CPUs per core the guest's topology reports (QEMU
    /// `-smp <cpus>,threads=<n>`): 1 makes each vCPU a core of its own, 2 pairs
    /// them as SMT siblings, which the kernel's core spread reads
    /// (core/kernel/docs/scheduler.md § SMT Awareness). Divides `cpus`.
    pub threads_per_core: u32,
    /// Guest memory size in MiB.
    pub mem_mib: u32,
    pub display: QemuDisplay,
    pub gdb: GdbMode<'a>,
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
    /// Whether the guest CPU implements `Zkr`; riscv64 only, ignored on
    /// `x86_64`.
    pub riscv_zkr: RiscvZkr,
    /// Guest paging depth; `x86_64` only, ignored on riscv64.
    pub x86_paging: X86Paging,
    /// Whether the guest CPU offers CET shadow stacks; `x86_64` only, ignored
    /// on riscv64.
    pub x86_shadow_stack: X86ShadowStack,
    /// Whether the machine's IOMMU is attached; every launch site attaches it
    /// unless the run asks for the no-IOMMU variant (`--iommu absent`).
    pub iommu: Iommu,
    /// When set, attach the debug port (`--debug-port`): a `virtio-console`
    /// device whose port QEMU exposes as a TCP server on `127.0.0.1` at this
    /// port ([`debug_port_args`]).
    pub debug_port: Option<u16>,
    /// Whether the test devices are attached (`--test-devices`): `edu` and
    /// the `pci-testdev` functions svctest's devmgr phases drive through the
    /// test-only drivers ([`test_device_args`]).
    pub test_devices: bool,
    /// When set, attach the two PCI Express root ports devices can be
    /// hot-added behind or removed from (`test-hotplug`:
    /// `HOTPLUG_PORT_DEVICE` and `HOTPLUG_DISK_PORT_DEVICE`), their hotplug
    /// under the port's control, with the disk it places behind the first
    /// ([`hotplug_port_args`]).
    pub hotplug_port: Option<HotplugPort<'a>>,
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

/// The `-smp` value for `cpus` vCPUs of `threads_per_core` threads each:
/// the bare count for one thread per core, else `<cpus>,threads=<n>`, from
/// which QEMU derives the cores.
///
/// # Errors
/// Fails when `cpus` is 0 or past the boot protocol's `MAX_CPUS`, or when
/// `threads_per_core` does not divide it into whole cores.
fn smp_arg(cpus: u32, threads_per_core: u32) -> Result<String>
{
    // The boot protocol caps a BootInfo's CPU count at MAX_CPUS; a guest with
    // more vCPUs than that would boot with the surplus dropped.
    let max_cpus = boot_protocol::MAX_CPUS;
    if cpus == 0 || usize::try_from(cpus).map_or(true, |c| c > max_cpus)
    {
        bail!("--cpus {cpus} out of range: must be 1..={max_cpus} (boot-protocol MAX_CPUS)");
    }
    if threads_per_core == 0 || !cpus.is_multiple_of(threads_per_core)
    {
        bail!(
            "--threads-per-core {threads_per_core} does not divide --cpus {cpus} into whole cores"
        );
    }
    if threads_per_core == 1
    {
        Ok(cpus.to_string())
    }
    else
    {
        Ok(format!("{cpus},threads={threads_per_core}"))
    }
}

/// Construct the full QEMU argv for a launch spec.
///
/// Pairs with `Arch::qemu_binary()` for the binary name. The returned vector
/// is suitable for `Command::new(binary).args(&argv)`.
pub fn build_qemu_argv(spec: &QemuLaunchSpec) -> Result<Vec<String>>
{
    build_qemu_argv_with_tpm(spec, None)
}

/// [`build_qemu_argv`], with `tpm` attached when it is set (`test-tpm`
/// alone), in place of the `virtio-rng-pci` device, so the TPM driver is the
/// `hwrng` class's only member. `x86_64` only: QEMU's TPM devices sit in the
/// PC Client TPM range, which the riscv64 `virt` machine does not decode.
pub fn build_qemu_argv_with_tpm(spec: &QemuLaunchSpec, tpm: Option<Tpm<'_>>)
-> Result<Vec<String>>
{
    if tpm.is_some() && spec.arch != Arch::X86_64
    {
        bail!(
            "a TPM is attached on x86_64 only: QEMU's TPM devices sit in the PC Client TPM range"
        );
    }
    let smp = smp_arg(spec.cpus, spec.threads_per_core)?;
    if spec.mem_mib == 0
    {
        bail!("--mem 0 is not a bootable guest memory size");
    }
    check_block_size(spec.disk_block_size)?;
    port_disk_block_size(spec).map_or(Ok(()), check_block_size)?;

    let mut args: Vec<String> = vec![
        "-m".into(),
        format!("{}M", spec.mem_mib),
        "-smp".into(),
        smp,
    ];
    args.extend(leading_devices(spec));
    args.extend([
        "-drive".into(),
        format!(
            "if=none,id=hd0,format=raw,file={}",
            spec.disk_path.display()
        ),
    ]);
    // A boot disk behind the hotplug port has its device placed after the
    // port (`hotplug_port_args`).
    if !boot_disk_behind_port(spec)
    {
        args.extend([
            "-device".into(),
            blk_device(
                "hd0",
                spec.disk_block_size,
                spec.second_disk.as_ref().map(|_| FIRST_DISK_SLOT),
                spec.iommu,
                spec.second_disk.as_ref().map_or(DiskLine::Own, |s| s.line),
            ),
        ]);
    }

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
                Some(second_disk_slot(second.line)),
                spec.iommu,
                second.line,
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
    ]);
    let rng: [String; 2] = [
        // Entropy source, driven twice. The firmware's RNG driver binds it
        // first and exposes EFI_RNG_PROTOCOL, which the bootloader draws from
        // for the KASLR slide / direct-map base and the pool seed. On riscv64
        // it is the only such source (EDK2 hands the bootloader ACPI, not a
        // DTB, so /chosen/rng-seed never reaches it); on x86-64 OVMF binds it
        // too, but its RDRAND driver answers the bootloader's draw. At run time devmgr binds
        // the virtio-rng driver of the `hwrng` class to it. Modern-only
        // (`disable-legacy=on`), since QEMU's transitional device cannot take
        // `iommu_platform=on`, and behind the IOMMU like every device a
        // driver of the system binds.
        "-device".into(),
        format!(
            "virtio-rng-pci,disable-legacy=on{}",
            spec.iommu.virtio_property()
        ),
    ];
    // A TPM launch leaves the RNG out, so the TPM driver is the `hwrng`
    // class's only member and entropyd's first contribution is the TPM's;
    // such a launch is x86-64's, where OVMF's RDRAND driver answers the
    // bootloader's draw either way.
    args.extend(tpm.map_or_else(|| Vec::from(rng), tpm_args));
    args.extend(["-serial".into(), "stdio".into(), "-no-reboot".into()]);

    if let Some(port) = spec.debug_port
    {
        args.extend(debug_port_args(port, spec.iommu));
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

    args.extend(gdb_args(spec.gdb));

    let accel = accel::detect_for_arch(spec.arch);
    match spec.arch
    {
        Arch::X86_64 => extend_x86(&mut args, spec, accel, X86Host::probe())?,
        Arch::Riscv64 => extend_riscv(&mut args, spec)?,
    }

    Ok(args)
}

/// The arguments that expose QEMU's gdbstub as `gdb` asks.
fn gdb_args(gdb: GdbMode<'_>) -> Vec<String>
{
    match gdb
    {
        GdbMode::Off => Vec::new(),
        GdbMode::Listen => vec!["-s".into()],
        GdbMode::Freeze => vec!["-s".into(), "-S".into()],
        GdbMode::Unix(path) => vec![
            "-gdb".into(),
            format!("unix:{},server=on,wait=off", path.display()),
        ],
    }
}

/// PCI slots of the two disks of a two-disk launch (a single disk takes
/// QEMU's next free slot). On `x86_64` OVMF programs a slot's `INTA` line
/// from `{10, 10, 11, 11}` indexed by `(slot + 1) % 4`, which pairs adjacent
/// slots, and on riscv64 the `virt` host swizzles `INTA` onto APLIC source
/// `32 + slot % 4`. `SECOND_DISK_SLOT`, two slots past the first, avoids
/// the share on both machines, so the ordinary two-disk boots give each disk
/// a line of its own. `SHARED_LINE_SECOND_DISK_SLOT`, four slots past the
/// first, lands on the first disk's line on both machines (the same index
/// into OVMF's table, the same APLIC source), which the shared-line boot
/// stages on purpose. Every slot sits below 25, past which q35 routes every
/// slot to one line, above the slots auto-placed devices take, and clear of
/// q35's built-in slot 0x1f.
const FIRST_DISK_SLOT: u8 = 0x10;
const SECOND_DISK_SLOT: u8 = FIRST_DISK_SLOT + 2;
const SHARED_LINE_SECOND_DISK_SLOT: u8 = FIRST_DISK_SLOT + 4;

/// The second disk's PCI slot: on the first disk's line when `line` is
/// [`DiskLine::Shared`].
const fn second_disk_slot(line: DiskLine) -> u8
{
    match line
    {
        DiskLine::Shared => SHARED_LINE_SECOND_DISK_SLOT,
        DiskLine::Own => SECOND_DISK_SLOT,
    }
}

/// The `virtio-blk-pci` device for `drive`, presenting `block_size`-byte
/// logical and physical blocks (QEMU requires the physical size to be at
/// least the logical), at PCI slot `slot` when one is given, behind the
/// IOMMU when `iommu` attaches one, and with no MSI-X capability
/// (`vectors=0`) when `line` is [`DiskLine::Shared`], so it signals on its
/// `INTx` line alone.
fn blk_device(
    drive: &str,
    block_size: u32,
    slot: Option<u8>,
    iommu: Iommu,
    line: DiskLine,
) -> String
{
    let addr = slot.map_or_else(String::new, |slot| format!(",addr={slot:#04x}"));
    let vectors = match line
    {
        DiskLine::Shared => ",vectors=0",
        DiskLine::Own => "",
    };
    format!(
        "virtio-blk-pci,drive={drive},disable-legacy=on{},logical_block_size={block_size},\
         physical_block_size={block_size}{addr}{vectors}",
        iommu.virtio_property()
    )
}

/// The QEMU character device id of the debug port's host end.
const DEBUG_PORT_CHARDEV: &str = "seraph-debug";

/// The arguments that attach the debug port: a `virtio-serial-pci` device,
/// behind the IOMMU when `iommu` attaches one, carrying one `virtconsole`
/// port (port 0, the only port a driver without `VIRTIO_CONSOLE_F_MULTIPORT`
/// drives), whose host end is a TCP server on `127.0.0.1:<port>` that does
/// not wait for a client (`wait=off`), so the guest boots before the host
/// connects and a debugger connects with `target remote localhost:<port>`.
/// devmgr binds the device as the debug port
/// (services/drivers/virtio/console/README.md).
fn debug_port_args(port: u16, iommu: Iommu) -> [String; 6]
{
    [
        "-chardev".into(),
        format!("socket,id={DEBUG_PORT_CHARDEV},host=127.0.0.1,port={port},server=on,wait=off"),
        "-device".into(),
        format!(
            "virtio-serial-pci,disable-legacy=on,id=debugport{}",
            iommu.virtio_property()
        ),
        "-device".into(),
        format!("virtconsole,chardev={DEBUG_PORT_CHARDEV},bus=debugport.0"),
    ]
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
#[expect(
    clippy::fn_params_excessive_bools,
    reason = "`host_has_la57` is whether the host CPU reports LA57, a host fact the function \
              compares with the request"
)]
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
    host: X86Host,
) -> Result<()>
{
    check_x86_paging(spec.x86_paging, accel, host.cpu_has_la57)?;
    // The `-cpu` properties every accelerator's model takes: the paging
    // depth and the shadow-stack feature, each pinned to the run's request.
    let props = format!(
        "{}{}",
        spec.x86_paging.cpu_la57_prop(),
        spec.x86_shadow_stack.cpu_cet_ss_prop(host)?
    );
    let iommu = spec.iommu == Iommu::Attached;
    // VT-d interrupt remapping needs the I/O APIC emulated outside KVM,
    // which QEMU otherwise refuses.
    let machine = if iommu && accel == Accel::Kvm
    {
        X86_MACHINE_SPLIT_IRQCHIP
    }
    else
    {
        "q35"
    };
    args.extend(["-machine".into(), machine.into()]);

    // VT-d DMA and interrupt remapping, with 32-bit (x2APIC) destinations
    // offered.
    if iommu
    {
        args.extend(["-device".into(), X86_IOMMU_DEVICE.into()]);
    }
    // The test devices: QEMU's `edu` device, whose DMA engine svctest's DMA
    // confinement phase drives through the test-only `test-dma` driver,
    // behind the IOMMU when one is attached and unconfined otherwise, and the
    // `pci-testdev` functions of the `test-fault` fixture.
    if spec.test_devices
    {
        args.extend(test_device_args());
    }
    args.extend(hotplug_port_args(spec));

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
            args.extend(["-enable-kvm".into(), "-cpu".into(), format!("host{props}")]);
        }
        Accel::Hvf =>
        {
            // macOS Hypervisor.framework. Same -cpu host rationale as KVM;
            // HVF passes host features through to the guest natively.
            args.extend([
                "-accel".into(),
                "hvf".into(),
                "-cpu".into(),
                format!("host{props}"),
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
                format!("max,migratable=no{props}"),
            ]);
        }
        Accel::Nvmm =>
        {
            args.extend([
                "-accel".into(),
                "nvmm".into(),
                "-cpu".into(),
                format!("max,migratable=no{props}"),
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
                format!("max,migratable=no{props}"),
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

    args.extend(display_args(spec));
    Ok(())
}

fn extend_riscv(args: &mut Vec<String>, spec: &QemuLaunchSpec) -> Result<()>
{
    let vars_path = spec
        .firmware_vars_path
        .context("riscv64 launch requires firmware_vars_path")?;

    // AIA is the only interrupt controller the kernel drives: `aia=aplic-imsic`
    // gives the machine an APLIC (MSI delivery) and per-hart IMSIC files in
    // place of the PLIC, and the kernel refuses to boot without them.
    args.extend(["-machine".into(), "virt,aia=aplic-imsic".into()]);
    // Pin the CPU model to a baseline that advertises the RVA23 features the
    // system requires: V (Vector) plus the Zba/Zbb/Zbs bitmanip set for
    // userspace, the supervisor paging extensions Svpbmt/Svinval/Svnapot, and
    // the AIA CSRs Ssaia (and Smaia, which the firmware's machine-level IMSIC
    // use needs), and Smstateen, whose S-mode part Ssstateen gives the kernel
    // the `sstateen0` it writes on every hart (the firmware, OpenSBI, grants
    // S-mode the CSR when the hart has Smstateen, which the rv64 model leaves
    // off), that the kernel's boot gate refuses to run without (explicit `=on`
    // pins against QEMU default drift). RVA23 also mandates Zfa, Zfhmin,
    // Zihintntl, Zicond, Zimop, Zcmop, Zcb, Zvfhmin, Zvbb, Zvkt, Zkt — those
    // land as QEMU coverage broadens. Which QEMU versions this string targets,
    // and why the named `-cpu rva23s64` model is not used, are specified in
    // docs/build-system.md § QEMU and Firmware.
    //
    // The `zkr` property (`RiscvZkr::cpu_zkr_prop`, on by default) gives the
    // hart the Zkr entropy source, whose `seed` CSR the firmware (OpenSBI)
    // grants S-mode when the hart has it, so the kernel's hardware RNG draws
    // from it; the source is optional, and `--riscv-zkr off` boots without it.
    //
    // `svadu=off,svade=on` pins the Svade A/D scheme the kernel requires: the
    // rv64 model enables Svadu, under which the hart sets A and D itself and
    // the kernel's software A/D update (`user_fault_is_spurious`) never runs.
    //
    // The trailing satp-mode properties (`RiscvMmu::cpu_satp_props`) pin the
    // paging-mode ceiling the guest advertises via DTB `mmu-type`.
    args.extend([
        "-cpu".into(),
        format!(
            "rv64,v=true,zba=true,zbb=true,zbs=true,svpbmt=on,svinval=on,svnapot=on,\
             ssaia=on,smaia=on,smstateen=on,svadu=off,svade=on{}{}",
            spec.riscv_zkr.cpu_zkr_prop(),
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

    // The test devices: QEMU's `edu` device, whose DMA engine svctest's DMA
    // confinement phase drives through the test-only `test-dma` driver,
    // behind the IOMMU when one is attached (`RISCV_IOMMU_DEVICE`, added
    // first) and unconfined otherwise, and the `pci-testdev` functions of the
    // `test-fault` fixture.
    if spec.test_devices
    {
        args.extend(test_device_args());
    }
    args.extend(hotplug_port_args(spec));

    // After the test devices, so the adapter's auto-placed PCI slot follows
    // the devices above.
    args.extend(display_args(spec));

    Ok(())
}

/// The display adapter and display arguments of a launch, for the
/// framebuffer device cell's surface (docs/testing.md "Coverage tiers").
///
/// Both machines present QEMU std VGA, so both arches show an identical
/// UEFI GOP (`QemuVideoDxe`, same mode table): q35's default adapter on
/// `x86_64`, which a headless launch drops with `-vga none`, and on riscv64,
/// whose `virt` machine has no built-in display, `-device VGA`. Every launch
/// without a window passes `-display none`, which needs no graphical
/// backend. A riscv64 window adds the adapter only with the `gtk` or `sdl`
/// backend, since with neither QEMU falls back to VNC.
fn display_args(spec: &QemuLaunchSpec) -> Vec<String>
{
    let mut args: Vec<String> = Vec::new();
    if spec.display != QemuDisplay::Window
    {
        args.extend(["-display".into(), "none".into()]);
    }
    match (spec.arch, spec.display)
    {
        (Arch::X86_64, QemuDisplay::Headless) => args.extend(["-vga".into(), "none".into()]),
        (Arch::X86_64, QemuDisplay::Window | QemuDisplay::Framebuffer)
        | (Arch::Riscv64, QemuDisplay::Headless) =>
        {}
        (Arch::Riscv64, QemuDisplay::Framebuffer) =>
        {
            args.extend(["-device".into(), "VGA".into()]);
        }
        (Arch::Riscv64, QemuDisplay::Window) =>
        {
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
    }
    args
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
    // The bootloader, the kernel and the bundle (init and its modules) are
    // the ESP copies every pack composes from the installed files
    // (`crate::esp::compose`). Validate the copies exist rather than any
    // installed binary.
    let bundle = crate::bundle::esp_path(ctx);
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

    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));

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
            usize::try_from(target_size.saturating_sub(current))
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
            threads_per_core: 1,
            mem_mib,
            display: QemuDisplay::Headless,
            gdb: GdbMode::Off,
            qmp_socket: None,
            vmgenid_guid: None,
            incoming: None,
            riscv_mmu: RiscvMmu::Sv48,
            riscv_zkr: RiscvZkr::On,
            x86_paging: X86Paging::Four,
            x86_shadow_stack: X86ShadowStack::Off,
            iommu: Iommu::Attached,
            debug_port: None,
            test_devices: false,
            hotplug_port: None,
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
    fn argv_exposes_the_gdbstub_on_a_unix_socket()
    {
        let mut spec = riscv_spec(1, 512);
        spec.gdb = GdbMode::Unix(Path::new("/tmp/wedge.gdb"));
        let argv = build_qemu_argv(&spec).unwrap();
        let gdb = argv.iter().position(|a| a == "-gdb").unwrap();
        assert_eq!(argv[gdb + 1], "unix:/tmp/wedge.gdb,server=on,wait=off");
        assert!(!argv.iter().any(|a| a == "-s" || a == "-S"));
    }

    #[test]
    fn argv_reflects_riscv_zkr()
    {
        let argv = build_qemu_argv(&riscv_spec(1, 512)).unwrap();
        assert!(cpu_arg(&argv).contains(",zkr=on"));

        let mut spec = riscv_spec(1, 512);
        spec.riscv_zkr = RiscvZkr::Off;
        let argv = build_qemu_argv(&spec).unwrap();
        let cpu = cpu_arg(&argv);
        assert!(cpu.contains(",zkr=off"));
        assert!(!cpu.contains(",zkr=on"));
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
    fn riscv_launch_presents_aia()
    {
        // The kernel drives AIA only and refuses to boot without Ssaia, an
        // APLIC and an IMSIC; a launch without them would kill every riscv64
        // QEMU run at boot.
        let argv = build_qemu_argv(&riscv_spec(1, 512)).unwrap();
        let machine = argv.iter().position(|a| a == "-machine").unwrap();
        assert_eq!(argv[machine + 1], "virt,aia=aplic-imsic");
        let cpu = cpu_arg(&argv);
        assert!(cpu.contains(",ssaia=on"));
        assert!(cpu.contains(",smaia=on"));
    }

    #[test]
    fn riscv_cpu_presents_state_enables()
    {
        // The kernel writes sstateen0 on every hart and halts the boot when
        // the hart has no Ssstateen; QEMU's rv64 model leaves Smstateen off.
        let argv = build_qemu_argv(&riscv_spec(1, 512)).unwrap();
        assert!(cpu_arg(&argv).contains(",smstateen=on"));
    }

    #[test]
    fn riscv_cpu_pins_svade()
    {
        // The rv64 model enables Svadu, so without the pin the hart sets A
        // and D itself and the kernel's Svade A/D update is never exercised.
        let argv = build_qemu_argv(&riscv_spec(1, 512)).unwrap();
        assert!(cpu_arg(&argv).contains(",svadu=off,svade=on"));
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
        build_qemu_argv(&riscv_spec(0, 512)).unwrap_err();
        let past = u32::try_from(boot_protocol::MAX_CPUS + 1).unwrap();
        build_qemu_argv(&riscv_spec(past, 512)).unwrap_err();
    }

    // Defect caught: a threads-per-core count that does not reach QEMU's
    // -smp (the guest's CPUID reports no SMT siblings), or one that does not
    // divide the vCPUs passed through to a QEMU that refuses the topology.
    #[test]
    fn threads_per_core_reaches_smp_and_must_divide_cpus()
    {
        let mut spec = riscv_spec(4, 512);
        spec.threads_per_core = 2;
        let argv = build_qemu_argv(&spec).unwrap();
        let smp = argv.iter().position(|a| a == "-smp").unwrap();
        assert_eq!(argv[smp + 1], "4,threads=2");
        spec.threads_per_core = 3;
        build_qemu_argv(&spec).unwrap_err();
        spec.threads_per_core = 0;
        build_qemu_argv(&spec).unwrap_err();
    }

    #[test]
    fn mem_zero_rejected()
    {
        build_qemu_argv(&riscv_spec(4, 0)).unwrap_err();
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
            threads_per_core: 1,
            mem_mib: 512,
            display: QemuDisplay::Headless,
            gdb: GdbMode::Off,
            qmp_socket: None,
            vmgenid_guid: Some("auto"),
            incoming: Some("exec:cat state.bin"),
            riscv_mmu: RiscvMmu::Sv48,
            riscv_zkr: RiscvZkr::On,
            x86_paging: X86Paging::Four,
            x86_shadow_stack: X86ShadowStack::Off,
            iommu: Iommu::Attached,
            debug_port: None,
            test_devices: false,
            hotplug_port: None,
        };
        let argv = build_qemu_argv(&spec).unwrap();
        assert!(argv.iter().any(|a| a == "vmgenid,guid=auto"));
        let inc = argv.iter().position(|a| a == "-incoming").unwrap();
        assert_eq!(argv[inc + 1], "exec:cat state.bin");
    }

    /// A host with every `x86_64` fact a launch can use.
    const HOST: X86Host = X86Host {
        cpu_has_la57: true,
        qemu_has_cet_ss: true,
    };

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
            threads_per_core: 1,
            mem_mib: 512,
            display: QemuDisplay::Headless,
            gdb: GdbMode::Off,
            qmp_socket: None,
            vmgenid_guid: None,
            incoming: None,
            riscv_mmu: RiscvMmu::Sv48,
            riscv_zkr: RiscvZkr::On,
            x86_paging,
            x86_shadow_stack: X86ShadowStack::Off,
            iommu: Iommu::Attached,
            debug_port: None,
            test_devices: false,
            hotplug_port: None,
        }
    }

    #[test]
    fn the_debug_port_attaches_its_device_behind_the_iommu_only_when_asked()
    {
        let argv = build_qemu_argv(&riscv_spec(4, 512)).unwrap();
        assert!(!argv.iter().any(|a| a.starts_with("virtio-serial-pci")));

        let mut spec = riscv_spec(4, 512);
        spec.debug_port = Some(4444);
        let argv = build_qemu_argv(&spec).unwrap();
        assert!(
            argv.iter()
                .any(|a| a.contains("port=4444,server=on,wait=off"))
        );
        let dev = argv
            .iter()
            .find(|a| a.starts_with("virtio-serial-pci"))
            .unwrap();
        assert!(dev.contains(",iommu_platform=on"));

        spec.iommu = Iommu::Absent;
        let argv = build_qemu_argv(&spec).unwrap();
        let dev = argv
            .iter()
            .find(|a| a.starts_with("virtio-serial-pci"))
            .unwrap();
        assert!(!dev.contains("iommu_platform"));
    }

    #[test]
    fn a_kvm_launch_with_the_iommu_splits_the_irqchip_and_no_other_does()
    {
        let machine = |argv: &[String]| -> String {
            let at = argv.iter().position(|a| a == "-machine").unwrap();
            argv[at + 1].clone()
        };
        for accel in [Accel::Kvm, Accel::Hvf, Accel::Whpx, Accel::Nvmm, Accel::Tcg]
        {
            for iommu in [Iommu::Attached, Iommu::Absent]
            {
                let mut spec = x86_spec(X86Paging::Four);
                spec.iommu = iommu;
                let mut argv = Vec::new();
                extend_x86(&mut argv, &spec, accel, HOST).unwrap();
                let split = accel == Accel::Kvm && iommu == Iommu::Attached;
                let expected = if split
                {
                    X86_MACHINE_SPLIT_IRQCHIP
                }
                else
                {
                    "q35"
                };
                assert_eq!(machine(&argv), expected, "{accel:?} {iommu:?}");
                assert_eq!(
                    devices(&argv).contains(&X86_IOMMU_DEVICE),
                    iommu == Iommu::Attached
                );
            }
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
                extend_x86(&mut argv, &x86_spec(paging), accel, HOST).unwrap();
                assert!(cpu_arg(&argv).contains(prop), "{accel:?} {paging:?}");
            }
        }
    }

    // The defect caught: a CPU model that leaves `cet-ss` to the host, so an
    // ordinary boot on a host whose KVM offers `CET_SS` runs on shadow stacks
    // and its outcome depends on the host, or a request for them that boots
    // without them.
    #[test]
    fn x86_cpu_pins_cet_ss_to_the_request_on_every_accelerator()
    {
        for accel in [Accel::Kvm, Accel::Hvf, Accel::Whpx, Accel::Nvmm, Accel::Tcg]
        {
            for (shadow_stack, props) in [
                (X86ShadowStack::Off, ",la57=off,cet-ss=off"),
                (X86ShadowStack::On, ",la57=off,cet-ss=on,enforce"),
            ]
            {
                let mut spec = x86_spec(X86Paging::Four);
                spec.x86_shadow_stack = shadow_stack;
                let mut argv = Vec::new();
                extend_x86(&mut argv, &spec, accel, HOST).unwrap();
                assert!(
                    cpu_arg(&argv).ends_with(props),
                    "{accel:?} {shadow_stack:?}: {}",
                    cpu_arg(&argv)
                );
            }
        }
    }

    // The defect caught: a default launch that names `cet-ss` to a QEMU
    // without the property, which refuses to start (the CI image's 10.2), or
    // a request for shadow stacks passed to such a QEMU instead of refused
    // with the reason.
    #[test]
    fn a_qemu_without_cet_ss_gets_no_pin_and_refuses_a_request()
    {
        let host = X86Host {
            qemu_has_cet_ss: false,
            ..HOST
        };
        for accel in [Accel::Kvm, Accel::Hvf, Accel::Whpx, Accel::Nvmm, Accel::Tcg]
        {
            let mut argv = Vec::new();
            extend_x86(&mut argv, &x86_spec(X86Paging::Four), accel, host).unwrap();
            assert!(
                cpu_arg(&argv).ends_with(",la57=off"),
                "{accel:?}: {}",
                cpu_arg(&argv)
            );
            assert!(!cpu_arg(&argv).contains("cet-ss"), "{accel:?}");

            let mut spec = x86_spec(X86Paging::Four);
            spec.x86_shadow_stack = X86ShadowStack::On;
            let err = extend_x86(&mut Vec::new(), &spec, accel, host).unwrap_err();
            assert!(err.to_string().contains("cet-ss"), "{accel:?}: {err}");
        }
    }

    #[test]
    fn the_cpu_help_flag_list_is_what_names_cet_ss()
    {
        // Abridged from QEMU 11.1's output: a model line names the flag
        // before the list does, so only the list counts.
        let knows = "Available CPUs:\n  SapphireRapids-v5     Intel Xeon Processor \
                     (SapphireRapids) [with cet-ss and cet-ibt]\n\nRecognized CPUID flags:\n  \
                     3dnow abm\n  cet-ss cid cldemote\n";
        assert!(lists_cpu_flag(knows, "cet-ss"));
        // QEMU 10.2's list, which has no CET flag.
        let lacks = "Available CPUs:\n  max\n\nRecognized CPUID flags:\n  3dnow abm\n  \
                     cid cldemote\n";
        assert!(!lists_cpu_flag(lacks, "cet-ss"));
        assert!(!lists_cpu_flag(
            "  SapphireRapids-v5 [with cet-ss]\n",
            "cet-ss"
        ));
        assert!(!lists_cpu_flag(knows, "cet"));
    }

    #[test]
    fn five_level_is_refused_on_a_native_accelerator_without_host_la57()
    {
        let err = check_x86_paging(X86Paging::Five, Accel::Kvm, false).unwrap_err();
        assert!(err.to_string().contains("SERAPH_ACCEL=tcg"));
        check_x86_paging(X86Paging::Five, Accel::Kvm, true).unwrap();
        check_x86_paging(X86Paging::Five, Accel::Tcg, false).unwrap();
        check_x86_paging(X86Paging::Four, Accel::Kvm, false).unwrap();
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
            line: DiskLine::Own,
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
        let addr = addr.split(',').next().unwrap();
        u8::from_str_radix(addr.trim_start_matches("0x"), 16).unwrap()
    }

    /// The two disks' slots of a two-disk launch, the second placed on the
    /// shared line or not.
    fn disk_slots(line: DiskLine) -> (u8, u8)
    {
        let mut spec = riscv_spec(1, 512);
        spec.second_disk = Some(SecondDisk {
            path: Path::new("disk-data.img"),
            block_size: 512,
            line,
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

    /// riscv64 `virt`: INTA of a slot reaches APLIC source 32 + slot % 4.
    fn aplic_source(slot: u8) -> u8
    {
        32 + slot % 4
    }

    #[test]
    fn two_disks_land_on_distinct_intx_lines_on_both_machines()
    {
        let (first, second) = disk_slots(DiskLine::Own);
        assert_ne!(ovmf_line(first), ovmf_line(second));
        assert_ne!(aplic_source(first), aplic_source(second));
        // q35 routes every slot past 24 to one line.
        assert!(first <= 24 && second <= 24);
    }

    #[test]
    fn shared_line_disks_land_on_one_intx_line_on_both_machines()
    {
        let (first, second) = disk_slots(DiskLine::Shared);
        assert_ne!(first, second);
        assert_eq!(ovmf_line(first), ovmf_line(second));
        assert_eq!(aplic_source(first), aplic_source(second));
        // Below q35's every-slot-one-line range, so the share is the
        // swizzle's, not q35's fallback.
        assert!(first <= 24 && second <= 24);
    }

    #[test]
    fn only_shared_line_disks_drop_msix()
    {
        for line in [DiskLine::Own, DiskLine::Shared]
        {
            let mut spec = riscv_spec(1, 512);
            spec.second_disk = Some(SecondDisk {
                path: Path::new("disk-data.img"),
                block_size: 512,
                line,
            });
            let argv = build_qemu_argv(&spec).unwrap();
            for drive in ["hd0", "hd1"]
            {
                let dev = blk_device_arg(&argv, drive).unwrap();
                assert_eq!(
                    dev.ends_with(",vectors=0"),
                    line == DiskLine::Shared,
                    "{dev}"
                );
            }
        }
        let argv = build_qemu_argv(&riscv_spec(1, 512)).unwrap();
        assert!(!blk_device_arg(&argv, "hd0").unwrap().contains("vectors"));
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
                line: DiskLine::Own,
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
            (x86_spec(X86Paging::Four), X86_IOMMU_DEVICE),
        ]
        {
            spec.second_disk = Some(SecondDisk {
                path: Path::new("second.img"),
                block_size: 512,
                line: DiskLine::Own,
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
            // Both disks, the keyboard, and the RNG, which the firmware and
            // the virtio-rng driver both reach through the IOMMU, modern-only.
            let devices = virtio(&argv);
            assert_eq!(devices.len(), 4);
            let behind = devices.iter().filter(|d| d.contains(",iommu_platform=on"));
            assert_eq!(behind.count(), 4);
            assert!(
                devices
                    .iter()
                    .any(|d| d == "virtio-rng-pci,disable-legacy=on,iommu_platform=on")
            );

            spec.iommu = Iommu::Absent;
            let argv = build_qemu_argv(&spec).unwrap();
            assert!(!argv.iter().any(|a| a.contains("iommu")));
            let devices = virtio(&argv);
            assert_eq!(devices.len(), 4);
            assert!(
                devices
                    .iter()
                    .any(|d| d == "virtio-rng-pci,disable-legacy=on")
            );
        }
    }

    /// The `-device` values of `argv`.
    fn devices(argv: &[String]) -> Vec<&str>
    {
        argv.windows(2)
            .filter(|w| w[0] == "-device")
            .map(|w| w[1].as_str())
            .collect()
    }

    #[test]
    fn the_test_devices_are_attached_only_when_asked_at_pinned_slots()
    {
        for mut spec in [riscv_spec(4, 512), x86_spec(X86Paging::Four)]
        {
            for iommu in [Iommu::Attached, Iommu::Absent]
            {
                spec.iommu = iommu;
                spec.test_devices = false;
                let argv = build_qemu_argv(&spec).unwrap();
                assert!(
                    !devices(&argv)
                        .iter()
                        .any(|d| *d == EDU_DEVICE || d.starts_with("pci-testdev"))
                );

                spec.test_devices = true;
                let argv = build_qemu_argv(&spec).unwrap();
                let attached = devices(&argv);
                assert!(attached.contains(&EDU_DEVICE));
                let testdevs: Vec<&str> = attached
                    .iter()
                    .copied()
                    .filter(|d| d.starts_with("pci-testdev"))
                    .collect();
                assert_eq!(testdevs, TEST_FAULT_DEVICES);
                // Every function is pinned past the disks' slots, below
                // q35's one-line range.
                for d in testdevs
                {
                    let addr = d
                        .split(',')
                        .find_map(|p| p.strip_prefix("addr=0x"))
                        .unwrap();
                    let slot = u8::from_str_radix(addr, 16).unwrap();
                    assert!(slot > SHARED_LINE_SECOND_DISK_SLOT && slot < 25, "{d}");
                }
            }
        }
    }

    // Defect caught: a TPM launch that keeps the RNG, so the TPM driver is
    // not the `hwrng` class's only member, or attaches a device on a backend
    // the emulator's socket does not carry, or a riscv64 launch that takes a
    // TPM QEMU's `virt` machine cannot decode.
    #[test]
    fn a_tpm_launch_attaches_the_tpm_in_place_of_the_rng()
    {
        let rng = |argv: &[String]| argv.iter().any(|a| a.starts_with("virtio-rng-pci"));
        let spec = x86_spec(X86Paging::Four);
        assert!(rng(&build_qemu_argv(&spec).unwrap()));
        assert!(
            !build_qemu_argv(&spec)
                .unwrap()
                .iter()
                .any(|a| a == "-tpmdev")
        );
        for (interface, device) in [
            (TpmInterface::Fifo, "tpm-tis,tpmdev=tpm0"),
            (TpmInterface::Crb, "tpm-crb,tpmdev=tpm0"),
        ]
        {
            let tpm = Tpm {
                interface,
                socket: Path::new("swtpm.sock"),
            };
            let argv = build_qemu_argv_with_tpm(&spec, Some(tpm)).unwrap();
            assert!(!rng(&argv));
            assert!(devices(&argv).contains(&device));
            assert!(
                argv.windows(2)
                    .any(|w| w[0] == "-chardev" && w[1] == "socket,id=chrtpm,path=swtpm.sock")
            );
            assert!(
                argv.windows(2)
                    .any(|w| w[0] == "-tpmdev" && w[1] == "emulator,id=tpm0,chardev=chrtpm")
            );
        }
        let tpm = Tpm {
            interface: TpmInterface::Fifo,
            socket: Path::new("swtpm.sock"),
        };
        build_qemu_argv_with_tpm(&riscv_spec(4, 512), Some(tpm)).unwrap_err();
    }

    #[test]
    fn the_hotplug_port_is_attached_only_when_asked_and_native_turns_acpi_hotplug_off()
    {
        let global = |argv: &[String]| {
            argv.windows(2)
                .any(|w| w[0] == "-global" && w[1] == X86_NATIVE_HOTPLUG_GLOBAL)
        };
        for mut spec in [riscv_spec(4, 512), x86_spec(X86Paging::Four)]
        {
            spec.hotplug_port = None;
            let argv = build_qemu_argv(&spec).unwrap();
            assert!(!devices(&argv).contains(&HOTPLUG_PORT_DEVICE));
            assert!(!devices(&argv).contains(&HOTPLUG_DISK_PORT_DEVICE));
            assert!(!global(&argv));

            spec.hotplug_port = Some(HotplugPort::empty(HotplugControl::Firmware));
            let argv = build_qemu_argv(&spec).unwrap();
            assert!(devices(&argv).contains(&HOTPLUG_PORT_DEVICE));
            assert!(devices(&argv).contains(&HOTPLUG_DISK_PORT_DEVICE));
            assert!(!global(&argv));

            spec.hotplug_port = Some(HotplugPort::empty(HotplugControl::Native));
            let argv = build_qemu_argv(&spec).unwrap();
            assert!(devices(&argv).contains(&HOTPLUG_PORT_DEVICE));
            assert!(devices(&argv).contains(&HOTPLUG_DISK_PORT_DEVICE));
            assert_eq!(global(&argv), spec.arch == Arch::X86_64);
        }
        assert!(HOTPLUG_PORT_DEVICE.contains(&format!("id={HOTPLUG_PORT_ID},")));
        assert!(HOTPLUG_DISK_PORT_DEVICE.contains(&format!("id={HOTPLUG_DISK_PORT_ID},")));
        assert!(EDU_DEVICE.ends_with(&format!("dma_mask={EDU_DMA_MASK:#x}")));
    }

    #[test]
    fn a_port_disk_sits_behind_the_port()
    {
        let path = Path::new("/w/spare.img");
        for mut spec in [riscv_spec(4, 512), x86_spec(X86Paging::Four)]
        {
            spec.hotplug_port = Some(HotplugPort {
                control: HotplugControl::Native,
                disk: Some(PortDisk::Boot),
            });
            let argv = build_qemu_argv(&spec).unwrap();
            let placed = devices(&argv);
            let boot: Vec<usize> = placed
                .iter()
                .enumerate()
                .filter(|(_, d)| d.starts_with("virtio-blk-pci,drive=hd0,"))
                .map(|(at, _)| at)
                .collect();
            let port = placed.iter().position(|d| *d == HOTPLUG_PORT_DEVICE);
            assert_eq!(boot.len(), 1, "one boot disk device: {placed:?}");
            assert!(port.is_some_and(|port| port < boot[0]), "{placed:?}");
            assert!(
                placed[boot[0]].ends_with(&format!(",bus={HOTPLUG_PORT_ID},id={PORT_DISK_ID}"))
            );
            assert!(!argv.iter().any(|a| a == "-blockdev"));

            spec.hotplug_port = Some(HotplugPort {
                control: HotplugControl::Native,
                disk: Some(PortDisk::Data {
                    path,
                    block_size: 4096,
                }),
            });
            let argv = build_qemu_argv(&spec).unwrap();
            assert!(blk_device_arg(&argv, "hd0").is_some());
            let data = blk_device_arg(&argv, PORT_DISK_NODE).unwrap();
            assert!(data.contains(",logical_block_size=4096,"));
            assert!(data.ends_with(&format!(",bus={HOTPLUG_PORT_ID},id={PORT_DISK_ID}")));
            let node = argv
                .windows(2)
                .find(|w| w[0] == "-blockdev")
                .map(|w| w[1].as_str());
            assert_eq!(
                node,
                Some(
                    format!(
                        "driver=raw,node-name={PORT_DISK_NODE},file.driver=file,\
                         file.filename=/w/spare.img"
                    )
                    .as_str()
                )
            );
        }
        let iommu_platform = |iommu| {
            port_disk_properties(4096, iommu)
                .iter()
                .any(|(name, value)| {
                    *name == "iommu_platform" && *value == crate::qmp::Property::Flag(true)
                })
        };
        assert!(iommu_platform(Iommu::Attached));
        assert!(!iommu_platform(Iommu::Absent));
        assert!(
            port_disk_properties(4096, Iommu::Absent)
                .contains(&("drive", crate::qmp::Property::Text(PORT_DISK_NODE)))
        );
    }

    #[test]
    fn the_test_fault_bars_match_the_fixture_roles()
    {
        use ipc::test_fault_labels::{HANG_BAR_BYTES, ORPHAN_BAR_BYTES};
        let bar = |d: &str| {
            d.split(',')
                .find_map(|p| p.strip_prefix("membar="))
                .map(|v| v.strip_suffix('K').unwrap().parse::<u64>().unwrap() << 10)
        };
        let bars: Vec<Option<u64>> = TEST_FAULT_DEVICES.iter().map(|d| bar(d)).collect();
        assert_eq!(
            bars,
            [None, None, Some(HANG_BAR_BYTES), Some(ORPHAN_BAR_BYTES)]
        );
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

    /// Whether `argv` passes `flag` followed by `value`.
    fn has_pair(argv: &[String], flag: &str, value: &str) -> bool
    {
        argv.windows(2).any(|w| w[0] == flag && w[1] == value)
    }

    #[test]
    fn a_framebuffer_launch_keeps_the_adapter_and_opens_no_window()
    {
        // The framebuffer cell needs the GOP the adapter gives the
        // bootloader; dropping the adapter would skip the framebuffer case,
        // and a missing `-display none` would open a window, or fall back to
        // VNC, on the host.
        let mut riscv = riscv_spec(4, 512);
        riscv.display = QemuDisplay::Framebuffer;
        let argv = build_qemu_argv(&riscv).unwrap();
        assert!(has_pair(&argv, "-device", "VGA"));
        assert!(has_pair(&argv, "-display", "none"));
        assert!(!argv.iter().any(|a| a == "usb-kbd"));

        let mut x86 = x86_spec(X86Paging::Four);
        x86.display = QemuDisplay::Framebuffer;
        let argv = build_qemu_argv(&x86).unwrap();
        assert!(!has_pair(&argv, "-vga", "none"));
        assert!(has_pair(&argv, "-display", "none"));
    }

    #[test]
    fn a_headless_launch_drops_the_adapter_on_both_machines()
    {
        let argv = build_qemu_argv(&riscv_spec(4, 512)).unwrap();
        assert!(!has_pair(&argv, "-device", "VGA"));
        assert!(has_pair(&argv, "-display", "none"));

        let argv = build_qemu_argv(&x86_spec(X86Paging::Four)).unwrap();
        assert!(has_pair(&argv, "-vga", "none"));
        assert!(has_pair(&argv, "-display", "none"));
    }
}
