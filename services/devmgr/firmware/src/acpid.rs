// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/devmgr/firmware/src/acpid.rs

//! devmgr's side of acpid: which operation regions it grants acpid, which
//! configuration-space accesses it makes for it, the memory grants it keeps
//! for a restarted acpid, and the results of acpid's evaluation it keeps for
//! each PCI host bridge once they agree with the device records
//! ([services/acpid/README.md](../../../acpid/README.md) § Region grants and
//! § Checks).
//!
//! The module decides; devmgr carves, derives, and accesses. A refusal names
//! what the request collides with, or which check failed, for devmgr's log.

extern crate alloc;

use alloc::collections::TryReserveError;
use alloc::vec::Vec;

use ipc::devmgr_labels::{PRT_NO_ROUTE, WINDOW_BUS, WINDOW_IO, WINDOW_MEMORY};

use crate::aml::CrsResource;
use crate::pci_records::RecordState;
use crate::scan::PciDevice;

/// The page size a memory grant is rounded to.
pub const PAGE_SIZE: u64 = 0x1000;
/// The ports past the last I/O port.
const IO_SPACE_END: u64 = 0x1_0000;
/// The configuration-mechanism ports, 0xCF8 to 0xCFF, through which every
/// function's configuration space is reachable on x86-64.
pub const CONFIG_PORTS: Range = Range {
    space: Space::Io,
    base: 0xCF8,
    end: 0xD00,
};
/// The lowest configuration-space offset acpid may write: below it lies the
/// header, whose BARs, Command register and bridge bus numbers devmgr
/// programs.
pub const CONFIG_WRITE_FLOOR: u64 = 0x40;
/// The bytes of one function's configuration space.
pub const CONFIG_SPACE_LEN: u64 = 0x1000;
/// The devices of one bus.
pub const PRT_DEVICES: usize = 32;

// ── Ranges and region grants ──────────────────────────────────────────

/// An ACPI address space devmgr grants regions of.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Space
{
    /// `SystemMemory`.
    Memory,
    /// `SystemIO`.
    Io,
}

/// A half-open range `[base, end)` of one space.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Range
{
    pub space: Space,
    pub base: u64,
    pub end: u64,
}

impl Range
{
    /// Whether the two ranges share an address of the same space.
    #[must_use]
    pub fn overlaps(&self, other: &Range) -> bool
    {
        self.space == other.space && self.base < other.end && other.base < self.end
    }

    /// Whether `other` lies wholly inside this range, in the same space.
    #[must_use]
    pub fn contains(&self, other: &Range) -> bool
    {
        self.space == other.space && self.base <= other.base && other.end <= self.end
    }

    /// The range's length.
    #[must_use]
    pub fn len(&self) -> u64
    {
        self.end.saturating_sub(self.base)
    }

    /// Whether the range holds no address.
    #[must_use]
    pub fn is_empty(&self) -> bool
    {
        self.end <= self.base
    }
}

/// The `data` words an acpid request of `label` carries, the version word
/// included, `count` being its word 3 (a `BRIDGE_WINDOWS` window count,
/// taken at most [`ipc::devmgr_labels::MAX_BRIDGE_WINDOWS`]). A request
/// shorter than this is malformed: a word it does not carry would read as 0.
/// `None` for a label without a fixed layout here.
#[must_use]
pub fn request_words(label: u64, count: u64) -> Option<usize>
{
    use ipc::devmgr_labels as labels;
    match label
    {
        labels::ACPI_REGION_GRANT => Some(4),
        labels::ACPI_PCI_CONFIG => Some(6),
        labels::OSC_RESULT => Some(7),
        labels::BRIDGE_WINDOWS =>
        {
            let windows = usize::try_from(count)
                .unwrap_or(usize::MAX)
                .min(labels::MAX_BRIDGE_WINDOWS);
            windows.checked_mul(3)?.checked_add(4)
        }
        labels::PRT_TABLE => Some(labels::PRT_TABLE_WORDS),
        labels::ACPI_HOTPLUG => Some(3),
        _ => None,
    }
}

/// The range a grant of `len` bytes or ports at `base` of `space` covers:
/// memory widened to whole pages, ports exactly. `None` for an empty or
/// overflowing range and for ports past 0xFFFF.
#[must_use]
pub fn grant_range(space: Space, base: u64, len: u64) -> Option<Range>
{
    let end = base.checked_add(len).filter(|_| len != 0)?;
    match space
    {
        Space::Io => (end <= IO_SPACE_END).then_some(Range { space, base, end }),
        Space::Memory =>
        {
            let mask = !(PAGE_SIZE - 1);
            let end = end.checked_add(PAGE_SIZE - 1)? & mask;
            Some(Range {
                space,
                base: base & mask,
                end,
            })
        }
    }
}

/// The range an `ACPI_REGION_GRANT` of `len` bytes or ports at `base` of
/// `space` is granted: the ports exactly, a region at a time; for memory,
/// the one page that holds the access, since memory is carved and kept a page
/// at a time, so whether a page is granted does not depend on which
/// overlapping region asked first. `None` where [`grant_range`] gives none,
/// and for memory that spans more than one page.
#[must_use]
pub fn request_range(space: Space, base: u64, len: u64) -> Option<Range>
{
    grant_range(space, base, len).filter(|r| r.space == Space::Io || r.len() == PAGE_SIZE)
}

/// Every BAR of `device` the scan sized, as a range.
pub fn pci_ranges(device: &PciDevice) -> impl Iterator<Item = Range> + '_
{
    device
        .bar_phys
        .iter()
        .zip(&device.bar_size)
        .zip(&device.bar_is_mmio)
        .take(device.bar_count)
        .filter_map(|((&base, &size), &mmio)| {
            let end = base.checked_add(size).filter(|_| size != 0)?;
            let space = if mmio { Space::Memory } else { Space::Io };
            Some(Range { space, base, end })
        })
}

/// A platform record's `Mmio` or `IoPort` resource as a range; `None` for
/// an interrupt, and for an empty or overflowing range.
#[must_use]
pub fn platform_range(resource: CrsResource) -> Option<Range>
{
    let (space, base, len) = match resource
    {
        CrsResource::Mmio { base, size } => (Space::Memory, base, size),
        CrsResource::IoPort { base, count } => (Space::Io, u64::from(base), u64::from(count)),
        CrsResource::Interrupt { .. } => return None,
    };
    let end = base.checked_add(len).filter(|_| len != 0)?;
    Some(Range { space, base, end })
}

/// What a refused region collides with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Holder
{
    /// A resource of a device record: a PCI BAR or a platform record's
    /// `Mmio` or `IoPort`, whether or not a driver holds it yet, a resource
    /// container's aside ([`HeldRange`]).
    Device,
    /// The configuration-mechanism ports ([`CONFIG_PORTS`]).
    ConfigMechanism,
    /// The FACS, whose global lock and waking vector acpid does not own.
    Facs,
    /// An interrupt controller the kernel programs (the local APIC, an I/O
    /// APIC, the APLIC, an IMSIC interrupt file) or a legacy port the kernel
    /// drives.
    Kernel,
}

/// A memory or I/O range a device record not removed holds, and whether
/// that record is a resource container ([`crate::binding::container`]),
/// whose ranges are the firmware's own registers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeldRange
{
    pub range: Range,
    pub container: bool,
}

/// Why a region is refused: the holder and the range of its it overlaps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Refusal
{
    pub holder: Holder,
    pub range: Range,
}

/// Whether devmgr refuses acpid the region `want` ([`grant_range`]'s
/// range): the first range of `devices` (each record's resources, a
/// resource container's left out), then of `kernel` (the kernel's interrupt
/// controllers and ports), then [`CONFIG_PORTS`], then `facs` that `want`
/// overlaps. A container's range is granted only where no other holder
/// refuses it, a device record that shares it among them.
/// `None` lets the request go on to the carve, which refuses memory no
/// aperture devmgr still holds covers.
pub fn region_refusal(
    want: &Range,
    devices: impl IntoIterator<Item = HeldRange>,
    kernel: &[Range],
    facs: Option<Range>,
) -> Option<Refusal>
{
    let refused = |holder: Holder| {
        move |range: Range| want.overlaps(&range).then_some(Refusal { holder, range })
    };
    devices
        .into_iter()
        .filter(|held| !held.container)
        .map(|held| held.range)
        .find_map(refused(Holder::Device))
        .or_else(|| kernel.iter().copied().find_map(refused(Holder::Kernel)))
        .or_else(|| refused(Holder::ConfigMechanism)(CONFIG_PORTS))
        .or_else(|| facs.and_then(refused(Holder::Facs)))
}

/// The memory grants devmgr keeps for acpid: each carved range and the cap
/// over it, so a range granted once is granted again, as a derivation, to an
/// acpid that restarts, instead of being lost to the first one's exit.
pub struct Grants<S>
{
    kept: Vec<(Range, S)>,
}

impl<S: Copy> Default for Grants<S>
{
    fn default() -> Self
    {
        Self::new()
    }
}

impl<S: Copy> Grants<S>
{
    /// No grant kept.
    #[must_use]
    pub const fn new() -> Self
    {
        Self { kept: Vec::new() }
    }

    /// The kept grant whose range contains `want`, and its cap.
    #[must_use]
    pub fn within(&self, want: &Range) -> Option<(Range, S)>
    {
        self.kept
            .iter()
            .copied()
            .find(|(range, _)| range.contains(want))
    }

    /// Keep `slot` as the cap over `range`.
    ///
    /// # Errors
    /// Returns the allocation error when the table cannot grow; nothing is
    /// kept, and the caller still holds the cap.
    pub fn keep(&mut self, range: Range, slot: S) -> Result<(), TryReserveError>
    {
        self.kept.try_reserve(1)?;
        self.kept.push((range, slot));
        Ok(())
    }
}

// ── Configuration-space accesses ──────────────────────────────────────

/// An access acpid asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigOp
{
    Read,
    Write,
}

/// What devmgr does for an allowed access.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigAccess
{
    /// Make the access.
    Access,
    /// Make none, and answer the read with all-ones ([`all_ones`]), as an
    /// absent function reads.
    AllOnes,
}

/// Why devmgr makes no access.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigError
{
    /// A width other than 1, 2 or 4, an offset not aligned to it, or a
    /// register past the configuration space.
    Invalid,
    /// A write below [`CONFIG_WRITE_FLOOR`], or to a function with no
    /// unbound record: a bound one (a driver was started for it, or devmgr
    /// took it as a RISC-V IOMMU unit or a managed hotplug slot's port), a
    /// removed one, or one devmgr has no
    /// record of.
    Refused,
}

/// Whether devmgr makes a `width`-byte `op` at `offset` of a function
/// whose record is in `state` (`None`: no record holds the function).
///
/// # Errors
/// [`ConfigError`] says why no access is made.
pub fn config_access(
    op: ConfigOp,
    offset: u64,
    width: u64,
    state: Option<RecordState>,
) -> Result<ConfigAccess, ConfigError>
{
    let aligned = matches!(width, 1 | 2 | 4) && offset.is_multiple_of(width);
    if !aligned
        || offset
            .checked_add(width)
            .is_none_or(|end| end > CONFIG_SPACE_LEN)
    {
        return Err(ConfigError::Invalid);
    }
    match (op, state)
    {
        (ConfigOp::Read, Some(RecordState::Unbound | RecordState::Bound)) =>
        {
            Ok(ConfigAccess::Access)
        }
        (ConfigOp::Read, None | Some(RecordState::Removed)) => Ok(ConfigAccess::AllOnes),
        (ConfigOp::Write, Some(RecordState::Unbound)) if offset >= CONFIG_WRITE_FLOOR =>
        {
            Ok(ConfigAccess::Access)
        }
        (ConfigOp::Write, _) => Err(ConfigError::Refused),
    }
}

/// The all-ones value of a `width`-byte read (1, 2 or 4; 0 for any other).
#[must_use]
pub const fn all_ones(width: u64) -> u64
{
    match width
    {
        1 => 0xFF,
        2 => 0xFFFF,
        4 => 0xFFFF_FFFF,
        _ => 0,
    }
}

// ── Host bridge results ───────────────────────────────────────────────

/// A function's address: segment, bus, device, function.
pub type Address = (u16, u8, u8, u8);

/// The address of `device`.
#[must_use]
pub fn address(device: &PciDevice) -> Address
{
    (device.segment, device.bus, device.dev, device.func)
}

/// A bridge's `_OSC` result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Osc
{
    /// Whether `_OSC` was evaluated; false when the bridge has none or its
    /// evaluation failed.
    pub evaluated: bool,
    /// The status dword it returned.
    pub status: u32,
    /// The control dword it returned: the features whose native control the
    /// firmware grants.
    pub control: u32,
}

/// The kind of one bridge window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WindowKind
{
    Memory,
    Io,
    Bus,
}

/// One `_CRS` window of a bridge: `[base, end)` of its kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Window
{
    pub kind: WindowKind,
    pub base: u64,
    pub end: u64,
}

/// The windows of a `BRIDGE_WINDOWS` push: `words` holds one
/// `(kind, base, length)` triple per window. `None` for an unknown kind, a
/// length that overflows, or a word count not a multiple of three; an empty
/// window is dropped.
#[must_use]
pub fn windows_from_words(words: &[u64]) -> Option<Vec<Window>>
{
    let (triples, rest) = words.as_chunks::<3>();
    if !rest.is_empty()
    {
        return None;
    }
    let mut windows = Vec::new();
    for &[kind, base, len] in triples
    {
        let kind = match kind
        {
            WINDOW_MEMORY => WindowKind::Memory,
            WINDOW_IO => WindowKind::Io,
            WINDOW_BUS => WindowKind::Bus,
            _ => return None,
        };
        let end = base.checked_add(len)?;
        if len != 0
        {
            windows.try_reserve(1).ok()?;
            windows.push(Window { kind, base, end });
        }
    }
    Some(windows)
}

/// The routes of one root bus: the line of pin `INTA` to `INTD` of each
/// device, [`PRT_NO_ROUTE`] where the table routes none.
pub type PrtTable = [[u16; 4]; PRT_DEVICES];

/// The table of a `PRT_TABLE` push's 32 device words, each holding pin
/// `INTA` to `INTD` in its 16-bit lanes 0 to 3. `None` unless `words` holds
/// exactly 32.
#[must_use]
pub fn prt_from_words(words: &[u64]) -> Option<PrtTable>
{
    if words.len() != PRT_DEVICES
    {
        return None;
    }
    let mut table = [[0u16; 4]; PRT_DEVICES];
    for (pins, &word) in table.iter_mut().zip(words)
    {
        for (lane, line) in pins.iter_mut().enumerate()
        {
            let shift = 16u32.saturating_mul(u32::try_from(lane).ok()?);
            *line = u16::try_from(word.checked_shr(shift).unwrap_or(0) & 0xFFFF).ok()?;
        }
    }
    Some(table)
}

/// A `PRT_TABLE` push's interrupt model.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrtMode
{
    /// The model acpid selected: GSIs.
    Routes,
    /// x86-64, before `_PIC(1)`: the PIC model the firmware hands over in.
    PicMode,
}

/// How devmgr checks a table of one [`PrtMode`], which the arch decides.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrtRule
{
    /// The mode whose table devmgr must hold for the bridge before it keeps
    /// this one.
    pub after: Option<PrtMode>,
    /// Whether each function's route must equal the line devmgr gives it;
    /// otherwise it must only be routed.
    pub lines: bool,
}

/// Which check a bridge push failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Disagreement
{
    /// The windows hold no bus window, more than one, or one that does not
    /// hold the bridge's bus or runs past bus 255.
    BusRange,
    /// A memory BAR of the function lies in no memory window.
    MemoryWindow
    {
        function: Address, bar: Range
    },
    /// A memory BAR of the function lies in no aperture devmgr was given at
    /// boot.
    Aperture
    {
        function: Address, bar: Range
    },
    /// An I/O BAR of the function lies in no I/O window.
    IoWindow
    {
        function: Address, bar: Range
    },
    /// The table routes no line for the function's pin, which reaches the
    /// root bus as `pin` of device `dev`.
    Unrouted
    {
        function: Address, dev: u8, pin: u8
    },
    /// The table routes the function's pin to `line`, devmgr gives it
    /// `expected`.
    Line
    {
        function: Address,
        line: u16,
        expected: u32,
    },
    /// devmgr does not yet hold what it checks the table against: the
    /// bridge's windows, whose bus range names the functions checked, or its
    /// table of the [`PrtRule::after`] mode.
    Order,
}

/// A value devmgr holds for a bridge, and the boot functions its check
/// covered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Held<T>
{
    pub value: T,
    pub covered: u64,
}

/// What devmgr holds for one PCI host bridge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bridge
{
    pub segment: u16,
    pub bus: u8,
    pub osc: Option<Osc>,
    pub windows: Option<Held<Vec<Window>>>,
    pub pic: Option<Held<PrtTable>>,
    pub routes: Option<Held<PrtTable>>,
}

impl Bridge
{
    /// The bridge's buses, those of the windows devmgr holds; `None` until
    /// it holds them.
    #[must_use]
    pub fn buses(&self) -> Option<(u8, u8)>
    {
        self.windows
            .as_ref()
            .and_then(|held| bus_range(self.bus, &held.value))
    }
}

/// How devmgr took a push.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Push
{
    /// The first of its kind for the bridge that passed: devmgr holds it.
    Kept,
    /// Equal to the one devmgr holds.
    Same,
    /// Different from the one devmgr holds, which it keeps.
    Differs,
    /// It failed the check; devmgr holds nothing new.
    Refused(Disagreement),
}

/// The bridges acpid pushed results for, in segment, then bus order.
#[derive(Default)]
pub struct Bridges
{
    list: Vec<Bridge>,
}

impl Bridges
{
    /// No bridge.
    #[must_use]
    pub const fn new() -> Self
    {
        Self { list: Vec::new() }
    }

    /// The bridge at `ordinal`, in segment, then bus order.
    #[must_use]
    pub fn get(&self, ordinal: usize) -> Option<&Bridge>
    {
        self.list.get(ordinal)
    }

    /// Every bridge, in segment, then bus order.
    pub fn iter(&self) -> impl Iterator<Item = &Bridge> + Clone
    {
        self.list.iter()
    }

    /// The bridge at `(segment, bus)`, if devmgr holds a push for it.
    #[must_use]
    pub fn find(&self, segment: u16, bus: u8) -> Option<&Bridge>
    {
        self.list
            .iter()
            .find(|b| (b.segment, b.bus) == (segment, bus))
    }

    /// The line the table of `mode` devmgr holds routes `function`'s
    /// interrupt pin to: the table of the bridge whose buses
    /// ([`Bridge::buses`]) hold the function's bus, at the pin and device
    /// number its interrupt reaches the root bus with
    /// (`PciDevice::host_intx`). `None` for a function with no pin, one on
    /// the buses of no bridge devmgr holds windows for, one whose bridge has
    /// no table of `mode` held, and one whose pin that table does not route.
    #[must_use]
    pub fn line(&self, mode: PrtMode, function: &PciDevice) -> Option<u32>
    {
        let (pin, dev) = function.host_intx?;
        let bridge = self.list.iter().find(|b| {
            b.segment == function.segment
                && b.buses()
                    .is_some_and(|(first, last)| (first..=last).contains(&function.bus))
        })?;
        let held = match mode
        {
            PrtMode::Routes => bridge.routes.as_ref(),
            PrtMode::PicMode => bridge.pic.as_ref(),
        }?;
        route(&held.value, pin, dev).map(u32::from)
    }

    /// The bridge at `(segment, bus)`, made with nothing held when absent;
    /// `None` when a new bridge cannot be recorded.
    fn entry(&mut self, segment: u16, bus: u8) -> Option<&mut Bridge>
    {
        let at = match self
            .list
            .binary_search_by_key(&(segment, bus), |b| (b.segment, b.bus))
        {
            Ok(at) => at,
            Err(at) =>
            {
                self.list.try_reserve(1).ok()?;
                self.list.insert(
                    at,
                    Bridge {
                        segment,
                        bus,
                        osc: None,
                        windows: None,
                        pic: None,
                        routes: None,
                    },
                );
                at
            }
        };
        self.list.get_mut(at)
    }

    /// Take the bridge's `_OSC` result: the first is kept for the boot.
    ///
    /// `None` when a new bridge cannot be recorded; nothing is held then.
    pub fn push_osc(&mut self, segment: u16, bus: u8, osc: Osc) -> Option<Push>
    {
        let bridge = self.entry(segment, bus)?;
        Some(keep(&mut bridge.osc, osc))
    }

    /// Take the bridge's `_CRS` windows, checked against `functions` (the
    /// device records, removed ones left out) and the boot `apertures`
    /// (`(base, end)`): the first that pass are kept for the boot
    /// ([`check_windows`]).
    ///
    /// `None` when a new bridge cannot be recorded; nothing is held then.
    pub fn push_windows<'a>(
        &mut self,
        segment: u16,
        bus: u8,
        windows: Vec<Window>,
        functions: impl Iterator<Item = &'a PciDevice> + Clone,
        apertures: &[(u64, u64)],
    ) -> Option<Push>
    {
        let bridge = self.entry(segment, bus)?;
        if let Some(held) = &bridge.windows
        {
            return Some(
                if held.value == windows
                {
                    Push::Same
                }
                else
                {
                    Push::Differs
                },
            );
        }
        match check_windows(segment, bus, &windows, functions, apertures)
        {
            Ok(covered) =>
            {
                bridge.windows = Some(Held {
                    value: windows,
                    covered,
                });
                Some(Push::Kept)
            }
            Err(why) => Some(Push::Refused(why)),
        }
    }

    /// Take the bridge's `_PRT` of `mode`, checked by `rule` against the
    /// functions on its buses ([`Bridge::buses`]), `expected` giving the
    /// line devmgr gives a function: the first that passes is kept for the
    /// boot ([`check_prt`]). A table that comes before the bridge's windows,
    /// or before its table of `rule`'s earlier mode, is refused
    /// ([`Disagreement::Order`]).
    ///
    /// `None` when a new bridge cannot be recorded; nothing is held then.
    #[expect(
        clippy::too_many_arguments,
        reason = "the bridge's address, the table, its mode and rule, and the records it is \
                  checked against are each an input of the check"
    )]
    pub fn push_prt<'a>(
        &mut self,
        segment: u16,
        bus: u8,
        mode: PrtMode,
        table: &PrtTable,
        rule: PrtRule,
        functions: impl Iterator<Item = &'a PciDevice>,
        expected: impl Fn(&PciDevice) -> Option<u32>,
    ) -> Option<Push>
    {
        let bridge = self.entry(segment, bus)?;
        let held = match mode
        {
            PrtMode::Routes => &bridge.routes,
            PrtMode::PicMode => &bridge.pic,
        };
        if let Some(held) = held
        {
            return Some(
                if held.value == *table
                {
                    Push::Same
                }
                else
                {
                    Push::Differs
                },
            );
        }
        let waiting = match rule.after
        {
            Some(PrtMode::Routes) => bridge.routes.is_none(),
            Some(PrtMode::PicMode) => bridge.pic.is_none(),
            None => false,
        };
        let Some((first, last)) = bridge.buses().filter(|_| !waiting)
        else
        {
            return Some(Push::Refused(Disagreement::Order));
        };
        let on_bridge =
            functions.filter(|f| f.segment == segment && (first..=last).contains(&f.bus));
        let expected = |f: &PciDevice| if rule.lines { expected(f) } else { None };
        match check_prt(table, on_bridge, expected)
        {
            Ok(covered) =>
            {
                let held = Some(Held {
                    value: *table,
                    covered,
                });
                match mode
                {
                    PrtMode::Routes => bridge.routes = held,
                    PrtMode::PicMode => bridge.pic = held,
                }
                Some(Push::Kept)
            }
            Err(why) => Some(Push::Refused(why)),
        }
    }
}

/// Keep `value` in `slot` when it is empty; else compare.
fn keep<T: PartialEq>(slot: &mut Option<T>, value: T) -> Push
{
    match slot
    {
        Some(held) if *held == value => Push::Same,
        Some(_) => Push::Differs,
        None =>
        {
            *slot = Some(value);
            Push::Kept
        }
    }
}

/// The bus range of `windows`: its one bus window, when that holds `bus` and
/// ends at or below bus 255.
fn bus_range(bus: u8, windows: &[Window]) -> Option<(u8, u8)>
{
    let mut buses = windows.iter().filter(|w| w.kind == WindowKind::Bus);
    let window = buses.next()?;
    if buses.next().is_some()
    {
        return None;
    }
    let first = u8::try_from(window.base).ok()?;
    let last = u8::try_from(window.end.checked_sub(1)?).ok()?;
    (first..=last).contains(&bus).then_some((first, last))
}

/// Check a bridge's windows against the functions on its buses: each memory
/// BAR inside a memory window and inside one of the boot `apertures`
/// (`(base, end)`), each I/O BAR inside an I/O window. A BAR at address 0 is
/// one the firmware left unassigned and is not checked. Returns the
/// functions checked.
///
/// # Errors
/// The first [`Disagreement`] found.
pub fn check_windows<'a>(
    segment: u16,
    bus: u8,
    windows: &[Window],
    functions: impl Iterator<Item = &'a PciDevice>,
    apertures: &[(u64, u64)],
) -> Result<u64, Disagreement>
{
    let (first, last) = bus_range(bus, windows).ok_or(Disagreement::BusRange)?;
    let inside = |kind: WindowKind, bar: &Range| {
        windows
            .iter()
            .any(|w| w.kind == kind && w.base <= bar.base && bar.end <= w.end)
    };
    let mut covered = 0u64;
    for function in functions.filter(|f| f.segment == segment && (first..=last).contains(&f.bus))
    {
        let at = address(function);
        for bar in pci_ranges(function).filter(|bar| bar.base != 0)
        {
            match bar.space
            {
                Space::Memory =>
                {
                    if !inside(WindowKind::Memory, &bar)
                    {
                        return Err(Disagreement::MemoryWindow { function: at, bar });
                    }
                    if !apertures
                        .iter()
                        .any(|&(base, end)| base <= bar.base && bar.end <= end)
                    {
                        return Err(Disagreement::Aperture { function: at, bar });
                    }
                }
                Space::Io =>
                {
                    if !inside(WindowKind::Io, &bar)
                    {
                        return Err(Disagreement::IoWindow { function: at, bar });
                    }
                }
            }
        }
        covered = covered.saturating_add(1);
    }
    Ok(covered)
}

/// Check a root bus's routes against `functions`, those on the bridge's
/// buses: each function with an interrupt pin must be routed at the pin and
/// device number its interrupt reaches the root bus with
/// (`PciDevice::host_intx`), to `expected`'s line for it when that gives
/// one. Returns the functions checked.
///
/// # Errors
/// The first [`Disagreement`] found.
pub fn check_prt<'a>(
    table: &PrtTable,
    functions: impl Iterator<Item = &'a PciDevice>,
    expected: impl Fn(&PciDevice) -> Option<u32>,
) -> Result<u64, Disagreement>
{
    let mut covered = 0u64;
    for function in functions
    {
        let Some((pin, dev)) = function.host_intx
        else
        {
            continue;
        };
        let at = address(function);
        let line = route(table, pin, dev).ok_or(Disagreement::Unrouted {
            function: at,
            dev,
            pin,
        })?;
        if let Some(want) = expected(function)
            && u32::from(line) != want
        {
            return Err(Disagreement::Line {
                function: at,
                line,
                expected: want,
            });
        }
        covered = covered.saturating_add(1);
    }
    Ok(covered)
}

/// The line `table` routes pin `pin` (`INTA`..=`INTD`, 1..=4) of root-bus
/// device `dev` to; `None` where it routes none.
fn route(table: &PrtTable, pin: u8, dev: u8) -> Option<u16>
{
    table
        .get(usize::from(dev))
        .and_then(|pins| pins.get(usize::from(pin).checked_sub(1)?))
        .copied()
        .filter(|&line| u64::from(line) != PRT_NO_ROUTE)
}

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::binding::{RecordKeys, container};
    use crate::scan::MAX_BARS;
    use virtio_core::VirtioPciStartupInfo;

    fn function(at: Address, pin: u8) -> PciDevice
    {
        PciDevice {
            segment: at.0,
            bus: at.1,
            dev: at.2,
            func: at.3,
            vendor_id: 0x1AF4,
            device_id: 0x1041,
            class_code: 0,
            revision: 0,
            subsystem_vendor: 0,
            subsystem_id: 0,
            bar_phys: [0; MAX_BARS],
            bar_size: [0; MAX_BARS],
            bar_is_mmio: [false; MAX_BARS],
            bar_pci_idx: [0; MAX_BARS],
            bar_count: 0,
            irq_line: 0,
            irq_pin: pin,
            virtio_info: VirtioPciStartupInfo::default(),
            bridge_buses: None,
            host_intx: (pin != 0).then_some((pin, at.2)),
            msi: None,
            msix: None,
        }
    }

    fn with_bar(mut device: PciDevice, base: u64, size: u64, space: Space) -> PciDevice
    {
        let i = device.bar_count;
        device.bar_phys[i] = base;
        device.bar_size[i] = size;
        device.bar_is_mmio[i] = space == Space::Memory;
        device.bar_count += 1;
        device
    }

    fn memory(base: u64, end: u64) -> Range
    {
        Range {
            space: Space::Memory,
            base,
            end,
        }
    }

    fn io(base: u64, end: u64) -> Range
    {
        Range {
            space: Space::Io,
            base,
            end,
        }
    }

    fn window(kind: WindowKind, base: u64, end: u64) -> Window
    {
        Window { kind, base, end }
    }

    /// q35's root bridge as OVMF describes it: buses 0-0xFF, ports
    /// 0x6000-0xFFFF, memory below the ECAM and one window above 4 GiB.
    fn q35_windows() -> Vec<Window>
    {
        vec![
            window(WindowKind::Bus, 0, 0x100),
            window(WindowKind::Io, 0x6000, 0x1_0000),
            window(WindowKind::Memory, 0x8000_0000, 0xB000_0000),
            window(WindowKind::Memory, 0x38_0000_0000, 0x40_0000_0000),
        ]
    }

    /// devmgr's boot apertures on q35: [2 GiB, ECAM) and [4 GiB, top).
    const APERTURES: [(u64, u64); 2] =
        [(0x8000_0000, 0xB000_0000), (0x1_0000_0000, 0x80_0000_0000)];

    #[test]
    fn a_memory_grant_covers_whole_pages_and_ports_exactly()
    {
        assert_eq!(
            grant_range(Space::Memory, 0xFED0_0010, 8),
            Some(memory(0xFED0_0000, 0xFED0_1000))
        );
        assert_eq!(
            grant_range(Space::Memory, 0x1FFF, 2),
            Some(memory(0x1000, 0x3000))
        );
        assert_eq!(grant_range(Space::Io, 0x600, 4), Some(io(0x600, 0x604)));
        assert_eq!(
            grant_range(Space::Io, 0xFFFF, 1),
            Some(io(0xFFFF, 0x1_0000))
        );
        assert_eq!(grant_range(Space::Io, 0xFFFF, 2), None);
        assert_eq!(grant_range(Space::Io, 0x600, 0), None);
        assert_eq!(grant_range(Space::Memory, u64::MAX, 2), None);
        assert_eq!(grant_range(Space::Memory, u64::MAX - 1, 1), None);
    }

    #[test]
    fn a_region_that_overlaps_a_holder_is_refused_by_the_first_it_meets()
    {
        let nic = with_bar(
            with_bar(
                function((0, 0, 2, 0), 1),
                0x8100_0000,
                0x1000,
                Space::Memory,
            ),
            0x6000,
            0x20,
            Space::Io,
        );
        let serial = platform_range(CrsResource::IoPort {
            base: 0x3F8,
            count: 8,
        });
        let devices = || {
            pci_ranges(&nic).chain(serial).map(|range| HeldRange {
                range,
                container: false,
            })
        };
        let kernel = [memory(0xFEE0_0000, 0xFEE0_1000), io(0x40, 0x44)];
        let facs = Some(memory(0x7FEB_1000, 0x7FEB_1040));
        let refused =
            |want: Range| region_refusal(&want, devices(), &kernel, facs).map(|r| r.holder);

        // A byte in the BAR's page, and a port of each I/O resource.
        let page = grant_range(Space::Memory, 0x8100_0FF0, 4).unwrap_or(memory(0, 0));
        assert_eq!(refused(page), Some(Holder::Device));
        assert_eq!(refused(io(0x601F, 0x6020)), Some(Holder::Device));
        assert_eq!(refused(io(0x3FD, 0x3FE)), Some(Holder::Device));
        assert_eq!(refused(io(0xCFC, 0xD00)), Some(Holder::ConfigMechanism));
        assert_eq!(
            refused(memory(0xFEE0_0000, 0xFEE0_2000)),
            Some(Holder::Kernel)
        );
        assert_eq!(refused(io(0x43, 0x44)), Some(Holder::Kernel));
        assert_eq!(
            refused(memory(0x7FEB_0000, 0x7FEB_2000)),
            Some(Holder::Facs)
        );
        // The space is part of the range: port 0xCF8 is not memory 0xCF8.
        assert_eq!(refused(memory(0, 0x1000)), None);
        assert_eq!(refused(io(0x600, 0x604)), None);
        // The PM1a control pair and the 8042 ports: no service but acpid
        // drives the ACPI sleep and reset registers, and nothing holds the
        // 8042.
        assert_eq!(refused(io(0x604, 0x606)), None);
        assert_eq!(refused(io(0x60, 0x68)), None);
        assert_eq!(refused(io(0xB2, 0xB3)), None);
        assert_eq!(refused(memory(0xFED0_0000, 0xFED0_1000)), None);
        let refusal = region_refusal(&io(0x6000, 0x6001), devices(), &kernel, facs);
        assert_eq!(refusal.map(|r| r.range), Some(io(0x6000, 0x6020)));
    }

    #[test]
    fn a_resource_containers_range_is_granted_unless_another_holder_refuses_it()
    {
        let keys = |hid: &'static [u8], cids: &'static [&'static [u8]]| RecordKeys {
            pci: None,
            acpi_hid: Some(hid),
            acpi_cids: cids,
            spcr: None,
            platform: None,
            iommu_family: None,
            boot_framebuffer: false,
        };
        let held = |range: Range, record: RecordKeys<'_>| HeldRange {
            range,
            container: container(&record),
        };
        // QEMU q35: the PCI hotplug block (\_SB.PCI0.PHPR) and the CPU
        // hotplug block (\_SB.PCI0.PRES), both PNP0A06; a UART whose own
        // ID sits beside a container _CID; a container over the PIT's ports
        // and one over the configuration ports.
        let devices = [
            held(io(0xCC0, 0xCD8), keys(b"PNP0A06", &[])),
            held(io(0xCD8, 0xCE4), keys(b"PNP0A06", &[])),
            held(io(0x2F8, 0x300), keys(b"PNP0501", &[b"PNP0C02"])),
            held(io(0x40, 0x44), keys(b"PNP0C02", &[])),
            held(io(0xCF8, 0xD00), keys(b"PNP0C02", &[])),
            held(io(0x7000, 0x7100), keys(b"PNP0C02", &[])),
            held(io(0x7080, 0x7090), keys(b"PNP0B00", &[])),
        ];
        let kernel = [io(0x40, 0x44)];
        let refused = |want: Range| region_refusal(&want, devices, &kernel, None).map(|r| r.holder);

        // The firmware's own registers are granted.
        assert_eq!(refused(io(0xCD0, 0xCD8)), None);
        assert_eq!(refused(io(0xCD8, 0xCE4)), None);
        // Mixed keys are a device's: refused through its record.
        assert_eq!(refused(io(0x2F8, 0x300)), Some(Holder::Device));
        // A container's range that another record also holds is refused
        // through that record, and the fixed refusals still win.
        assert_eq!(refused(io(0x7080, 0x7081)), Some(Holder::Device));
        assert_eq!(refused(io(0x7000, 0x7010)), None);
        assert_eq!(refused(io(0x40, 0x44)), Some(Holder::Kernel));
        assert_eq!(refused(io(0xCF8, 0xD00)), Some(Holder::ConfigMechanism));
    }

    #[test]
    fn a_memory_request_is_one_page_and_a_port_request_its_whole_region()
    {
        assert_eq!(
            request_range(Space::Memory, 0xFED0_1FFC, 4),
            Some(memory(0xFED0_1000, 0xFED0_2000))
        );
        assert_eq!(request_range(Space::Memory, 0xFED0_1FFE, 4), None);
        assert_eq!(request_range(Space::Memory, 0xFED0_0000, 0x2000), None);
        assert_eq!(
            request_range(Space::Io, 0x600, 0x40),
            Some(io(0x600, 0x640))
        );
        assert_eq!(request_range(Space::Memory, 0x1000, 0), None);
    }

    #[test]
    fn a_kept_grant_answers_every_range_inside_it()
    {
        let mut grants = Grants::new();
        assert_eq!(grants.within(&memory(0x1000, 0x2000)), None);
        assert_eq!(grants.keep(memory(0x1000, 0x3000), 7u64), Ok(()));
        assert_eq!(
            grants.within(&memory(0x2000, 0x3000)),
            Some((memory(0x1000, 0x3000), 7))
        );
        assert_eq!(grants.within(&memory(0x2000, 0x4000)), None);
        assert_eq!(grants.within(&io(0x1000, 0x2000)), None);
    }

    #[test]
    fn a_read_is_made_of_a_recorded_function_and_a_write_only_past_the_header_of_an_unbound_one()
    {
        use ConfigAccess::{Access, AllOnes};
        use ConfigError::{Invalid, Refused};
        use ConfigOp::{Read, Write};
        use RecordState::{Bound, Removed, Unbound};
        assert_eq!(config_access(Read, 0, 4, Some(Bound)), Ok(Access));
        assert_eq!(config_access(Read, 0x3E, 2, Some(Unbound)), Ok(Access));
        assert_eq!(config_access(Read, 0, 2, None), Ok(AllOnes));
        assert_eq!(config_access(Read, 0, 1, Some(Removed)), Ok(AllOnes));
        assert_eq!(config_access(Write, 0x40, 4, Some(Unbound)), Ok(Access));
        assert_eq!(config_access(Write, 0xFFF, 1, Some(Unbound)), Ok(Access));
        assert_eq!(config_access(Write, 0x3C, 4, Some(Unbound)), Err(Refused));
        assert_eq!(config_access(Write, 0x40, 4, Some(Bound)), Err(Refused));
        assert_eq!(config_access(Write, 0x40, 4, Some(Removed)), Err(Refused));
        assert_eq!(config_access(Write, 0x40, 4, None), Err(Refused));
        assert_eq!(config_access(Read, 0x41, 2, Some(Bound)), Err(Invalid));
        assert_eq!(config_access(Read, 0x40, 3, Some(Bound)), Err(Invalid));
        assert_eq!(config_access(Read, 0x1000, 1, Some(Bound)), Err(Invalid));
        assert_eq!(
            config_access(Write, u64::MAX - 3, 4, Some(Unbound)),
            Err(Invalid)
        );
        assert_eq!(
            (all_ones(1), all_ones(2), all_ones(4)),
            (0xFF, 0xFFFF, 0xFFFF_FFFF)
        );
    }

    #[test]
    fn each_request_carries_every_word_of_its_layout()
    {
        use ipc::devmgr_labels as labels;
        assert_eq!(request_words(labels::ACPI_REGION_GRANT, 0), Some(4));
        assert_eq!(request_words(labels::ACPI_PCI_CONFIG, 0), Some(6));
        assert_eq!(request_words(labels::OSC_RESULT, 1), Some(7));
        assert_eq!(request_words(labels::BRIDGE_WINDOWS, 0), Some(4));
        assert_eq!(request_words(labels::BRIDGE_WINDOWS, 3), Some(13));
        assert_eq!(
            request_words(labels::BRIDGE_WINDOWS, u64::MAX),
            Some(4 + 3 * labels::MAX_BRIDGE_WINDOWS)
        );
        assert_eq!(request_words(labels::PRT_TABLE, 0), Some(36));
        assert_eq!(request_words(labels::ACPI_HOTPLUG, 0), Some(3));
        assert_eq!(request_words(labels::QUERY_HOST_BRIDGE, 0), None);
    }

    #[test]
    fn pushes_decode_from_their_words()
    {
        let words = [
            WINDOW_BUS,
            0,
            0x100,
            WINDOW_IO,
            0x6000,
            0xA000,
            WINDOW_MEMORY,
            0x8000_0000,
            0,
        ];
        assert_eq!(
            windows_from_words(&words),
            Some(vec![
                window(WindowKind::Bus, 0, 0x100),
                window(WindowKind::Io, 0x6000, 0x1_0000)
            ])
        );
        assert_eq!(windows_from_words(&[3, 0, 1]), None);
        assert_eq!(windows_from_words(&[WINDOW_IO, 0, 1, WINDOW_IO]), None);
        assert_eq!(windows_from_words(&[WINDOW_MEMORY, u64::MAX, 2]), None);

        let mut words = [PRT_NO_ROUTE * 0x0001_0001_0001_0001; PRT_DEVICES];
        words[2] = 0x000B_000B_000A_000A;
        let table = prt_from_words(&words);
        assert_eq!(table.map(|t| t[2]), Some([0x0A, 0x0A, 0x0B, 0x0B]));
        assert_eq!(table.map(|t| t[3]), Some([0xFFFF; 4]));
        assert_eq!(prt_from_words(&words[1..]), None);
    }

    #[test]
    fn windows_pass_when_every_bar_on_the_buses_lies_in_a_window_and_an_aperture()
    {
        let functions = [
            function((0, 0, 0, 0), 0),
            with_bar(
                with_bar(
                    function((0, 0, 2, 0), 1),
                    0x8100_0000,
                    0x1000,
                    Space::Memory,
                ),
                0x6000,
                0x20,
                Space::Io,
            ),
            with_bar(
                function((0, 1, 0, 0), 1),
                0x38_0000_0000,
                0x4000,
                Space::Memory,
            ),
            // Unassigned, and on another segment: not checked.
            with_bar(function((0, 1, 1, 0), 0), 0, 0x1000, Space::Memory),
            with_bar(function((1, 0, 3, 0), 0), 0x10, 0x10, Space::Memory),
        ];
        let check = |windows: &[Window]| check_windows(0, 0, windows, functions.iter(), &APERTURES);
        assert_eq!(check(&q35_windows()), Ok(4));

        let mut windows = q35_windows();
        windows.retain(|w| w.base != 0x38_0000_0000);
        let bar = memory(0x38_0000_0000, 0x38_0000_4000);
        assert_eq!(
            check(&windows),
            Err(Disagreement::MemoryWindow {
                function: (0, 1, 0, 0),
                bar
            })
        );

        let mut windows = q35_windows();
        windows.retain(|w| w.kind != WindowKind::Io);
        let bar = io(0x6000, 0x6020);
        assert_eq!(
            check(&windows),
            Err(Disagreement::IoWindow {
                function: (0, 0, 2, 0),
                bar
            })
        );

        let high = [APERTURES[0]];
        let bar = memory(0x38_0000_0000, 0x38_0000_4000);
        assert_eq!(
            check_windows(0, 0, &q35_windows(), functions.iter(), &high),
            Err(Disagreement::Aperture {
                function: (0, 1, 0, 0),
                bar
            })
        );

        // Buses 0-0: the function on bus 1 is off the bridge.
        let mut windows = q35_windows();
        windows[0] = window(WindowKind::Bus, 0, 1);
        assert_eq!(check(&windows), Ok(2));
        // No bus window, two, one without the bridge's bus, one past 255.
        assert_eq!(check(&windows[1..]), Err(Disagreement::BusRange));
        windows.push(window(WindowKind::Bus, 0x80, 0x81));
        assert_eq!(check(&windows), Err(Disagreement::BusRange));
        assert_eq!(
            check(&[window(WindowKind::Bus, 1, 2)]),
            Err(Disagreement::BusRange)
        );
        assert_eq!(
            check(&[window(WindowKind::Bus, 0, 0x101)]),
            Err(Disagreement::BusRange)
        );
    }

    /// x86-64's rules: the PIC-mode table checked against each function's
    /// line, the routes kept only after it and only routed.
    const PIC: PrtRule = PrtRule {
        after: None,
        lines: true,
    };
    const APIC: PrtRule = PrtRule {
        after: Some(PrtMode::PicMode),
        lines: false,
    };

    fn table(routes: &[(usize, usize, u16)]) -> PrtTable
    {
        let mut table = [[0xFFFF; 4]; PRT_DEVICES];
        for &(dev, pin, line) in routes
        {
            table[dev][pin - 1] = line;
        }
        table
    }

    #[test]
    fn a_routes_table_is_kept_only_after_the_pic_table_that_agrees_with_the_lines()
    {
        let mut nic = function((0, 0, 2, 0), 1);
        nic.irq_line = 10;
        let mut disk = function((0, 0, 3, 0), 2);
        disk.irq_line = 11;
        let functions = [function((0, 0, 0, 0), 0), nic, disk];
        let line = |f: &PciDevice| Some(u32::from(f.irq_line));
        let pic = table(&[(2, 1, 10), (3, 2, 11)]);
        let apic = table(&[(2, 1, 16), (3, 2, 21)]);
        let mut bridges = Bridges::new();
        // Before the windows, no table is taken.
        assert_eq!(
            bridges.push_prt(0, 0, PrtMode::PicMode, &pic, PIC, functions.iter(), line),
            Some(Push::Refused(Disagreement::Order))
        );
        let windows = vec![window(WindowKind::Bus, 0, 0x100)];
        assert_eq!(
            bridges.push_windows(0, 0, windows, functions.iter(), &APERTURES),
            Some(Push::Kept)
        );
        let mut push = |mode, table: &PrtTable, rule| {
            bridges.push_prt(0, 0, mode, table, rule, functions.iter(), line)
        };

        assert_eq!(
            push(PrtMode::Routes, &apic, APIC),
            Some(Push::Refused(Disagreement::Order))
        );
        let wrong = table(&[(2, 1, 10), (3, 2, 10)]);
        assert_eq!(
            push(PrtMode::PicMode, &wrong, PIC),
            Some(Push::Refused(Disagreement::Line {
                function: (0, 0, 3, 0),
                line: 10,
                expected: 11
            }))
        );
        let short = table(&[(2, 1, 10)]);
        assert_eq!(
            push(PrtMode::PicMode, &short, PIC),
            Some(Push::Refused(Disagreement::Unrouted {
                function: (0, 0, 3, 0),
                dev: 3,
                pin: 2
            }))
        );
        assert_eq!(push(PrtMode::PicMode, &pic, PIC), Some(Push::Kept));
        assert_eq!(push(PrtMode::PicMode, &pic, PIC), Some(Push::Same));
        assert_eq!(push(PrtMode::PicMode, &wrong, PIC), Some(Push::Differs));
        assert_eq!(
            push(PrtMode::Routes, &short, APIC),
            Some(Push::Refused(Disagreement::Unrouted {
                function: (0, 0, 3, 0),
                dev: 3,
                pin: 2
            }))
        );
        assert_eq!(push(PrtMode::Routes, &apic, APIC), Some(Push::Kept));
        let bridge = bridges.get(0);
        assert_eq!(
            bridge
                .and_then(|b| b.pic.as_ref())
                .map(|h| (h.value, h.covered)),
            Some((pic, 2))
        );
        assert_eq!(
            bridge
                .and_then(|b| b.routes.as_ref())
                .map(|h| (h.value, h.covered)),
            Some((apic, 2))
        );
    }

    #[test]
    fn a_function_behind_a_bridge_is_checked_on_the_root_bus_pin_and_device_it_reaches()
    {
        // A function at device 0, pin INTA, on bus 1 behind the root port at
        // device 4: its interrupt reaches the root bus as INTA of device 4.
        let mut leaf = function((0, 1, 0, 0), 1);
        leaf.host_intx = Some((1, 4));
        let functions = [leaf];
        let swizzle = |f: &PciDevice| {
            f.host_intx
                .map(|(pin, dev)| 32 + (u32::from(pin) - 1 + u32::from(dev)) % 4)
        };
        let riscv = PrtRule {
            after: None,
            lines: true,
        };
        let routes = table(&[(4, 1, 32)]);
        let mut bridges = Bridges::new();
        // With no windows held, devmgr does not know the bridge's buses, and
        // takes no table.
        assert_eq!(
            bridges.push_prt(
                0,
                0,
                PrtMode::Routes,
                &routes,
                riscv,
                functions.iter(),
                swizzle
            ),
            Some(Push::Refused(Disagreement::Order))
        );

        let windows = vec![window(WindowKind::Bus, 0, 0x100)];
        assert_eq!(
            bridges.push_windows(0, 0, windows, functions.iter(), &APERTURES),
            Some(Push::Kept)
        );
        assert_eq!(
            bridges.push_prt(
                0,
                0,
                PrtMode::Routes,
                &table(&[(4, 1, 33)]),
                riscv,
                functions.iter(),
                swizzle
            ),
            Some(Push::Refused(Disagreement::Line {
                function: (0, 1, 0, 0),
                line: 33,
                expected: 32
            }))
        );
        assert_eq!(
            bridges.push_prt(
                0,
                0,
                PrtMode::Routes,
                &routes,
                riscv,
                functions.iter(),
                swizzle
            ),
            Some(Push::Kept)
        );
        assert_eq!(
            bridges
                .get(0)
                .and_then(|b| b.routes.as_ref())
                .map(|h| h.covered),
            Some(1)
        );
    }

    #[test]
    fn a_function_takes_the_line_the_held_table_routes_its_root_bus_pin_and_device_to()
    {
        // The root port at device 4, its line programmed, and a function on
        // bus 1 behind it, its line not: its INTB reaches the root bus as
        // INTB of device 4.
        let mut port = function((0, 0, 4, 0), 1);
        port.irq_line = 10;
        let mut leaf = function((0, 1, 0, 0), 2);
        leaf.host_intx = Some((2, 4));
        let functions = [port, leaf];
        let mut unrouted = function((0, 1, 1, 0), 3);
        unrouted.host_intx = Some((3, 4));
        let mut elsewhere = function((1, 1, 0, 0), 2);
        elsewhere.host_intx = Some((2, 4));
        let no_pin = function((0, 1, 2, 0), 0);
        let programmed = |f: &PciDevice| (f.irq_line != 0).then(|| u32::from(f.irq_line));
        let pic = table(&[(4, 1, 10), (4, 2, 11)]);
        let mut bridges = Bridges::new();
        assert_eq!(bridges.line(PrtMode::PicMode, &leaf), None);

        let windows = vec![window(WindowKind::Bus, 0, 0x100)];
        assert_eq!(
            bridges.push_windows(0, 0, windows, functions.iter(), &APERTURES),
            Some(Push::Kept)
        );
        // Windows alone: no table to route by.
        assert_eq!(bridges.line(PrtMode::PicMode, &leaf), None);
        assert_eq!(
            bridges.push_prt(
                0,
                0,
                PrtMode::PicMode,
                &pic,
                PIC,
                functions.iter(),
                programmed
            ),
            Some(Push::Kept)
        );
        assert_eq!(bridges.line(PrtMode::PicMode, &leaf), Some(11));
        assert_eq!(bridges.line(PrtMode::PicMode, &port), Some(10));
        // No table of the other mode; a pin the table leaves unrouted; a
        // segment no bridge holds; no pin at all.
        assert_eq!(bridges.line(PrtMode::Routes, &leaf), None);
        assert_eq!(bridges.line(PrtMode::PicMode, &unrouted), None);
        assert_eq!(bridges.line(PrtMode::PicMode, &elsewhere), None);
        assert_eq!(bridges.line(PrtMode::PicMode, &no_pin), None);
    }

    #[test]
    fn the_first_result_of_each_bridge_is_kept_and_bridges_are_listed_in_address_order()
    {
        let granted = Osc {
            evaluated: true,
            status: 0,
            control: 0x1E,
        };
        let fewer = Osc {
            control: 0x0E,
            ..granted
        };
        let mut bridges = Bridges::new();
        assert_eq!(bridges.push_osc(0, 0x80, granted), Some(Push::Kept));
        assert_eq!(bridges.push_osc(0, 0, granted), Some(Push::Kept));
        assert_eq!(bridges.push_osc(0, 0, granted), Some(Push::Same));
        assert_eq!(bridges.push_osc(0, 0, fewer), Some(Push::Differs));
        assert_eq!(
            bridges.get(0).map(|b| (b.bus, b.osc)),
            Some((0, Some(granted)))
        );
        assert_eq!(bridges.get(1).map(|b| b.bus), Some(0x80));
        assert!(bridges.get(2).is_none());

        let none: [PciDevice; 0] = [];
        assert_eq!(
            bridges.push_windows(0, 0, q35_windows(), none.iter(), &APERTURES),
            Some(Push::Kept)
        );
        assert_eq!(
            bridges.push_windows(0, 0, q35_windows(), none.iter(), &APERTURES),
            Some(Push::Same)
        );
        assert_eq!(
            bridges.push_windows(0, 0, q35_windows()[..2].to_vec(), none.iter(), &APERTURES),
            Some(Push::Differs)
        );
        assert_eq!(
            bridges
                .get(0)
                .and_then(|b| b.windows.as_ref())
                .map(|h| h.value.len()),
            Some(4)
        );
        // A refused push holds nothing: the bridge at 0x80 has no windows.
        let below = vec![window(WindowKind::Bus, 0, 0x80)];
        assert_eq!(
            bridges.push_windows(0, 0x80, below, none.iter(), &APERTURES),
            Some(Push::Refused(Disagreement::BusRange))
        );
        assert!(
            bridges
                .get(1)
                .is_some_and(|b| b.windows.is_none() && b.buses().is_none())
        );
    }
}
