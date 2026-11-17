// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/devmgr/firmware/src/hotplug.rs

//! PCI Express native hotplug: the slots devmgr can manage, the memory
//! windows a slot's hot-added functions take their BARs from, the
//! native-control grant, the BAR assignment, the admission of a hot-added
//! function's record, and the decision the slot poller makes on each Slot
//! Status reading. The procedure is specified in
//! [hotplug.md](../../docs/hotplug.md).
//!
//! Register offsets and bits are those of the PCI Express capability (PCI
//! Express Base Specification r4.0 § 7.5.3) and of the type-1 configuration
//! header (PCI-to-PCI Bridge Architecture Specification r1.2 § 3.2).

extern crate alloc;

use alloc::collections::TryReserveError;
use alloc::vec::Vec;

use crate::acpid::{Address, Bridge, Bridges, Osc, address};
use crate::pci::{CAP_ID_PCI_EXPRESS, COMMAND, COMMAND_MEMORY, STATUS, find_capability};
use crate::pci_records::{AppendError, PciRecords, RecordState};
use crate::scan::{ConfigSpace, MAX_BARS, PciDevice};

/// Offset of the PCI Express Capabilities register in the capability: bits
/// 7:4 the device/port type, bit 8 Slot Implemented.
const PCIE_CAPABILITIES: u16 = 0x02;
/// Device/port type of a Root Port of a Root Complex.
const PORT_ROOT: u16 = 0x4;
/// Device/port type of a switch's Downstream Port.
const PORT_DOWNSTREAM: u16 = 0x6;
/// PCI Express Capabilities: the port is connected to a slot.
const SLOT_IMPLEMENTED: u16 = 1 << 8;
/// Offset of Link Capabilities.
const LINK_CAPABILITIES: u16 = 0x0C;
/// Link Capabilities: Data Link Layer Link Active Reporting Capable.
const LINK_ACTIVE_REPORTING: u32 = 1 << 20;
/// Offset of Link Status.
pub const LINK_STATUS: u16 = 0x12;
/// Link Status: Data Link Layer Link Active.
pub const LINK_ACTIVE: u16 = 1 << 13;
/// Offset of Slot Capabilities.
const SLOT_CAPABILITIES: u16 = 0x14;
/// Slot Capabilities: Attention Button Present.
const SLOTCAP_BUTTON: u32 = 1 << 0;
/// Slot Capabilities: Power Controller Present.
const SLOTCAP_POWER_CONTROLLER: u32 = 1 << 1;
/// Slot Capabilities: Power Indicator Present.
const SLOTCAP_POWER_INDICATOR: u32 = 1 << 4;
/// Slot Capabilities: Hot-Plug Capable.
const SLOTCAP_HOTPLUG_CAPABLE: u32 = 1 << 6;
/// Slot Capabilities: No Command Completed Support.
const SLOTCAP_NO_COMMAND_COMPLETED: u32 = 1 << 18;
/// Offset of Slot Control.
pub const SLOT_CONTROL: u16 = 0x18;
/// Slot Control: the enables of the slot's event interrupts (Attention
/// Button Pressed, Power Fault Detected, MRL Sensor Changed, Presence Detect
/// Changed, Command Completed Interrupt, Hot-Plug Interrupt) and of Data Link
/// Layer State Changed.
pub const SLOTCTL_EVENT_ENABLES: u16 = 0x3F | (1 << 12);
/// Slot Control: the Power Indicator Control field.
const SLOTCTL_POWER_INDICATOR: u16 = 0x3 << 8;
/// Power Indicator Control: on.
const SLOTCTL_POWER_INDICATOR_ON: u16 = 0x1 << 8;
/// Slot Control: Power Controller Control; set, the slot's power is off.
const SLOTCTL_POWER_OFF: u16 = 1 << 10;
/// Offset of Slot Status.
pub const SLOT_STATUS: u16 = 0x1A;
/// Slot Status: Attention Button Pressed (RW1C).
const SLOTSTA_BUTTON: u16 = 1 << 0;
/// Slot Status: Power Fault Detected (RW1C).
const SLOTSTA_POWER_FAULT: u16 = 1 << 1;
/// Slot Status: MRL Sensor Changed (RW1C).
const SLOTSTA_MRL_CHANGED: u16 = 1 << 2;
/// Slot Status: Presence Detect Changed (RW1C).
const SLOTSTA_PRESENCE_CHANGED: u16 = 1 << 3;
/// Slot Status: Command Completed (RW1C).
pub const SLOTSTA_COMMAND_COMPLETED: u16 = 1 << 4;
/// Slot Status: Presence Detect State.
const SLOTSTA_PRESENT: u16 = 1 << 6;
/// Slot Status: Data Link Layer State Changed (RW1C).
const SLOTSTA_LINK_CHANGED: u16 = 1 << 8;
/// The Slot Status event latches the poller reads and clears: every RW1C
/// bit but Command Completed, which only a Slot Control write waits on.
pub const SLOTSTA_LATCHES: u16 = SLOTSTA_BUTTON
    | SLOTSTA_POWER_FAULT
    | SLOTSTA_MRL_CHANGED
    | SLOTSTA_PRESENCE_CHANGED
    | SLOTSTA_LINK_CHANGED;

/// The period of the poll of every managed slot's Slot Status, in
/// milliseconds.
pub const HOTPLUG_POLL_MS: u64 = 1000;
/// The longest wait for a Slot Control command to complete, and for the
/// link of a slot just powered to come up where the port reports it (PCI
/// Express Base Specification r4.0 § 6.7.3.2 and § 6.6.1); the wait after
/// power-on of a port that does not report it. In milliseconds.
pub const SLOT_WAIT_MS: u64 = 1000;
/// The wait after the link comes up before a configuration request goes
/// below the port (§ 6.6.1), in milliseconds.
pub const LINK_SETTLE_MS: u64 = 100;

/// A type-1 header's Memory Base and Memory Limit, its Prefetchable Memory
/// Base and Limit, and the prefetchable window's upper 32 bits.
const MEMORY_BASE: u16 = 0x20;
const MEMORY_LIMIT: u16 = 0x22;
const PREFETCH_BASE: u16 = 0x24;
const PREFETCH_LIMIT: u16 = 0x26;
const PREFETCH_BASE_UPPER: u16 = 0x28;
const PREFETCH_LIMIT_UPPER: u16 = 0x2C;
/// The granule of a bridge's memory windows: 1 MiB.
const WINDOW_GRANULE: u64 = 1 << 20;

/// The `_OSC` control bit of PCI Express native hotplug (PCI Firmware
/// Specification r3.2 § 4.5.1).
pub const OSC_NATIVE_HOTPLUG: u32 = 1 << 0;

/// The offset of a type-0 header's first BAR register.
const BAR0: u16 = 0x10;

/// A memory window `[base, end)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Window
{
    pub base: u64,
    pub end: u64,
}

impl Window
{
    /// Whether the window lies wholly inside one of `apertures`, each
    /// `(base, end)`.
    #[must_use]
    pub fn inside(&self, apertures: &[(u64, u64)]) -> bool
    {
        apertures
            .iter()
            .any(|&(base, end)| base <= self.base && self.end <= end)
    }
}

/// A hotplug slot: a PCI Express Root Port or switch Downstream Port whose
/// PCI Express capability has Slot Implemented and whose Slot Capabilities
/// has Hot-Plug Capable, with the buses and the memory windows the firmware
/// programmed into its type-1 header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Slot
{
    /// The port's address.
    pub port: Address,
    /// The offset of the port's PCI Express capability.
    pub express: u16,
    /// The port's Slot Capabilities.
    pub capabilities: u32,
    /// Whether the port reports Data Link Layer Link Active.
    pub link_reporting: bool,
    /// The secondary bus, where a hot-added function appears.
    pub secondary: u8,
    /// The subordinate bus: the slot's subtree is buses
    /// `secondary..=subordinate`.
    pub subordinate: u8,
    /// The non-prefetchable memory window; `None` when it is off.
    pub memory: Option<Window>,
    /// The prefetchable memory window; `None` when it is off.
    pub prefetchable: Option<Window>,
}

impl Slot
{
    /// Whether the function at `address` lies in the slot's subtree.
    #[must_use]
    pub fn holds(&self, address: Address) -> bool
    {
        let (segment, bus, _, _) = address;
        segment == self.port.0 && (self.secondary..=self.subordinate).contains(&bus)
    }

    /// The configuration offset of the port's PCI Express register at
    /// `register` ([`SLOT_CONTROL`], [`SLOT_STATUS`], [`LINK_STATUS`]).
    #[must_use]
    pub const fn register(&self, register: u16) -> u16
    {
        self.express.wrapping_add(register)
    }

    /// Whether the slot has a power controller.
    #[must_use]
    pub const fn power_controller(&self) -> bool
    {
        self.capabilities & SLOTCAP_POWER_CONTROLLER != 0
    }

    /// Whether the slot has an attention button.
    #[must_use]
    pub const fn button(&self) -> bool
    {
        self.capabilities & SLOTCAP_BUTTON != 0
    }

    /// Whether a Slot Control write is followed by Command Completed.
    #[must_use]
    pub const fn command_completion(&self) -> bool
    {
        self.capabilities & SLOTCAP_NO_COMMAND_COMPLETED == 0
    }
}

/// The hotplug slot `port` leads to, read through `cfg`: `None` for a
/// function that is no type-1 PCI Express Root Port or Downstream Port with
/// Slot Implemented and Hot-Plug Capable, or whose secondary bus is not above
/// its own (an unconfigured bridge).
#[must_use]
pub fn read_slot(cfg: &impl ConfigSpace, port: &PciDevice) -> Option<Slot>
{
    let (secondary, subordinate) = port.bridge_buses?;
    if secondary <= port.bus || subordinate < secondary
    {
        return None;
    }
    let (b, d, f) = (port.bus, port.dev, port.func);
    let status = cfg.read16(b, d, f, STATUS);
    let express = find_capability(status, CAP_ID_PCI_EXPRESS, |at| cfg.read8(b, d, f, at))?;
    let flags = cfg.read16(b, d, f, express.wrapping_add(PCIE_CAPABILITIES));
    let port_type = (flags >> 4) & 0xF;
    if flags == u16::MAX
        || flags & SLOT_IMPLEMENTED == 0
        || !matches!(port_type, PORT_ROOT | PORT_DOWNSTREAM)
    {
        return None;
    }
    let capabilities = cfg.read32(b, d, f, express.wrapping_add(SLOT_CAPABILITIES));
    if capabilities == u32::MAX || capabilities & SLOTCAP_HOTPLUG_CAPABLE == 0
    {
        return None;
    }
    let link = cfg.read32(b, d, f, express.wrapping_add(LINK_CAPABILITIES));
    Some(Slot {
        port: crate::acpid::address(port),
        express,
        capabilities,
        link_reporting: link != u32::MAX && link & LINK_ACTIVE_REPORTING != 0,
        secondary,
        subordinate,
        memory: memory_window(
            cfg.read16(b, d, f, MEMORY_BASE),
            cfg.read16(b, d, f, MEMORY_LIMIT),
        ),
        prefetchable: prefetchable_window(
            cfg.read16(b, d, f, PREFETCH_BASE),
            cfg.read16(b, d, f, PREFETCH_LIMIT),
            cfg.read32(b, d, f, PREFETCH_BASE_UPPER),
            cfg.read32(b, d, f, PREFETCH_LIMIT_UPPER),
        ),
    })
}

/// Append to `out` the hotplug slot of each of `functions` that leads to
/// one ([`read_slot`]), in their order.
///
/// # Errors
/// `TryReserveError` when `out` cannot grow; it then holds the slots found
/// before.
pub fn slots(
    cfg: &impl ConfigSpace,
    functions: &[PciDevice],
    out: &mut Vec<Slot>,
) -> Result<(), TryReserveError>
{
    for slot in functions.iter().filter_map(|f| read_slot(cfg, f))
    {
        out.try_reserve(1)?;
        out.push(slot);
    }
    Ok(())
}

/// The non-prefetchable window of a type-1 header whose Memory Base and
/// Memory Limit read `base` and `limit`: bits 15:4 of each are address bits
/// 31:20, the limit's low 20 bits all ones. `None` when the limit lies below
/// the base, which turns the window off.
#[must_use]
pub fn memory_window(base: u16, limit: u16) -> Option<Window>
{
    let start = u64::from(base & 0xFFF0) << 16;
    let end = (u64::from(limit & 0xFFF0) << 16).saturating_add(WINDOW_GRANULE);
    (end > start).then_some(Window { base: start, end })
}

/// The prefetchable window of a type-1 header: as [`memory_window`], with
/// address bits 63:32 from the upper registers when the base's low nibble
/// reads 1 (64-bit addressing).
#[must_use]
pub fn prefetchable_window(
    base: u16,
    limit: u16,
    base_upper: u32,
    limit_upper: u32,
) -> Option<Window>
{
    let (upper_base, upper_limit) = if base & 0xF == 0x1
    {
        (u64::from(base_upper) << 32, u64::from(limit_upper) << 32)
    }
    else
    {
        (0, 0)
    };
    let start = upper_base | (u64::from(base & 0xFFF0) << 16);
    let end = (upper_limit | (u64::from(limit & 0xFFF0) << 16)).checked_add(WINDOW_GRANULE)?;
    (end > start).then_some(Window { base: start, end })
}

/// Whether the `_OSC` result `osc` grants native PCI Express hotplug
/// control: it was evaluated and its control dword has the native hotplug
/// bit.
#[must_use]
pub const fn osc_grants(osc: Option<Osc>) -> bool
{
    match osc
    {
        Some(o) => o.evaluated && o.control & OSC_NATIVE_HOTPLUG != 0,
        None => false,
    }
}

/// The native-control grant of a slot: the `_OSC` result `osc` of its host
/// bridge grants native hotplug control, or the machine's platform
/// description table does (`platform_grant`, its `pcie_native_hotplug = yes`).
/// With neither, devmgr does not manage the slot.
#[must_use]
#[expect(
    clippy::fn_params_excessive_bools,
    reason = "`platform_grant` is the platform description table's `pcie_native_hotplug` value"
)]
pub const fn native_control(osc: Option<Osc>, platform_grant: bool) -> bool
{
    platform_grant || osc_grants(osc)
}

/// The host bridge bus `bus` of `segment` lies below: the one whose bus
/// window holds the bus, else, when no bridge's bus window does, the one
/// whose root bus it is.
#[must_use]
pub fn host_bridge(bridges: &Bridges, segment: u16, bus: u8) -> Option<&Bridge>
{
    let on_segment = || bridges.iter().filter(move |b| b.segment == segment);
    on_segment()
        .find(|b| {
            b.buses()
                .is_some_and(|(first, last)| (first..=last).contains(&bus))
        })
        .or_else(|| on_segment().find(|b| b.bus == bus))
}

/// One MMIO BAR of a hot-added function to place.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BarRequest
{
    /// The BAR register index, 0 to 5.
    pub register: u8,
    /// The BAR's size.
    pub size: u64,
    /// A 64-bit BAR, which takes two registers.
    pub wide: bool,
    pub prefetchable: bool,
}

/// The MMIO BARs of `device` to place: each MMIO BAR its scan sized, typed by
/// its register's type bits, which `read32` reads at a configuration offset.
/// I/O BARs are not placed.
#[must_use]
pub fn bar_requests(
    device: &PciDevice,
    read32: impl Fn(u16) -> u32,
) -> [Option<BarRequest>; MAX_BARS]
{
    let mut requests = [None; MAX_BARS];
    let sized = device
        .bar_pci_idx
        .iter()
        .zip(&device.bar_size)
        .zip(&device.bar_is_mmio)
        .take(device.bar_count)
        .filter(|(_, mmio)| **mmio);
    for (out, ((&register, &size), _)) in requests.iter_mut().zip(sized)
    {
        let flags = read32(bar_offset(register));
        *out = Some(BarRequest {
            register,
            size,
            wide: (flags >> 1) & 0x3 == 0x2,
            prefetchable: flags & (1 << 3) != 0,
        });
    }
    requests
}

/// The configuration offset of BAR register `register`.
fn bar_offset(register: u8) -> u16
{
    BAR0.saturating_add(u16::from(register).saturating_mul(4))
}

/// A placed BAR: its register and its base.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Placed
{
    pub register: u8,
    pub base: u64,
    pub size: u64,
    pub wide: bool,
}

/// Why a function's BARs were not placed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unplaced
{
    /// The BAR's size is not a power of two.
    BadSize(u8),
    /// No window the BAR may go in is open.
    NoWindow(u8),
    /// No free range of the BAR's size, aligned to it, is left in the windows
    /// it may go in.
    NoRoom(u8),
}

/// Place every request of `requests` in a slot's windows: `memory`, the
/// non-prefetchable window, and `prefetchable`, clear of `taken` (each
/// `(base, end)`: the BARs of the live records on the slot's buses) and of
/// each other. Each BAR is aligned to its size, as a BAR's base must be, and
/// to a page, and takes at least a page, which it shares with no other BAR
/// (devmgr carves a BAR's cap in whole pages); the largest is placed first,
/// each at the lowest free base. A 64-bit
/// prefetchable BAR goes in the prefetchable window, or in the
/// non-prefetchable window when it does not fit there (prefetchable memory
/// may be mapped as non-prefetchable); every other BAR goes in the
/// non-prefetchable window, which lies below 4 GiB.
///
/// # Errors
/// [`Unplaced`] for the first BAR that cannot be placed; nothing is placed
/// then.
pub fn assign(
    requests: &[Option<BarRequest>; MAX_BARS],
    memory: Option<Window>,
    prefetchable: Option<Window>,
    taken: &[(u64, u64)],
) -> Result<[Option<Placed>; MAX_BARS], Unplaced>
{
    let mut order: [Option<BarRequest>; MAX_BARS] = *requests;
    // Largest first; equal sizes keep register order. Absent requests last.
    order.sort_unstable_by_key(|r| r.map(|r| (core::cmp::Reverse(r.size), r.register)));
    let absent = order.iter().take_while(|r| r.is_none()).count();
    order.rotate_left(absent);
    let mut placed: [Option<Placed>; MAX_BARS] = [None; MAX_BARS];
    for (at, request) in order.iter().enumerate()
    {
        let Some(request) = *request
        else
        {
            continue;
        };
        if !request.size.is_power_of_two()
        {
            return Err(Unplaced::BadSize(request.register));
        }
        let windows: [Option<Window>; 2] = if request.wide && request.prefetchable
        {
            [prefetchable, memory]
        }
        else
        {
            [memory, None]
        };
        if windows.iter().all(Option::is_none)
        {
            return Err(Unplaced::NoWindow(request.register));
        }
        let earlier = placed.get(..at).unwrap_or(&[]);
        let base = windows
            .iter()
            .flatten()
            .find_map(|w| lowest_free(*w, request.size, taken, earlier))
            .ok_or(Unplaced::NoRoom(request.register))?;
        if let Some(out) = placed.get_mut(at)
        {
            *out = Some(Placed {
                register: request.register,
                base,
                size: request.size,
                wide: request.wide,
            });
        }
    }
    Ok(placed)
}

/// The page devmgr carves a BAR's `Mmio` cap at: a carve covers whole pages
/// (`SYS_MMIO_SPLIT` splits at a page-aligned offset), so no two BARs it
/// places share a page.
const PAGE: u64 = 0x1000;

/// The span a BAR of `size` bytes takes in a window: its size, and at least
/// one page.
const fn span(size: u64) -> u64
{
    if size < PAGE { PAGE } else { size }
}

/// The lowest base in `window`, aligned to the BAR's span ([`span`] of
/// `size`), whose span overlaps neither the pages of `taken` nor the span
/// of a BAR of `placed`.
fn lowest_free(
    window: Window,
    size: u64,
    taken: &[(u64, u64)],
    placed: &[Option<Placed>],
) -> Option<u64>
{
    let size = span(size);
    let taken = taken.iter().map(|&(b, e)| {
        (
            b & !(PAGE - 1),
            e.checked_next_multiple_of(PAGE).unwrap_or(u64::MAX),
        )
    });
    let placed = placed
        .iter()
        .flatten()
        .map(|p| (p.base, p.base.saturating_add(span(p.size))));
    let mut base = window.base.checked_next_multiple_of(size)?;
    loop
    {
        let end = base.checked_add(size)?;
        if end > window.end
        {
            return None;
        }
        let clash = taken
            .clone()
            .chain(placed.clone())
            .filter(|&(b, e)| b < end && base < e)
            .map(|(_, e)| e)
            .max();
        match clash
        {
            None => return Some(base),
            Some(clash_end) => base = clash_end.checked_next_multiple_of(size)?,
        }
    }
}

/// Write the BARs of `placed` into the function at `bus:dev.func`, its
/// Memory Space decode off while they change and restored after, so the
/// function never decodes a half-written base.
pub fn program_bars(
    cfg: &impl ConfigSpace,
    (bus, dev, func): (u8, u8, u8),
    placed: &[Option<Placed>; MAX_BARS],
)
{
    let command = cfg.read16(bus, dev, func, COMMAND);
    let decoding = command & COMMAND_MEMORY != 0;
    if decoding
    {
        cfg.write16(bus, dev, func, COMMAND, command & !COMMAND_MEMORY);
    }
    for p in placed.iter().flatten()
    {
        let [lo0, lo1, lo2, lo3, hi0, hi1, hi2, hi3] = p.base.to_le_bytes();
        let at = bar_offset(p.register);
        cfg.write32(bus, dev, func, at, u32::from_le_bytes([lo0, lo1, lo2, lo3]));
        if p.wide
        {
            cfg.write32(
                bus,
                dev,
                func,
                at.saturating_add(4),
                u32::from_le_bytes([hi0, hi1, hi2, hi3]),
            );
        }
    }
    if decoding
    {
        cfg.write16(bus, dev, func, COMMAND, command);
    }
}

/// Whether the scan of a function whose BARs were programmed (`device`) reads
/// each BAR of `placed` at its placed base.
#[must_use]
pub fn placed_match(device: &PciDevice, placed: &[Option<Placed>; MAX_BARS]) -> bool
{
    placed.iter().flatten().all(|p| {
        device
            .bar_pci_idx
            .iter()
            .zip(&device.bar_phys)
            .take(device.bar_count)
            .any(|(&register, &phys)| register == p.register && phys == p.base)
    })
}

/// What the add job found at one function of a slot's secondary bus
/// ([`place`]).
#[derive(Clone, Copy)]
pub enum Found
{
    /// No function answers there.
    Absent,
    /// The function, its BARs placed, programmed and read back; a type-1
    /// function as read, its BARs untouched.
    Ready(PciDevice),
    /// Its BARs do not fit the slot's windows; none was written.
    Unplaced(PciDevice, Unplaced),
    /// Its BARs did not read back as programmed.
    NotProgrammed(PciDevice),
}

/// Read the function at `bus:dev.func` of the slot `slot` through `cfg`,
/// place its MMIO BARs in the slot's windows clear of `taken` ([`assign`]),
/// program them ([`program_bars`]), and read it again for its record. A
/// type-1 function is returned as read, for [`admit`] to refuse.
pub fn place(
    cfg: &impl ConfigSpace,
    slot: &Slot,
    (bus, dev, func): (u8, u8, u8),
    taken: &[(u64, u64)],
) -> Found
{
    let segment = slot.port.0;
    let Some(device) = crate::scan::function(cfg, segment, bus, dev, func)
    else
    {
        return Found::Absent;
    };
    if device.bridge_buses.is_some()
    {
        return Found::Ready(device);
    }
    let requests = bar_requests(&device, |at| cfg.read32(bus, dev, func, at));
    let placed = match assign(&requests, slot.memory, slot.prefetchable, taken)
    {
        Ok(placed) => placed,
        Err(why) => return Found::Unplaced(device, why),
    };
    program_bars(cfg, (bus, dev, func), &placed);
    match crate::scan::function(cfg, segment, bus, dev, func)
    {
        Some(programmed) if placed_match(&programmed, &placed) => Found::Ready(programmed),
        _ => Found::NotProgrammed(device),
    }
}

/// What the add job did with one function found on a slot's secondary bus.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admission
{
    /// A type-1 function: a hot-added switch or bridge, not descended into
    /// and not recorded.
    Bridge,
    /// The function's record was appended at this index.
    Appended(usize),
    /// The records refused it; they are as they were.
    Refused(AppendError),
}

/// Hold the live record of a managed slot's port, `port`, as devmgr's own:
/// the poller writes the port's Slot Control and Slot Status, which lie past
/// the configuration header, so no pass binds the port and acpid is refused
/// every configuration write to it ([`crate::acpid::config_access`]).
/// Returns whether an unbound record was marked; a port a driver holds stays
/// as it is.
pub fn hold_port(records: &mut PciRecords, port: Address) -> bool
{
    let index =
        records.devices().iter().enumerate().position(|(i, d)| {
            address(d) == port && records.state(i) != Some(RecordState::Removed)
        });
    index.is_some_and(|i| records.mark_bound(i))
}

/// Admit the function `device`, its BARs programmed: a type-1 function is not
/// recorded; any other is appended through `append` (the records'
/// `PciRecords::append`).
pub fn admit(
    device: PciDevice,
    append: impl FnOnce(PciDevice) -> Result<usize, AppendError>,
) -> Admission
{
    if device.bridge_buses.is_some()
    {
        return Admission::Bridge;
    }
    match append(device)
    {
        Ok(index) => Admission::Appended(index),
        Err(e) => Admission::Refused(e),
    }
}

/// Why the records refused a hot-added function, as devmgr logs it.
#[must_use]
pub const fn refusal(error: AppendError) -> &'static str
{
    match error
    {
        AppendError::Present => "a live record already holds its address",
        AppendError::NoMemory => "no memory to grow the device records",
    }
}

/// Where the poller holds a managed slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlotState
{
    /// No function behind the slot is recorded or being added.
    Empty,
    /// The functions behind the slot are recorded, or their add job is
    /// posted.
    Occupied,
    /// An arrival failed to bring the slot's link up; the slot waits for the
    /// card's removal before it is tried again.
    Failed,
    /// The card of an occupied slot is gone, or its attention button was
    /// pressed, and the removal was reported once; the slot is occupied
    /// again once its card is present with the button not pressed.
    Departed,
}

/// What the poller does after reading a slot's Slot Status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action
{
    None,
    /// A card is present in an empty slot: power the slot on, wait for its
    /// link, and post its add job. The slot is then occupied, or failed when
    /// the link does not come up.
    PowerUp,
    /// The card of an occupied slot is gone, or its attention button was
    /// pressed: the removal path, which devmgr does not run; the event is
    /// logged.
    Removal,
}

/// The poller's decision for a slot in `state` whose Slot Status reads
/// `status`, with the state it holds the slot in after any action but
/// [`Action::PowerUp`]. A status of all ones, from a port that does not
/// answer, changes nothing.
#[must_use]
pub const fn next(state: SlotState, status: u16) -> (SlotState, Action)
{
    if status == u16::MAX
    {
        return (state, Action::None);
    }
    let present = status & SLOTSTA_PRESENT != 0;
    match state
    {
        SlotState::Empty if present => (SlotState::Empty, Action::PowerUp),
        SlotState::Occupied if !present || status & SLOTSTA_BUTTON != 0 =>
        {
            (SlotState::Departed, Action::Removal)
        }
        SlotState::Failed if !present => (SlotState::Empty, Action::None),
        SlotState::Departed if present && status & SLOTSTA_BUTTON == 0 =>
        {
            (SlotState::Occupied, Action::None)
        }
        SlotState::Empty | SlotState::Occupied | SlotState::Failed | SlotState::Departed =>
        {
            (state, Action::None)
        }
    }
}

/// The state a slot is taken over in: occupied when a card is present and a
/// live record lies behind the slot (`recorded`), else empty, so a present
/// card with nothing recorded is brought up on the first poll.
#[must_use]
#[expect(
    clippy::fn_params_excessive_bools,
    reason = "`recorded` is whether a live record lies behind the slot"
)]
pub const fn initial(status: u16, recorded: bool) -> SlotState
{
    if status != u16::MAX && status & SLOTSTA_PRESENT != 0 && recorded
    {
        SlotState::Occupied
    }
    else
    {
        SlotState::Empty
    }
}

/// The Slot Control value `control` with the slot's power on where the slot
/// has a power controller, and its power indicator on where it has one.
#[must_use]
pub const fn power_on(control: u16, capabilities: u32) -> u16
{
    let mut value = control;
    if capabilities & SLOTCAP_POWER_CONTROLLER != 0
    {
        value &= !SLOTCTL_POWER_OFF;
    }
    if capabilities & SLOTCAP_POWER_INDICATOR != 0
    {
        value = (value & !SLOTCTL_POWER_INDICATOR) | SLOTCTL_POWER_INDICATOR_ON;
    }
    value
}

/// The Slot Control value `control` with the slot's power off where the slot
/// has a power controller, and its power indicator off where it has one.
#[must_use]
pub const fn power_off(control: u16, capabilities: u32) -> u16
{
    let mut value = control;
    if capabilities & SLOTCAP_POWER_CONTROLLER != 0
    {
        value |= SLOTCTL_POWER_OFF;
    }
    if capabilities & SLOTCAP_POWER_INDICATOR != 0
    {
        value |= SLOTCTL_POWER_INDICATOR;
    }
    value
}

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::acpid::Bridges;
    use crate::scan::scan;
    use std::cell::RefCell;
    use std::collections::BTreeMap;

    // Configuration headers captured from QEMU 11.1.3 (QMP `xp` over the ECAM
    // window) once the firmware had programmed the bridges: an empty
    // `pcie-root-port` at 00:03.0 of q35 under OVMF, and two at 00:02.0 (empty)
    // and 00:03.0 (an `edu` behind it) of riscv64 `virt` under edk2
    // RISCV_VIRT. Dwords past each list read 0.
    const Q35_ROOT_PORT: &[u32] = &[
        0x000c_1b36,
        0x0010_0007,
        0x0604_0000,
        0x0001_0000,
        0x8020_1000,
        0x0000_0000,
        0x0001_0100,
        0x0000_00f0,
        0x8010_8000,
        0x0001_fff1,
        0xffff_ffff,
        0x0000_0000,
        0x0000_0000,
        0x0000_0054,
        0x0000_0000,
        0x0000_010b,
        0x0000_000d,
        0x0000_1b36,
        0x0000_4011,
        0x0000_0000,
        0x0000_0800,
        0x0142_4810,
        0x0000_8020,
        0x0000_0000,
        0x0030_0604,
        0x0204_0000,
        0x000a_007b,
        0x0000_07c0,
        0x0000_0000,
        0x0000_0000,
        0x0030_0020,
        0x0000_0000,
        0x0000_001e,
        0x0000_0004,
        0x0000_0000,
        0x0000_0000,
    ];
    const VIRT_EMPTY_PORT: &[u32] = &[
        0x000c_1b36,
        0x0010_0007,
        0x0604_0000,
        0x0001_0000,
        0x4040_1000,
        0x0000_0000,
        0x0001_0100,
        0x0000_00f0,
        0x4030_4020,
        0x0001_fff1,
        0xffff_ffff,
        0x0000_0000,
        0x0000_0000,
        0x0000_0054,
        0x0000_0000,
        0x0000_01ff,
        0x0000_000d,
        0x0000_1b36,
        0x0000_4011,
        0x0000_0000,
        0x0000_0800,
        0x0142_4810,
        0x0000_8020,
        0x0000_0000,
        0x0030_0604,
        0x0204_0000,
        0x000a_007b,
        0x0000_07c0,
        0x0000_0000,
        0x0000_0000,
        0x0030_0020,
        0x0000_0000,
        0x0000_001e,
        0x0000_0004,
        0x0000_0000,
        0x0000_0000,
    ];
    const VIRT_OCCUPIED_PORT: &[u32] = &[
        0x000c_1b36,
        0x0010_0007,
        0x0604_0000,
        0x0001_0000,
        0x4040_0000,
        0x0000_0000,
        0x0002_0200,
        0x0000_00f0,
        0x4010_4000,
        0x0001_fff1,
        0xffff_ffff,
        0x0000_0000,
        0x0000_0000,
        0x0000_0054,
        0x0000_0000,
        0x0000_01ff,
        0x0000_000d,
        0x0000_1b36,
        0x0000_4011,
        0x0000_0000,
        0x0000_0800,
        0x0142_4810,
        0x0000_8020,
        0x0000_0000,
        0x0030_0604,
        0x2204_0000,
        0x0012_007b,
        0x0040_03c0,
        0x0000_0000,
        0x0000_0000,
        0x0030_0020,
        0x0000_0000,
        0x0000_001e,
        0x0000_0004,
        0x0000_0000,
        0x0000_0000,
    ];

    /// One function: its header dwords, and the writable bits of each BAR.
    struct Function
    {
        regs: [u32; 64],
        bar_masks: [u32; MAX_BARS],
    }

    /// In-memory configuration space: absent functions read all ones; a
    /// write keeps only a BAR register's writable bits.
    #[derive(Default)]
    struct Space
    {
        funcs: RefCell<BTreeMap<(u8, u8, u8), Function>>,
    }

    impl Space
    {
        fn add(&self, bdf: (u8, u8, u8), dwords: &[u32])
        {
            let mut regs = [0u32; 64];
            regs[..dwords.len()].copy_from_slice(dwords);
            self.funcs.borrow_mut().insert(
                bdf,
                Function {
                    regs,
                    bar_masks: [0; MAX_BARS],
                },
            );
        }

        fn set(&self, bdf: (u8, u8, u8), reg: u16, value: u32)
        {
            self.funcs.borrow_mut().get_mut(&bdf).unwrap().regs[usize::from(reg / 4)] = value;
        }

        fn dword(&self, bus: u8, dev: u8, func: u8, reg: u16) -> u32
        {
            self.funcs
                .borrow()
                .get(&(bus, dev, func))
                .map_or(u32::MAX, |f| f.regs[usize::from(reg / 4) % 64])
        }

        fn write(&self, bus: u8, dev: u8, func: u8, reg: u16, value: u32, mask: u32)
        {
            let mut funcs = self.funcs.borrow_mut();
            let Some(f) = funcs.get_mut(&(bus, dev, func))
            else
            {
                return;
            };
            let at = usize::from(reg / 4) % 64;
            let shift = u32::from(reg % 4) * 8;
            let (value, mask) = (value << shift, mask << shift);
            let writable = if (0x10..0x28).contains(&reg)
            {
                f.bar_masks[(usize::from(reg) - 0x10) / 4]
            }
            else
            {
                u32::MAX
            };
            let mask = mask & writable;
            f.regs[at] = (f.regs[at] & !mask) | (value & mask);
        }
    }

    impl ConfigSpace for Space
    {
        fn read8(&self, bus: u8, dev: u8, func: u8, reg: u16) -> u8
        {
            u8::try_from((self.dword(bus, dev, func, reg) >> (u32::from(reg % 4) * 8)) & 0xFF)
                .unwrap()
        }
        fn read16(&self, bus: u8, dev: u8, func: u8, reg: u16) -> u16
        {
            u16::try_from((self.dword(bus, dev, func, reg) >> (u32::from(reg % 4) * 8)) & 0xFFFF)
                .unwrap()
        }
        fn read32(&self, bus: u8, dev: u8, func: u8, reg: u16) -> u32
        {
            self.dword(bus, dev, func, reg)
        }
        fn write16(&self, bus: u8, dev: u8, func: u8, reg: u16, val: u16)
        {
            self.write(bus, dev, func, reg, u32::from(val), 0xFFFF);
        }
        fn write32(&self, bus: u8, dev: u8, func: u8, reg: u16, val: u32)
        {
            self.write(bus, dev, func, reg, val, u32::MAX);
        }
    }

    /// A host bridge at 00:00.0 (vendor 1b36, class 06/00).
    const HOST_BRIDGE: &[u32] = &[0x0008_1b36, 0, 0x0600_0000, 0];

    /// QEMU's `edu` (1234:11e8) with its 1 MiB 32-bit non-prefetchable BAR 0
    /// unassigned, as it reads hot-added.
    fn add_edu(space: &Space, bdf: (u8, u8, u8))
    {
        space.add(bdf, &[0x11e8_1234, 0, 0x00ff_0010, 0]);
        space.funcs.borrow_mut().get_mut(&bdf).unwrap().bar_masks[0] = 0xFFF0_0000;
    }

    fn found(space: &Space) -> Vec<Slot>
    {
        let mut functions = Vec::new();
        scan(space, 0, 0, 3, &mut functions).unwrap();
        let mut out = Vec::new();
        slots(space, &functions, &mut out).unwrap();
        out
    }

    #[test]
    fn a_managed_port_is_held_from_acpid_writes()
    {
        use crate::acpid::{ConfigAccess, ConfigError, ConfigOp, config_access};
        let space = Space::default();
        space.add((0, 0, 0), HOST_BRIDGE);
        space.add((0, 3, 0), Q35_ROOT_PORT);
        let mut functions = Vec::new();
        scan(&space, 0, 0, 3, &mut functions).unwrap();
        let mut records = PciRecords::new(functions).unwrap();
        let port = (0, 0, 3, 0);
        let index = records
            .devices()
            .iter()
            .position(|d| address(d) == port)
            .unwrap();
        let slot_control = 0x6C;
        let write = |records: &PciRecords| {
            config_access(ConfigOp::Write, slot_control, 2, records.state(index))
        };
        assert_eq!(write(&records), Ok(ConfigAccess::Access));
        assert!(hold_port(&mut records, port));
        assert_eq!(write(&records), Err(ConfigError::Refused));
        assert_eq!(
            config_access(ConfigOp::Read, slot_control, 2, records.state(index)),
            Ok(ConfigAccess::Access)
        );
        // Held once; no record at another address.
        assert!(!hold_port(&mut records, port));
        assert!(!hold_port(&mut records, (0, 0, 4, 0)));
        assert!(records.unbound_at(index).is_none());
    }

    #[test]
    fn the_q35_root_port_is_a_slot_with_its_secondary_bus_and_windows()
    {
        let space = Space::default();
        space.add((0, 0, 0), HOST_BRIDGE);
        space.add((0, 3, 0), Q35_ROOT_PORT);
        let found = found(&space);
        assert_eq!(
            found,
            [Slot {
                port: (0, 0, 3, 0),
                express: 0x54,
                capabilities: 0x000a_007b,
                link_reporting: true,
                secondary: 1,
                subordinate: 1,
                memory: Some(Window {
                    base: 0x8000_0000,
                    end: 0x8020_0000,
                }),
                prefetchable: None,
            }]
        );
        let slot = found[0];
        assert!(slot.power_controller() && slot.button() && slot.command_completion());
        assert_eq!(slot.register(SLOT_CONTROL), 0x6C);
        assert_eq!(slot.register(SLOT_STATUS), 0x6E);
        assert_eq!(slot.register(LINK_STATUS), 0x66);
        // The captured empty slot: powered off, both indicators off.
        assert_eq!(space.read16(0, 3, 0, slot.register(SLOT_CONTROL)), 0x07C0);
        assert_eq!(space.read16(0, 3, 0, slot.register(SLOT_STATUS)), 0);
    }

    #[test]
    fn the_virt_root_ports_are_slots_and_the_bridge_and_iommu_are_not()
    {
        let space = Space::default();
        space.add((0, 0, 0), HOST_BRIDGE);
        // The RISC-V IOMMU at 00:01.0 (1b36:0014, class 08/06).
        space.add((0, 1, 0), &[0x0014_1b36, 0, 0x0806_0000, 0]);
        space.add((0, 2, 0), VIRT_EMPTY_PORT);
        space.add((0, 3, 0), VIRT_OCCUPIED_PORT);
        add_edu(&space, (2, 0, 0));
        let found = found(&space);
        let ports: Vec<_> = found
            .iter()
            .map(|s| (s.port, s.secondary, s.memory))
            .collect();
        assert_eq!(
            ports,
            [
                (
                    (0, 0, 2, 0),
                    1,
                    Some(Window {
                        base: 0x4020_0000,
                        end: 0x4040_0000
                    })
                ),
                (
                    (0, 0, 3, 0),
                    2,
                    Some(Window {
                        base: 0x4000_0000,
                        end: 0x4020_0000
                    })
                ),
            ]
        );
        assert!(
            found
                .iter()
                .all(|s| s.prefetchable.is_none() && s.link_reporting)
        );
        // The occupied slot is powered (Power Controller Control clear) and
        // its card present.
        assert_eq!(
            space.read16(0, 3, 0, 0x6E) & SLOTSTA_PRESENT,
            SLOTSTA_PRESENT
        );
        assert_eq!(space.read16(0, 3, 0, 0x6C) & SLOTCTL_POWER_OFF, 0);
    }

    #[test]
    fn a_slot_holding_the_iommu_function_is_known_by_its_subtree()
    {
        let space = Space::default();
        space.add((0, 3, 0), VIRT_OCCUPIED_PORT);
        let slot = found(&space)[0];
        assert!(slot.holds((0, 2, 0, 0)));
        assert!(!slot.holds((0, 0, 1, 0)));
        assert!(!slot.holds((1, 2, 0, 0)));
    }

    #[test]
    fn a_port_without_a_hotplug_slot_is_not_one()
    {
        // Slot Implemented clear.
        let space = Space::default();
        space.add((0, 3, 0), Q35_ROOT_PORT);
        space.set((0, 3, 0), 0x54, 0x0042_4810);
        assert_eq!(found(&space), Vec::<Slot>::new());
        // Hot-Plug Capable clear.
        space.set((0, 3, 0), 0x54, 0x0142_4810);
        space.set((0, 3, 0), 0x68, 0x000a_003b);
        assert_eq!(found(&space), Vec::<Slot>::new());
        // An upstream port (type 5).
        space.set((0, 3, 0), 0x68, 0x000a_007b);
        space.set((0, 3, 0), 0x54, 0x0152_4810);
        assert_eq!(found(&space), Vec::<Slot>::new());
        // A bridge whose secondary bus is not programmed.
        space.set((0, 3, 0), 0x54, 0x0142_4810);
        space.set((0, 3, 0), 0x18, 0);
        assert_eq!(found(&space), Vec::<Slot>::new());
    }

    #[test]
    fn windows_decode_their_bases_and_limits()
    {
        assert_eq!(
            memory_window(0x8000, 0x8010),
            Some(Window {
                base: 0x8000_0000,
                end: 0x8020_0000
            })
        );
        assert_eq!(memory_window(0xFFF0, 0x0000), None);
        // A 64-bit prefetchable window above 4 GiB.
        assert_eq!(
            prefetchable_window(0x0001, 0x0FF1, 0x8, 0x8),
            Some(Window {
                base: 0x8_0000_0000,
                end: 0x8_1000_0000
            })
        );
        // The upper registers count only with 64-bit addressing.
        assert_eq!(
            prefetchable_window(0x0000, 0x0FF0, 0x8, 0x8),
            Some(Window {
                base: 0,
                end: 0x1000_0000
            })
        );
        // The firmware's empty window of the captured ports.
        assert_eq!(prefetchable_window(0xFFF1, 0x0001, u32::MAX, 0), None);
        assert!(
            Window {
                base: 0x8000_0000,
                end: 0x8020_0000
            }
            .inside(&[(0x7000_0000, 0x8020_0000)])
        );
        assert!(
            !Window {
                base: 0x8000_0000,
                end: 0x8020_0000
            }
            .inside(&[(0x7000_0000, 0x8010_0000), (0x8010_0000, 0x9000_0000)])
        );
    }

    /// An evaluated `_OSC` result granting `control`.
    fn osc(control: u32) -> Osc
    {
        Osc {
            evaluated: true,
            status: 0,
            control,
        }
    }

    /// The result of an `_OSC` that failed, with `control` left set.
    fn failed_osc(control: u32) -> Osc
    {
        Osc {
            evaluated: false,
            status: 0,
            control,
        }
    }

    #[test]
    fn native_control_needs_the_osc_bit_or_the_platform_key()
    {
        // q35 with ACPI PCI hotplug of the bridges off: 0x1f.
        assert!(native_control(Some(osc(0x1F)), false));
        // Default q35: 0x1e, native hotplug withheld.
        assert!(!native_control(Some(osc(0x1E)), false));
        // A failed or absent _OSC grants nothing.
        assert!(!native_control(Some(failed_osc(0x1F)), false));
        assert!(!native_control(None, false));
        // riscv64 virt: the platform key grants, whatever _OSC returned.
        assert!(native_control(Some(osc(0x1E)), true));
        assert!(native_control(None, true));
    }

    #[test]
    fn a_slots_host_bridge_is_the_one_of_its_root_bus_and_segment()
    {
        let mut bridges = Bridges::new();
        bridges.push_osc(0, 0, osc(0x1F)).unwrap();
        bridges.push_osc(1, 0, osc(0x1E)).unwrap();
        let osc_of = |segment, bus| host_bridge(&bridges, segment, bus).and_then(|b| b.osc);
        assert_eq!(osc_of(0, 0), Some(osc(0x1F)));
        assert_eq!(osc_of(1, 0), Some(osc(0x1E)));
        assert_eq!(osc_of(2, 0), None);
        assert_eq!(osc_of(0, 3), None);
    }

    /// A 32-bit non-prefetchable BAR request.
    fn request(register: u8, size: u64) -> BarRequest
    {
        BarRequest {
            register,
            size,
            wide: false,
            prefetchable: false,
        }
    }

    fn bases(placed: &[Option<Placed>; MAX_BARS]) -> Vec<(u8, u64)>
    {
        let mut out: Vec<_> = placed
            .iter()
            .flatten()
            .map(|p| (p.register, p.base))
            .collect();
        out.sort_unstable();
        out
    }

    const MEMORY: Option<Window> = Some(Window {
        base: 0x8000_0000,
        end: 0x8020_0000,
    });

    #[test]
    fn bars_are_placed_aligned_largest_first_clear_of_taken_ranges()
    {
        let mut requests = [None; MAX_BARS];
        requests[0] = Some(request(0, 0x10_0000));
        assert_eq!(
            bases(&assign(&requests, MEMORY, None, &[]).unwrap()),
            [(0, 0x8000_0000)]
        );
        // A live record's BAR takes the first MiB.
        assert_eq!(
            bases(&assign(&requests, MEMORY, None, &[(0x8000_0000, 0x8000_1000)]).unwrap()),
            [(0, 0x8010_0000)]
        );
        // The largest goes first, at the window's base; the smaller after it.
        requests[1] = Some(request(1, 0x1000));
        requests[2] = Some(request(2, 0x10_0000));
        requests[0] = Some(request(0, 0x1000));
        assert_eq!(
            bases(&assign(&requests, MEMORY, None, &[]).unwrap()),
            [(0, 0x8010_0000), (1, 0x8010_1000), (2, 0x8000_0000)]
        );
        // Each base is aligned to its size.
        let mut one = [None; MAX_BARS];
        one[0] = Some(request(0, 0x20_0000));
        let shifted = Some(Window {
            base: 0x8010_0000,
            end: 0x8060_0000,
        });
        assert_eq!(
            bases(&assign(&one, shifted, None, &[]).unwrap()),
            [(0, 0x8020_0000)]
        );
    }

    #[test]
    fn bars_smaller_than_a_page_take_a_page_of_their_own()
    {
        // Two 256-byte BARs: each on its own page, never packed into one.
        let mut requests = [None; MAX_BARS];
        requests[0] = Some(request(0, 0x100));
        requests[1] = Some(request(1, 0x100));
        assert_eq!(
            bases(&assign(&requests, MEMORY, None, &[]).unwrap()),
            [(0, 0x8000_0000), (1, 0x8000_1000)]
        );
        // A live record's sub-page BAR keeps its whole page from a placement.
        requests[1] = None;
        assert_eq!(
            bases(&assign(&requests, MEMORY, None, &[(0x8000_0100, 0x8000_0200)]).unwrap()),
            [(0, 0x8000_1000)]
        );
        // A window of one page holds one sub-page BAR, not two.
        requests[1] = Some(request(1, 0x100));
        let page = Some(Window {
            base: 0x8000_0000,
            end: 0x8000_1000,
        });
        assert_eq!(assign(&requests, page, None, &[]), Err(Unplaced::NoRoom(1)));
    }

    #[test]
    fn bars_that_do_not_fit_are_refused_whole()
    {
        let mut requests = [None; MAX_BARS];
        requests[0] = Some(request(0, 0x40_0000));
        assert_eq!(
            assign(&requests, MEMORY, None, &[]),
            Err(Unplaced::NoRoom(0))
        );
        requests[0] = Some(request(0, 0x10_0000));
        requests[1] = Some(request(1, 0x10_0000));
        requests[2] = Some(request(2, 0x10_0000));
        assert_eq!(
            assign(&requests, MEMORY, None, &[]),
            Err(Unplaced::NoRoom(2))
        );
        assert_eq!(
            assign(&requests, None, None, &[]),
            Err(Unplaced::NoWindow(0))
        );
        requests[1] = Some(request(1, 0x3000));
        assert_eq!(
            assign(&requests, MEMORY, None, &[]),
            Err(Unplaced::BadSize(1))
        );
    }

    #[test]
    fn a_64_bit_prefetchable_bar_goes_in_the_prefetchable_window_first()
    {
        let prefetchable = Some(Window {
            base: 0x8_0000_0000,
            end: 0x8_0040_0000,
        });
        let mut requests = [None; MAX_BARS];
        requests[0] = Some(request(0, 0x1000));
        requests[2] = Some(BarRequest {
            register: 2,
            size: 0x10_0000,
            wide: true,
            prefetchable: true,
        });
        assert_eq!(
            bases(&assign(&requests, MEMORY, prefetchable, &[]).unwrap()),
            [(0, 0x8000_0000), (2, 0x8_0000_0000)]
        );
        // With the prefetchable window off, or full, it goes in the other.
        assert_eq!(
            bases(&assign(&requests, MEMORY, None, &[]).unwrap()),
            [(0, 0x8010_0000), (2, 0x8000_0000)]
        );
        let full = [(0x8_0000_0000, 0x8_0040_0000)];
        assert_eq!(
            bases(&assign(&requests, MEMORY, prefetchable, &full).unwrap()),
            [(0, 0x8010_0000), (2, 0x8000_0000)]
        );
        // A 32-bit prefetchable BAR never goes in the prefetchable window.
        let mut narrow = [None; MAX_BARS];
        narrow[0] = Some(BarRequest {
            register: 0,
            size: 0x1000,
            wide: false,
            prefetchable: true,
        });
        assert_eq!(
            assign(&narrow, None, prefetchable, &[]),
            Err(Unplaced::NoWindow(0))
        );
    }

    #[test]
    fn a_hot_added_edu_is_placed_programmed_and_read_back()
    {
        let space = Space::default();
        space.add((0, 3, 0), Q35_ROOT_PORT);
        add_edu(&space, (1, 0, 0));
        let slot = found(&space)[0];
        let edu = crate::scan::function(&space, 0, 1, 0, 0).unwrap();
        assert_eq!(
            (edu.bar_count, edu.bar_size[0], edu.bar_phys[0]),
            (1, 0x10_0000, 0)
        );
        let requests = bar_requests(&edu, |at| space.read32(1, 0, 0, at));
        assert_eq!(requests[0], Some(request(0, 0x10_0000)));
        let placed = assign(&requests, slot.memory, slot.prefetchable, &[]).unwrap();
        // The function decodes memory while the BAR changes; the write turns
        // decode off and back on.
        space.write16(1, 0, 0, COMMAND, COMMAND_MEMORY);
        program_bars(&space, (1, 0, 0), &placed);
        assert_eq!(space.read16(1, 0, 0, COMMAND), COMMAND_MEMORY);
        let programmed = crate::scan::function(&space, 0, 1, 0, 0).unwrap();
        assert_eq!(programmed.bar_phys[0], 0x8000_0000);
        assert!(placed_match(&programmed, &placed));
        assert!(!placed_match(&edu, &placed));
        assert!(crate::scan::function(&space, 0, 1, 0, 1).is_none());
    }

    #[test]
    fn place_programs_a_function_that_fits_and_leaves_one_that_does_not_untouched()
    {
        let space = Space::default();
        space.add((0, 3, 0), Q35_ROOT_PORT);
        add_edu(&space, (1, 0, 0));
        let slot = found(&space)[0];
        let window = slot.memory.unwrap();
        // The whole window is taken: the 1 MiB BAR has no room, and nothing
        // is written.
        let Found::Unplaced(device, why) =
            place(&space, &slot, (1, 0, 0), &[(window.base, window.end)])
        else
        {
            panic!("a BAR with no room was placed");
        };
        assert_eq!(why, Unplaced::NoRoom(0));
        assert_eq!(device.bar_phys[0], 0);
        assert_eq!(space.read32(1, 0, 0, BAR0), 0);
        // With the window free it is placed at the window's base.
        let Found::Ready(device) = place(&space, &slot, (1, 0, 0), &[])
        else
        {
            panic!("a BAR that fits was not placed");
        };
        assert_eq!(device.bar_phys[0], window.base);
        assert!(matches!(
            place(&space, &slot, (1, 0, 1), &[]),
            Found::Absent
        ));
        // A port's own window is beside the point: a type-1 function is
        // returned as read, its windows unprogrammed.
        space.add((1, 0, 2), Q35_ROOT_PORT);
        let Found::Ready(bridge) = place(&space, &slot, (1, 0, 2), &[])
        else
        {
            panic!("a bridge was not returned as read");
        };
        assert!(bridge.bridge_buses.is_some());
        assert_eq!(
            admit(bridge, |_| panic!("a bridge is not appended")),
            Admission::Bridge
        );
    }

    #[test]
    fn a_hot_added_function_is_appended_and_a_refusal_has_its_reason()
    {
        let space = Space::default();
        add_edu(&space, (1, 0, 0));
        let edu = crate::scan::function(&space, 0, 1, 0, 0).unwrap();
        assert_eq!(admit(edu, |_| Ok(7)), Admission::Appended(7));
        assert_eq!(
            admit(edu, |_| Err(AppendError::NoMemory)),
            Admission::Refused(AppendError::NoMemory)
        );
        assert_eq!(
            admit(edu, |_| Err(AppendError::Present)),
            Admission::Refused(AppendError::Present)
        );
        assert_ne!(
            refusal(AppendError::NoMemory),
            refusal(AppendError::Present)
        );
        // A hot-added switch is not recorded and not appended.
        space.add((0, 3, 0), Q35_ROOT_PORT);
        let bridge = crate::scan::function(&space, 0, 0, 3, 0).unwrap();
        assert_eq!(
            admit(bridge, |_| panic!("a bridge is not appended")),
            Admission::Bridge
        );
    }

    #[test]
    fn the_poller_powers_an_empty_slot_up_once_a_card_is_present()
    {
        let present = SLOTSTA_PRESENT;
        // QEMU's plug latches Presence Detect Changed and Attention Button
        // Pressed with Presence Detect State.
        let plugged = present | SLOTSTA_PRESENCE_CHANGED | SLOTSTA_BUTTON;
        assert_eq!(next(SlotState::Empty, 0), (SlotState::Empty, Action::None));
        assert_eq!(
            next(SlotState::Empty, plugged),
            (SlotState::Empty, Action::PowerUp)
        );
        assert_eq!(
            next(SlotState::Empty, present),
            (SlotState::Empty, Action::PowerUp)
        );
        assert_eq!(
            next(SlotState::Occupied, present),
            (SlotState::Occupied, Action::None)
        );
        assert_eq!(
            next(SlotState::Occupied, present | SLOTSTA_LINK_CHANGED),
            (SlotState::Occupied, Action::None)
        );
        assert_eq!(
            next(SlotState::Occupied, SLOTSTA_PRESENCE_CHANGED),
            (SlotState::Departed, Action::Removal)
        );
        assert_eq!(
            next(SlotState::Occupied, present | SLOTSTA_BUTTON),
            (SlotState::Departed, Action::Removal)
        );
        assert_eq!(
            next(SlotState::Failed, present),
            (SlotState::Failed, Action::None)
        );
        assert_eq!(next(SlotState::Failed, 0), (SlotState::Empty, Action::None));
        // A removal is reported once: presence stays clear on the polls after.
        assert_eq!(
            next(SlotState::Departed, 0),
            (SlotState::Departed, Action::None)
        );
        assert_eq!(
            next(SlotState::Departed, present | SLOTSTA_BUTTON),
            (SlotState::Departed, Action::None)
        );
        assert_eq!(
            next(SlotState::Departed, present),
            (SlotState::Occupied, Action::None)
        );
        for state in [
            SlotState::Empty,
            SlotState::Occupied,
            SlotState::Failed,
            SlotState::Departed,
        ]
        {
            assert_eq!(next(state, u16::MAX), (state, Action::None));
        }
        assert_eq!(initial(present, true), SlotState::Occupied);
        assert_eq!(initial(present, false), SlotState::Empty);
        assert_eq!(initial(0, true), SlotState::Empty);
        assert_eq!(initial(u16::MAX, true), SlotState::Empty);
    }

    #[test]
    fn power_on_and_off_change_only_what_the_slot_has()
    {
        // The captured slot: power controller and both indicators, powered
        // off with the indicators off.
        assert_eq!(power_on(0x07C0, 0x000a_007b), 0x01C0);
        assert_eq!(power_off(0x01C0, 0x000a_007b), 0x07C0);
        // No power controller and no power indicator: nothing to write.
        assert_eq!(power_on(0x07C0, 0x0000_0040), 0x07C0);
        assert_eq!(power_off(0x01C0, 0x0000_0040), 0x01C0);
        // The event enables are kept as they were.
        assert_eq!(
            power_on(0x07C0 | 0x8, 0x000a_007b) & SLOTCTL_EVENT_ENABLES,
            0x8
        );
    }
}
