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
use crate::pci::{
    CAP_ID_PCI_EXPRESS, COMMAND, COMMAND_BUS_MASTER, COMMAND_INTERRUPT_DISABLE, COMMAND_MEMORY,
    STATUS, find_capability,
};
use crate::pci_records::{AppendError, PciRecords, RecordState};
use crate::resource::{CarveError, Span, SpanTable, SplitError};
use crate::scan::{ConfigSpace, MAX_BARS, PCI_REVISION_CLASS, PCI_SUBSYSTEM, PciDevice};

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
/// Power Indicator Control: blinking.
const SLOTCTL_POWER_INDICATOR_BLINK: u16 = 0x2 << 8;
/// Power Indicator Control: off.
const SLOTCTL_POWER_INDICATOR_OFF: u16 = 0x3 << 8;
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

/// What decides a slot's native-control grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrantBy
{
    /// The machine's platform description table (`pcie_native_hotplug = yes`).
    PlatformTable,
    /// The `_OSC` result of the slot's host bridge.
    Osc,
}

/// Where a slot's native-control grant stands, as [`slot_grant`] decides it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlotGrant
{
    /// devmgr manages the slot, native control granted by the given source.
    Manage(GrantBy),
    /// The firmware drives the slot: its host bridge's `_OSC` result
    /// withholds native control, or failed, and the platform description
    /// tables, known, grant none. Final.
    Firmware,
    /// Not decided yet: no `_OSC` result has arrived, or one that withholds
    /// native control has while the platform description tables are not
    /// known.
    Wait,
}

/// The native-control grant of a slot whose host bridge's `_OSC` result is
/// `osc` (`None` until it arrives), `tables` being the machine's
/// platform description table's `pcie_native_hotplug` once devmgr knows its
/// tables (`Some(false)` when it knows there is none), `None` before.
///
/// A table can only add native control, never withdraw it: a grant by
/// either source manages the slot at once. A withheld or failed `_OSC`
/// settles the slot to the firmware only once the tables are known and grant
/// nothing, so a table read later is never preempted by that result
/// (docs/driver-binding.md § Platform Description Tables).
#[must_use]
pub const fn slot_grant(osc: Option<Osc>, tables: Option<bool>) -> SlotGrant
{
    if matches!(tables, Some(true))
    {
        return SlotGrant::Manage(GrantBy::PlatformTable);
    }
    if osc_grants(osc)
    {
        return SlotGrant::Manage(GrantBy::Osc);
    }
    if osc.is_some() && tables.is_some()
    {
        return SlotGrant::Firmware;
    }
    SlotGrant::Wait
}

/// What devmgr settles a slot to on this turn, its grant being `grant`
/// ([`slot_grant`]) and `hold` holding devmgr's `CSpace` headroom, `false`
/// when the headroom is short of its mark and its top-up was refused
/// (`services/devmgr/docs/responsibilities.md` § `CSpace` headroom). A
/// grant that settles the slot keeps capabilities: a managed slot a
/// derivation of its port's configuration page, and a managed slot and one
/// left to the firmware the held BAR pages of the functions behind it. Such
/// a grant waits while `hold` is refused, and a later turn settles it;
/// `hold` is called for no other grant.
#[must_use]
pub fn held_grant(grant: SlotGrant, hold: impl FnOnce() -> bool) -> SlotGrant
{
    if matches!(grant, SlotGrant::Wait) || hold()
    {
        grant
    }
    else
    {
        SlotGrant::Wait
    }
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
/// non-prefetchable window, and `prefetchable`, each BAR inside one range of
/// `free` (each `(base, end)`: the ranges of the windows devmgr's apertures
/// still hold, [`free_ranges`]) and clear of the others. Each BAR is aligned
/// to its size, as a BAR's base must be, and to a page, and takes at least a
/// page, which it shares with no other BAR (devmgr carves a BAR's cap in whole
/// pages); the largest is placed first, each at the lowest free base. A
/// 64-bit prefetchable BAR goes in the prefetchable window, or in the
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
    free: &[(u64, u64)],
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
            .find_map(|w| lowest_free(*w, request.size, free, earlier))
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
/// `size`), whose span lies inside one range of `free` and overlaps the
/// span of no BAR of `placed`.
fn lowest_free(
    window: Window,
    size: u64,
    free: &[(u64, u64)],
    placed: &[Option<Placed>],
) -> Option<u64>
{
    let size = span(size);
    let placed = placed
        .iter()
        .flatten()
        .map(|p| (p.base, p.base.saturating_add(span(p.size))));
    free.iter()
        .filter_map(|&(b, e)| {
            let end_of_range = e.min(window.end);
            let mut base = b.max(window.base).checked_next_multiple_of(size)?;
            loop
            {
                let end = base.checked_add(size)?;
                if end > end_of_range
                {
                    return None;
                }
                let clash = placed
                    .clone()
                    .filter(|&(pb, pe)| pb < end && base < pe)
                    .map(|(_, pe)| pe)
                    .max();
                match clash
                {
                    None => return Some(base),
                    Some(clash_end) => base = clash_end.checked_next_multiple_of(size)?,
                }
            }
        })
        .min()
}

/// The ranges of `slot`'s windows that devmgr still holds: the part of each
/// span of `spans` (its aperture table's caps) inside each open window, its
/// ends rounded inward to pages. Each range lies inside one cap, so a BAR
/// placed in it ([`assign`]) is carved from that cap; two neighbours the
/// kernel did not merge are two ranges. Appended to `out`.
///
/// # Errors
/// The allocation error when `out` cannot grow.
pub fn free_ranges<S>(
    spans: &[Span<S>],
    slot: &Slot,
    out: &mut Vec<(u64, u64)>,
) -> Result<(), TryReserveError>
{
    for window in [slot.memory, slot.prefetchable].into_iter().flatten()
    {
        for s in spans
        {
            let Some(base) = s.base.max(window.base).checked_next_multiple_of(PAGE)
            else
            {
                continue;
            };
            let end = s.end.min(window.end) & !(PAGE - 1);
            if base < end
            {
                out.try_reserve(1)?;
                out.push((base, end));
            }
        }
    }
    Ok(())
}

/// The page span `(base, len)` of each assigned MMIO BAR of `device`: the
/// range devmgr holds for it in a slot's windows, at least a page.
pub fn bar_spans(device: &PciDevice) -> impl Iterator<Item = (u64, u64)> + '_
{
    device
        .bar_phys
        .iter()
        .zip(&device.bar_size)
        .zip(&device.bar_is_mmio)
        .take(device.bar_count)
        .filter(|&((&phys, _), &mmio)| mmio && phys != 0)
        .map(|((&phys, &size), _)| {
            let (base, end) = bar_page_span(phys, size);
            (base, end.saturating_sub(base))
        })
}

/// The whole pages `(base, end)` a BAR at `phys` of `size` bytes lies in:
/// the range devmgr carves and holds its caps in, and within which a BAR cap
/// given back to the held BAR pages is merged with its neighbours.
#[must_use]
pub const fn bar_page_span(phys: u64, size: u64) -> (u64, u64)
{
    let base = phys & !(PAGE - 1);
    let end = match phys.saturating_add(size).checked_next_multiple_of(PAGE)
    {
        Some(end) => end,
        None => u64::MAX,
    };
    (base, end)
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
/// place its MMIO BARs in the ranges of the slot's windows devmgr still
/// holds, `free` ([`free_ranges`], [`assign`]),
/// program them ([`program_bars`]), and read it again for its record. A
/// type-1 function is returned as read, for [`admit`] to refuse.
pub fn place(
    cfg: &impl ConfigSpace,
    slot: &Slot,
    (bus, dev, func): (u8, u8, u8),
    free: &[(u64, u64)],
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
    let placed = match assign(&requests, slot.memory, slot.prefetchable, free)
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

/// Where the poller holds a managed slot
/// ([hotplug.md](../../docs/hotplug.md) § Poller).
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
    /// The attention button of an occupied slot was pressed: the power
    /// indicator blinks, and the removal starts once `polls_left` more polls
    /// pass with the button not pressed again and the card present.
    Pressed
    {
        polls_left: u64
    },
    /// The removal job is posted: the slot waits for the control thread's
    /// completion ([`completed`]) and is powered off only then. Nothing it
    /// reads meanwhile is acted on, but `asked` keeps whether a card was
    /// inserted or the attention button pressed, so the slot is powered up
    /// for it after the completion.
    Removing
    {
        asked: bool
    },
    /// The removal completed with the card it removed still present: the
    /// slot is powered off until its attention button is pressed or a card
    /// is inserted again.
    Off,
    /// Taken over with a function behind the slot that no longer reads as its
    /// live record ([`Behind::Replaced`]): the first poll posts the removal
    /// of the recorded card, a card present then asked for, so it is added
    /// once the removal completes.
    Replaced,
}

/// The attention button's abort window, in milliseconds: a second press
/// within it cancels the removal (PCI Express Base Specification r4.0
/// § 6.7.1.5).
const ABORT_WINDOW_MS: u64 = 5000;

/// The polls of [`HOTPLUG_POLL_MS`] the abort window lasts.
pub const ABORT_POLLS: u64 = ABORT_WINDOW_MS / HOTPLUG_POLL_MS;

// The window is a whole number of polls, at least one.
const _: () = assert!(ABORT_WINDOW_MS.is_multiple_of(HOTPLUG_POLL_MS) && ABORT_POLLS >= 1);

/// What the poller does after reading a slot's Slot Status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action
{
    None,
    /// A card is present in an empty slot, or one powered off since its
    /// removal is asked for again: power the slot on, wait for its link, and
    /// post its add job. The slot is then occupied, or failed when the link
    /// does not come up.
    PowerUp,
    /// The attention button was pressed: blink the power indicator for the
    /// abort window.
    Blink,
    /// The button was pressed again within the abort window: the removal is
    /// cancelled, and the power indicator turns on again.
    Cancel,
    /// Post the slot's removal job. The slot is powered off once the job
    /// completes ([`completed`]).
    Remove,
}

/// The poller's decision for a slot in `state` whose Slot Status reads
/// `status`, with the state it holds the slot in after any action but
/// [`Action::PowerUp`]. `link_down` is whether the slot reports its link
/// (Data Link Layer Link Active Reporting) and the link went down since the
/// last poll: Data Link Layer State Changed is latched and Link Active reads
/// clear. A status of all ones, from a port that does not answer, changes
/// nothing.
#[must_use]
#[expect(
    clippy::fn_params_excessive_bools,
    reason = "`link_down` is the one link reading the poller makes beside Slot Status"
)]
pub const fn next(state: SlotState, status: u16, link_down: bool) -> (SlotState, Action)
{
    if status == u16::MAX
    {
        return (state, Action::None);
    }
    let present = status & SLOTSTA_PRESENT != 0;
    let pressed = status & SLOTSTA_BUTTON != 0;
    // A presence change on a powered slot is its card leaving, whether or not
    // a card reads present again: one pulled and inserted, or swapped, within
    // a poll is removed and then, asked for by the change, added again.
    let changed = status & SLOTSTA_PRESENCE_CHANGED != 0;
    let gone = !present || link_down || changed;
    // The removal keeps as asked a card changed in the slot, and a second
    // press in the abort window, which asks to keep the card; a first press
    // on an occupied slot asks for its removal.
    let kept = pressed && matches!(state, SlotState::Pressed { .. });
    match state
    {
        SlotState::Empty if present => (SlotState::Empty, Action::PowerUp),
        SlotState::Replaced => (SlotState::Removing { asked: present }, Action::Remove),
        SlotState::Occupied | SlotState::Pressed { .. } if gone => (
            SlotState::Removing {
                asked: present && (changed || kept),
            },
            Action::Remove,
        ),
        SlotState::Occupied if pressed => (
            SlotState::Pressed {
                polls_left: ABORT_POLLS,
            },
            Action::Blink,
        ),
        SlotState::Pressed { .. } if pressed => (SlotState::Occupied, Action::Cancel),
        SlotState::Pressed { polls_left } if polls_left <= 1 =>
        {
            (SlotState::Removing { asked: false }, Action::Remove)
        }
        SlotState::Removing { asked } => (
            SlotState::Removing {
                asked: asked || asks(status),
            },
            Action::None,
        ),
        SlotState::Pressed { polls_left } => (
            SlotState::Pressed {
                polls_left: polls_left.saturating_sub(1),
            },
            Action::None,
        ),
        // A card inserted or swapped, or the attention button pressed, asks
        // for a card present to be powered up: one in a failed slot is tried
        // again.
        SlotState::Off | SlotState::Failed if asks(status) => (state, Action::PowerUp),
        SlotState::Failed | SlotState::Off if !present => (SlotState::Empty, Action::None),
        SlotState::Empty | SlotState::Occupied | SlotState::Failed | SlotState::Off =>
        {
            (state, Action::None)
        }
    }
}

/// Why [`next`] posted the removal of a slot it held in `state` on reading
/// `status` and `link_down`, as devmgr logs it.
#[must_use]
#[expect(
    clippy::fn_params_excessive_bools,
    reason = "`link_down` is the one link reading the poller makes beside Slot Status"
)]
pub const fn removal_cause(state: SlotState, status: u16, link_down: bool) -> &'static str
{
    if matches!(state, SlotState::Replaced)
    {
        "its card was removed or replaced while the slot's grant waited"
    }
    else if matches!(state, SlotState::Pressed { .. })
        && status & SLOTSTA_PRESENT != 0
        && status & SLOTSTA_PRESENCE_CHANGED == 0
        && !link_down
    {
        "its attention button's abort window elapsed"
    }
    else
    {
        "card removed or replaced, or its link lost"
    }
}

/// Whether Slot Status `status` asks for a card present to be powered up:
/// the card was inserted (Presence Detect Changed) or the attention button
/// pressed. `status` is not all ones.
const fn asks(status: u16) -> bool
{
    status & SLOTSTA_PRESENT != 0 && status & (SLOTSTA_BUTTON | SLOTSTA_PRESENCE_CHANGED) != 0
}

/// The state of a slot whose removal job completed and which the poller has
/// powered off, its Slot Status then reading `status`: empty when no card is
/// present, so a card present is powered up on the next poll when it was
/// inserted, or the attention button pressed, while the slot was removing
/// or since its last poll; else off, the card the removal removed still in
/// the slot. A slot that is not being removed is left as it is.
#[must_use]
pub const fn completed(state: SlotState, status: u16) -> SlotState
{
    match state
    {
        SlotState::Removing { asked }
            if status != u16::MAX && status & SLOTSTA_PRESENT != 0 && !asked && !asks(status) =>
        {
            SlotState::Off
        }
        SlotState::Removing { .. } => SlotState::Empty,
        SlotState::Empty
        | SlotState::Occupied
        | SlotState::Failed
        | SlotState::Pressed { .. }
        | SlotState::Off
        | SlotState::Replaced => state,
    }
}

/// Whether Slot Status `status` reads a card present.
#[must_use]
pub const fn present(status: u16) -> bool
{
    status != u16::MAX && status & SLOTSTA_PRESENT != 0
}

/// Whether Slot Status `status` latched Data Link Layer State Changed, so
/// the poller reads Link Status to learn whether the link went down.
#[must_use]
pub const fn link_changed(status: u16) -> bool
{
    status != u16::MAX && status & SLOTSTA_LINK_CHANGED != 0
}

/// What lies behind a slot when it is taken over, as devmgr's records and
/// the functions' configuration headers tell it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Behind
{
    /// No live record lies behind the slot.
    Nothing,
    /// Live records lie behind the slot, and each function reads as its
    /// record ([`same_function`]), or could not be read.
    Recorded,
    /// Live records lie behind the slot, and a function no longer reads as
    /// its record: the card was removed, or replaced by another, while the
    /// slot's grant waited.
    Replaced,
}

/// The state a slot is taken over in: occupied when live records lie behind
/// the slot and its functions read as recorded, whatever its Slot Status
/// reads; replaced when a function no longer does; else empty. A recorded
/// card that left while the slot's grant waited is then removed on the first
/// poll, a card that replaced it is removed and then added, and a present
/// card with nothing recorded is brought up on it.
#[must_use]
pub const fn initial(behind: Behind) -> SlotState
{
    match behind
    {
        Behind::Nothing => SlotState::Empty,
        Behind::Recorded => SlotState::Occupied,
        Behind::Replaced => SlotState::Replaced,
    }
}

/// Whether the function at `record`'s address in `cfg` reads as `record`
/// describes it: the same vendor and device ID, revision and class code,
/// and, for a type-0 header, subsystem vendor and ID. A function that does
/// not answer does not; a card replaced by one of the same identity does,
/// and is not told apart from it.
#[must_use]
pub fn same_function(cfg: &impl ConfigSpace, record: &PciDevice) -> bool
{
    let (b, d, f) = (record.bus, record.dev, record.func);
    let revision_class = cfg.read32(b, d, f, PCI_REVISION_CLASS);
    let [revision, ..] = revision_class.to_le_bytes();
    // Header layout: the header type without its multi-function bit.
    let layout = cfg.read8(b, d, f, 0x0E) & 0x7F;
    let subsystem = if layout == 0
    {
        (
            cfg.read16(b, d, f, PCI_SUBSYSTEM),
            cfg.read16(b, d, f, PCI_SUBSYSTEM + 2),
        )
    }
    else
    {
        (0, 0)
    };
    cfg.read16(b, d, f, 0x00) == record.vendor_id
        && cfg.read16(b, d, f, 0x02) == record.device_id
        && revision == record.revision
        && revision_class >> 8 == record.class_code
        && subsystem == (record.subsystem_vendor, record.subsystem_id)
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
    indicator(value, capabilities, SLOTCTL_POWER_INDICATOR_ON)
}

/// The Slot Control value `control` with the slot's power off where the slot
/// has a power controller, and its power indicator off where it has one.
#[must_use]
pub const fn power_off(control: u16, capabilities: u32) -> u16
{
    indicator(
        power_controller_off(control, capabilities),
        capabilities,
        SLOTCTL_POWER_INDICATOR_OFF,
    )
}

/// The Slot Control value `control` with the slot's power off where the slot
/// has a power controller, its power indicator as it was: the first of the
/// removal's two writes, the indicator turned off by the second
/// ([`indicator_off`]).
#[must_use]
pub const fn power_controller_off(control: u16, capabilities: u32) -> u16
{
    if capabilities & SLOTCAP_POWER_CONTROLLER != 0
    {
        control | SLOTCTL_POWER_OFF
    }
    else
    {
        control
    }
}

/// The Slot Control value `control` with the power indicator blinking,
/// where the slot has one: the abort window of an attention-button press.
#[must_use]
pub const fn blink(control: u16, capabilities: u32) -> u16
{
    indicator(control, capabilities, SLOTCTL_POWER_INDICATOR_BLINK)
}

/// The Slot Control value `control` with the power indicator on, where the
/// slot has one: a removal cancelled in its abort window.
#[must_use]
pub const fn indicator_on(control: u16, capabilities: u32) -> u16
{
    indicator(control, capabilities, SLOTCTL_POWER_INDICATOR_ON)
}

/// The Slot Control value `control` with the power indicator off, where the
/// slot has one.
#[must_use]
pub const fn indicator_off(control: u16, capabilities: u32) -> u16
{
    indicator(control, capabilities, SLOTCTL_POWER_INDICATOR_OFF)
}

/// `control` with Power Indicator Control set to `value` where the slot has
/// a power indicator.
const fn indicator(control: u16, capabilities: u32, value: u16) -> u16
{
    if capabilities & SLOTCAP_POWER_INDICATOR != 0
    {
        (control & !SLOTCTL_POWER_INDICATOR) | value
    }
    else
    {
        control
    }
}

/// Return held BAR pages: move each span of `held` (the held BAR pages)
/// that `inside` holds for, given its `(base, end)`, to `free` (the
/// apertures), whole, one at a time, and merge it there with each adjacent
/// span through `merge` ([`SpanTable::move_merged`]). A span is moved as the
/// cap it is, so nothing is split, and only from `held`, so a page is
/// returned once: a span returned already, or carved by a bind and not given
/// back, is not there. Returns the number of spans moved.
///
/// # Errors
/// [`CarveError::NoMemory`], with the spans moved before, when `free`
/// cannot grow; the spans not moved stay in `held`.
pub fn return_bars<S: Copy>(
    held: &mut SpanTable<S>,
    free: &mut SpanTable<S>,
    inside: impl Fn(u64, u64) -> bool,
    mut merge: impl FnMut(&Span<S>, &Span<S>) -> Option<S>,
) -> Result<usize, (usize, CarveError)>
{
    let mut moved = 0usize;
    while let Some((base, end)) = held
        .spans()
        .iter()
        .map(|s| (s.base, s.end))
        .find(|&(base, end)| inside(base, end))
    {
        // Moved whole, the span splits nothing.
        held.move_merged(
            free,
            base,
            end.saturating_sub(base),
            1,
            |_, _| Err(SplitError::Failed),
            &mut merge,
        )
        .map_err(|e| (moved, e))?;
        moved = moved.saturating_add(1);
    }
    Ok(moved)
}

/// Quiesce the function at `at` (bus, device, function) of `cfg` before its
/// removal: memory decode and Bus Master Enable off and Interrupt Disable
/// set, so it answers at none of its BARs, masters nothing and asserts no
/// line while the slot is powered off, whether a driver was bound to it or
/// not. A function that does not answer is left as it is. Returns whether the
/// Command register was written.
pub fn quiesce(cfg: &impl ConfigSpace, at: (u8, u8, u8)) -> bool
{
    let (bus, dev, func) = at;
    let command = cfg.read16(bus, dev, func, COMMAND);
    if command == u16::MAX
    {
        return false;
    }
    let quiet = (command & !(COMMAND_MEMORY | COMMAND_BUS_MASTER)) | COMMAND_INTERRUPT_DISABLE;
    if quiet != command
    {
        cfg.write16(bus, dev, func, COMMAND, quiet);
    }
    true
}

/// What a removal job did ([`remove`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Removal
{
    /// The records marked removed.
    pub functions: usize,
    /// The held BAR spans returned to the apertures, or, with the spans
    /// returned before it, why the rest stay held.
    pub returned: Result<usize, (usize, CarveError)>,
}

/// The removal job of `slot`, in its order: withdraw the driver of each
/// live record behind the slot (`withdraw`, given the function's address and
/// the held BAR pages, into which the withdrawal returns the BAR caps of its
/// driver's device); then turn off each one's memory decode (`quiesce`), so
/// it no longer answers at its BARs; then move every span of the held BAR
/// pages inside a BAR span of one of them ([`bar_spans`]) to the apertures
/// `free`, merged there with each adjacent span through `merge`
/// ([`return_bars`]); then mark each record removed. The slot's port is on
/// the bus above it and is not one of them. The caller powers the slot off
/// once this returns.
pub fn remove<S: Copy>(
    slot: &Slot,
    records: &mut PciRecords,
    held: &mut SpanTable<S>,
    free: &mut SpanTable<S>,
    mut withdraw: impl FnMut(Address, &mut SpanTable<S>),
    mut quiesce: impl FnMut(Address),
    merge: impl FnMut(&Span<S>, &Span<S>) -> Option<S>,
) -> Removal
{
    let behind = |records: &PciRecords, index: usize| {
        records
            .devices()
            .get(index)
            .filter(|d| {
                records.state(index) != Some(RecordState::Removed) && slot.holds(address(d))
            })
            .copied()
    };
    let count = records.devices().len();
    for index in 0..count
    {
        if let Some(device) = behind(records, index)
        {
            withdraw(address(&device), held);
        }
    }
    for index in 0..count
    {
        if let Some(device) = behind(records, index)
        {
            quiesce(address(&device));
        }
    }
    let returned = return_bars(
        held,
        free,
        |base, end| {
            (0..count).any(|index| {
                behind(records, index).is_some_and(|d| {
                    bar_spans(&d).any(|(b, len)| b <= base && end <= b.saturating_add(len))
                })
            })
        },
        merge,
    );
    let mut functions = 0usize;
    for index in 0..count
    {
        if behind(records, index).is_some() && records.remove(index)
        {
            functions = functions.saturating_add(1);
        }
    }
    Removal {
        functions,
        returned,
    }
}

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::acpid::Bridges;
    use crate::resource::{CarveError, SpanTable, SplitError};
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
    fn a_slot_is_managed_on_the_osc_bit_or_the_platform_key()
    {
        let by_osc = SlotGrant::Manage(GrantBy::Osc);
        // q35 with ACPI PCI hotplug of the bridges off: 0x1f, managed at
        // once, whether the tables are known or not.
        assert_eq!(slot_grant(Some(osc(0x1F)), None), by_osc);
        assert_eq!(slot_grant(Some(osc(0x1F)), Some(false)), by_osc);
        // riscv64 virt: the platform key grants, whatever _OSC returned.
        let by_table = SlotGrant::Manage(GrantBy::PlatformTable);
        assert_eq!(slot_grant(Some(osc(0x1E)), Some(true)), by_table);
        assert_eq!(slot_grant(Some(failed_osc(0x1F)), Some(true)), by_table);
        assert_eq!(slot_grant(None, Some(true)), by_table);
        assert_eq!(slot_grant(Some(osc(0x1F)), Some(true)), by_table);
    }

    #[test]
    fn a_withheld_or_failed_osc_waits_for_the_tables()
    {
        // Default q35: 0x1e, native hotplug withheld; a failed _OSC grants
        // nothing either. Neither settles the slot while the tables are not
        // known, since a table read later may still grant.
        assert_eq!(slot_grant(Some(osc(0x1E)), None), SlotGrant::Wait);
        assert_eq!(slot_grant(Some(failed_osc(0x1F)), None), SlotGrant::Wait);
        // Once devmgr knows its tables grant nothing, the firmware drives
        // the slot.
        assert_eq!(
            slot_grant(Some(osc(0x1E)), Some(false)),
            SlotGrant::Firmware
        );
        assert_eq!(
            slot_grant(Some(failed_osc(0x1F)), Some(false)),
            SlotGrant::Firmware
        );
        // No _OSC result yet: nothing is decided but a table's grant.
        assert_eq!(slot_grant(None, None), SlotGrant::Wait);
        assert_eq!(slot_grant(None, Some(false)), SlotGrant::Wait);
    }

    #[test]
    fn a_grant_waits_while_the_cspace_headroom_is_refused()
    {
        let settling = [
            SlotGrant::Manage(GrantBy::Osc),
            SlotGrant::Manage(GrantBy::PlatformTable),
            SlotGrant::Firmware,
        ];
        for grant in settling
        {
            // Managing a slot, or leaving it to the firmware, keeps
            // capabilities, so neither is settled after a refused top-up.
            assert_eq!(held_grant(grant, || false), SlotGrant::Wait, "{grant:?}");
            assert_eq!(held_grant(grant, || true), grant, "{grant:?}");
        }
        // A slot with no grant yet keeps nothing and asks for no top-up.
        let asked = core::cell::Cell::new(false);
        let hold = || {
            asked.set(true);
            false
        };
        assert_eq!(held_grant(SlotGrant::Wait, hold), SlotGrant::Wait);
        assert!(!asked.get());
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

    /// Every range free: the windows alone bound a placement.
    const FREE: &[(u64, u64)] = &[(0, u64::MAX)];

    #[test]
    fn bars_are_placed_aligned_largest_first_in_the_free_ranges()
    {
        let mut requests = [None; MAX_BARS];
        requests[0] = Some(request(0, 0x10_0000));
        assert_eq!(
            bases(&assign(&requests, MEMORY, None, FREE).unwrap()),
            [(0, 0x8000_0000)]
        );
        // The first page is not free: the BAR goes at the next MiB.
        assert_eq!(
            bases(&assign(&requests, MEMORY, None, &[(0x8000_1000, 0x8020_0000)]).unwrap()),
            [(0, 0x8010_0000)]
        );
        // Two free ranges side by side are two caps: a BAR spanning both is
        // not placed across them.
        let halves = [(0x8000_0000, 0x8008_0000), (0x8008_0000, 0x8010_0000)];
        assert_eq!(
            assign(&requests, MEMORY, None, &halves),
            Err(Unplaced::NoRoom(0))
        );
        // Nothing free, nothing placed.
        assert_eq!(
            assign(&requests, MEMORY, None, &[]),
            Err(Unplaced::NoRoom(0))
        );
        // The largest goes first, at the window's base; the smaller after it.
        requests[1] = Some(request(1, 0x1000));
        requests[2] = Some(request(2, 0x10_0000));
        requests[0] = Some(request(0, 0x1000));
        assert_eq!(
            bases(&assign(&requests, MEMORY, None, FREE).unwrap()),
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
            bases(&assign(&one, shifted, None, FREE).unwrap()),
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
            bases(&assign(&requests, MEMORY, None, FREE).unwrap()),
            [(0, 0x8000_0000), (1, 0x8000_1000)]
        );
        // A window of one page holds one sub-page BAR, not two.
        requests[1] = Some(request(1, 0x100));
        let page = Some(Window {
            base: 0x8000_0000,
            end: 0x8000_1000,
        });
        assert_eq!(
            assign(&requests, page, None, FREE),
            Err(Unplaced::NoRoom(1))
        );
    }

    #[test]
    fn bars_that_do_not_fit_are_refused_whole()
    {
        let mut requests = [None; MAX_BARS];
        requests[0] = Some(request(0, 0x40_0000));
        assert_eq!(
            assign(&requests, MEMORY, None, FREE),
            Err(Unplaced::NoRoom(0))
        );
        requests[0] = Some(request(0, 0x10_0000));
        requests[1] = Some(request(1, 0x10_0000));
        requests[2] = Some(request(2, 0x10_0000));
        assert_eq!(
            assign(&requests, MEMORY, None, FREE),
            Err(Unplaced::NoRoom(2))
        );
        assert_eq!(
            assign(&requests, None, None, FREE),
            Err(Unplaced::NoWindow(0))
        );
        requests[1] = Some(request(1, 0x3000));
        assert_eq!(
            assign(&requests, MEMORY, None, FREE),
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
            bases(&assign(&requests, MEMORY, prefetchable, FREE).unwrap()),
            [(0, 0x8000_0000), (2, 0x8_0000_0000)]
        );
        // With the prefetchable window off, or full, it goes in the other.
        assert_eq!(
            bases(&assign(&requests, MEMORY, None, FREE).unwrap()),
            [(0, 0x8010_0000), (2, 0x8000_0000)]
        );
        let full = [(0x8000_0000, 0x8020_0000)];
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
            assign(&narrow, None, prefetchable, FREE),
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
        let placed = assign(&requests, slot.memory, slot.prefetchable, FREE).unwrap();
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
        // devmgr holds none of the window: the 1 MiB BAR has no room, and
        // nothing is written.
        let Found::Unplaced(device, why) = place(&space, &slot, (1, 0, 0), &[])
        else
        {
            panic!("a BAR with no room was placed");
        };
        assert_eq!(why, Unplaced::NoRoom(0));
        assert_eq!(device.bar_phys[0], 0);
        assert_eq!(space.read32(1, 0, 0, BAR0), 0);
        // With the window free it is placed at the window's base.
        let Found::Ready(device) = place(&space, &slot, (1, 0, 0), &[(window.base, window.end)])
        else
        {
            panic!("a BAR that fits was not placed");
        };
        assert_eq!(device.bar_phys[0], window.base);
        assert!(matches!(
            place(&space, &slot, (1, 0, 1), FREE),
            Found::Absent
        ));
        // A port's own window is beside the point: a type-1 function is
        // returned as read, its windows unprogrammed.
        space.add((1, 0, 2), Q35_ROOT_PORT);
        let Found::Ready(bridge) = place(&space, &slot, (1, 0, 2), FREE)
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

    /// The two halves `(base, at)` and `(at, end)` of a split range.
    type SplitHalves = ((u64, u64), (u64, u64));

    /// A model of `SYS_MMIO_SPLIT`: a cap is its `(base, end)`.
    fn split_model(span: &Span<(u64, u64)>, at: u64) -> Result<SplitHalves, SplitError>
    {
        let (b, e) = span.slot;
        if at <= b || at >= e
        {
            return Err(SplitError::OutOfRange);
        }
        Ok(((b, at), (at, e)))
    }

    /// A model of `SYS_MMIO_MERGE` over [`split_model`]'s caps: two
    /// adjacent caps join into one.
    fn merge_model(lower: &Span<(u64, u64)>, upper: &Span<(u64, u64)>) -> Option<(u64, u64)>
    {
        (lower.slot.1 == upper.slot.0).then_some((lower.slot.0, upper.slot.1))
    }

    fn covered(table: &SpanTable<(u64, u64)>) -> Vec<(u64, u64)>
    {
        table.spans().iter().map(|s| (s.base, s.end)).collect()
    }

    #[test]
    fn free_ranges_are_the_held_spans_inside_the_windows_in_whole_pages()
    {
        let space = Space::default();
        space.add((0, 3, 0), Q35_ROOT_PORT);
        let mut slot = found(&space)[0];
        slot.memory = Some(Window {
            base: 0x8000_0000,
            end: 0x8020_0000,
        });
        slot.prefetchable = Some(Window {
            base: 0x8_0000_0000,
            end: 0x8_0010_0000,
        });
        let mut table = SpanTable::new();
        for (base, end) in [
            // Below the window, and across its base.
            (0x7000_0000, 0x7000_1000),
            (0x7FFF_F000, 0x8000_0800),
            // Two neighbours inside it, kept apart.
            (0x8000_2000, 0x8001_0000),
            (0x8001_0000, 0x8002_0000),
            // Across the window's end, its first page partly held.
            (0x801F_F800, 0x8030_0000),
            // The prefetchable window, whole.
            (0x8_0000_0000, 0x8_0010_0000),
        ]
        {
            assert!(table.insert((base, end), base, end - base).unwrap());
        }
        let mut free = Vec::new();
        free_ranges(table.spans(), &slot, &mut free).unwrap();
        assert_eq!(
            free,
            [
                (0x8000_2000, 0x8001_0000),
                (0x8001_0000, 0x8002_0000),
                (0x8_0000_0000, 0x8_0010_0000)
            ]
        );
        // A closed window frees nothing.
        slot.memory = None;
        slot.prefetchable = None;
        free.clear();
        free_ranges(table.spans(), &slot, &mut free).unwrap();
        assert_eq!(free, []);
    }

    #[test]
    fn a_placed_bar_is_held_whole_pages_and_no_longer_free()
    {
        let space = Space::default();
        add_edu(&space, (1, 0, 0));
        let mut edu = crate::scan::function(&space, 0, 1, 0, 0).unwrap();
        edu.bar_phys[0] = 0x8010_0000;
        assert_eq!(
            bar_spans(&edu).collect::<Vec<_>>(),
            [(0x8010_0000, 0x10_0000)]
        );
        // A sub-page BAR is held as its whole page; an unassigned BAR not at all.
        edu.bar_size[0] = 0x100;
        edu.bar_phys[0] = 0x8000_0100;
        assert_eq!(bar_spans(&edu).collect::<Vec<_>>(), [(0x8000_0000, 0x1000)]);
        edu.bar_phys[0] = 0;
        assert_eq!(bar_spans(&edu).count(), 0);
    }

    #[test]
    fn placement_takes_only_what_the_apertures_hold_and_a_failure_changes_nothing()
    {
        let space = Space::default();
        space.add((0, 3, 0), Q35_ROOT_PORT);
        add_edu(&space, (1, 0, 0));
        let slot = found(&space)[0];
        let window = slot.memory.unwrap();
        let mut apertures = SpanTable::new();
        assert!(
            apertures
                .insert(
                    (window.base, window.end),
                    window.base,
                    window.end - window.base
                )
                .unwrap()
        );
        let mut held = SpanTable::new();
        // acpid was granted the window's first page, carved out of the
        // apertures: the BAR is placed past it.
        let granted = apertures
            .carve(window.base, PAGE, PAGE, split_model)
            .unwrap();
        assert_eq!(granted, (window.base, window.base + PAGE));
        let mut free = Vec::new();
        free_ranges(apertures.spans(), &slot, &mut free).unwrap();
        let Found::Ready(device) = place(&space, &slot, (1, 0, 0), &free)
        else
        {
            panic!("a BAR that fits was not placed");
        };
        let bar = device.bar_phys[0];
        assert_eq!(bar, window.base + 0x10_0000);
        // Held at placement: the BAR's pages move out of the apertures.
        let spans: Vec<(u64, u64)> = bar_spans(&device).collect();
        apertures
            .move_all(&mut held, &spans, PAGE, split_model, merge_model)
            .unwrap();
        assert_eq!(covered(&held), [(bar, bar + 0x10_0000)]);
        // The mirror: a region grant of a page under the BAR finds no
        // aperture to carve it from.
        assert_eq!(
            apertures.carve(bar + 0x1000, PAGE, PAGE, split_model),
            Err(CarveError::NotCovered)
        );
        // A second function finds no room: the window's other free ranges are
        // a page short of a MiB below the BAR, and nothing above it. It is
        // left unwritten, and the tables as they were.
        add_edu(&space, (1, 0, 1));
        let before = (covered(&apertures), covered(&held));
        free.clear();
        free_ranges(apertures.spans(), &slot, &mut free).unwrap();
        assert!(matches!(
            place(&space, &slot, (1, 0, 1), &free),
            Found::Unplaced(_, Unplaced::NoRoom(0))
        ));
        assert_eq!(space.read32(1, 0, 1, BAR0), 0);
        assert_eq!((covered(&apertures), covered(&held)), before);
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
        assert_eq!(
            next(SlotState::Empty, 0, false),
            (SlotState::Empty, Action::None)
        );
        assert_eq!(
            next(SlotState::Empty, plugged, false),
            (SlotState::Empty, Action::PowerUp)
        );
        assert_eq!(
            next(SlotState::Empty, present, false),
            (SlotState::Empty, Action::PowerUp)
        );
        assert_eq!(
            next(SlotState::Occupied, present, false),
            (SlotState::Occupied, Action::None)
        );
        // A link change with the link still up is no removal.
        assert_eq!(
            next(SlotState::Occupied, present | SLOTSTA_LINK_CHANGED, false),
            (SlotState::Occupied, Action::None)
        );
        assert_eq!(
            next(SlotState::Failed, present, false),
            (SlotState::Failed, Action::None)
        );
        assert_eq!(
            next(SlotState::Failed, 0, false),
            (SlotState::Empty, Action::None)
        );
        assert!(present_reads(present) && !present_reads(0) && !present_reads(u16::MAX));
        assert!(link_changed(SLOTSTA_LINK_CHANGED) && !link_changed(u16::MAX));
    }

    #[test]
    fn a_recorded_slot_is_taken_over_occupied_so_a_card_gone_meanwhile_is_removed()
    {
        // The recorded card left while the slot's grant waited: the first
        // poll reads it gone and posts its removal.
        let recorded = initial(Behind::Recorded);
        assert_eq!(recorded, SlotState::Occupied);
        assert_eq!(
            next(recorded, 0, false),
            (SlotState::Removing { asked: false }, Action::Remove)
        );
        assert_eq!(
            next(recorded, SLOTSTA_PRESENT, false),
            (SlotState::Occupied, Action::None)
        );
        // Nothing recorded: a card present is brought up on the first poll.
        assert_eq!(
            next(initial(Behind::Nothing), SLOTSTA_PRESENT, false),
            (SlotState::Empty, Action::PowerUp)
        );
    }

    #[test]
    fn a_card_replaced_before_take_over_is_removed_and_then_added()
    {
        let space = Space::default();
        add_edu(&space, (1, 0, 0));
        let edu = crate::scan::function(&space, 0, 1, 0, 0).unwrap();
        assert!(same_function(&space, &edu));
        // Another card in its place: pci-testdev (1b36:0005), of another
        // identity; then none at all.
        let other = Space::default();
        other.add((1, 0, 0), &[0x0005_1b36, 0, 0x00ff_0000, 0]);
        assert!(!same_function(&other, &edu));
        assert!(!same_function(&Space::default(), &edu));
        // The same card of another revision, or of another subsystem.
        let revised = Space::default();
        revised.add((1, 0, 0), &[0x11e8_1234, 0, 0x00ff_0011, 0]);
        assert!(!same_function(&revised, &edu));
        let mut resold = edu;
        resold.subsystem_vendor ^= 1;
        assert!(!same_function(&space, &resold));
        // A card of the same identity is not told apart from it.
        let twin = Space::default();
        add_edu(&twin, (1, 0, 0));
        assert!(same_function(&twin, &edu));

        // The slot is taken over replaced: the first poll removes the recorded
        // card, the card present asked for, and once the removal completes
        // the next poll brings it up. Read gone, it is only removed.
        let replaced = initial(Behind::Replaced);
        assert_eq!(replaced, SlotState::Replaced);
        let (removing, action) = next(replaced, SLOTSTA_PRESENT, false);
        assert_eq!(
            (removing, action),
            (SlotState::Removing { asked: true }, Action::Remove)
        );
        assert_eq!(
            removal_cause(replaced, SLOTSTA_PRESENT, false),
            "its card was removed or replaced while the slot's grant waited"
        );
        let after = completed(removing, SLOTSTA_PRESENT);
        assert_eq!(after, SlotState::Empty);
        assert_eq!(
            next(after, SLOTSTA_PRESENT, false),
            (SlotState::Empty, Action::PowerUp)
        );
        assert_eq!(
            next(replaced, 0, false),
            (SlotState::Removing { asked: false }, Action::Remove)
        );
        // A port that does not answer changes nothing.
        assert_eq!(next(replaced, u16::MAX, false), (replaced, Action::None));
    }

    #[test]
    fn a_failed_slot_whose_card_is_swapped_or_asked_for_is_powered_up_again()
    {
        let present = SLOTSTA_PRESENT;
        assert_eq!(
            next(SlotState::Failed, present | SLOTSTA_PRESENCE_CHANGED, false),
            (SlotState::Failed, Action::PowerUp)
        );
        assert_eq!(
            next(SlotState::Failed, present | SLOTSTA_BUTTON, false),
            (SlotState::Failed, Action::PowerUp)
        );
        // A change that leaves no card present empties the slot.
        assert_eq!(
            next(SlotState::Failed, SLOTSTA_PRESENCE_CHANGED, false),
            (SlotState::Empty, Action::None)
        );
    }

    fn present_reads(status: u16) -> bool
    {
        super::present(status)
    }

    #[test]
    fn the_removal_states_follow_the_button_its_abort_window_and_the_card()
    {
        let present = SLOTSTA_PRESENT;
        let pressed = present | SLOTSTA_BUTTON;
        let full = SlotState::Pressed {
            polls_left: ABORT_POLLS,
        };
        // A press blinks the indicator for the abort window.
        assert_eq!(
            next(SlotState::Occupied, pressed, false),
            (full, Action::Blink)
        );
        // The window counts down while the card stays and the button is not
        // pressed again, and the removal starts as it ends.
        let mut state = full;
        for _ in 1..ABORT_POLLS
        {
            let (to, action) = next(state, present, false);
            assert_eq!(action, Action::None);
            state = to;
        }
        assert_eq!(state, SlotState::Pressed { polls_left: 1 });
        let removing = SlotState::Removing { asked: false };
        assert_eq!(next(state, present, false), (removing, Action::Remove));
        assert_eq!(
            removal_cause(state, present, false),
            "its attention button's abort window elapsed"
        );
        // A second press within the window cancels the removal.
        assert_eq!(
            next(full, pressed, false),
            (SlotState::Occupied, Action::Cancel)
        );
        // Surprise: the card leaves, or its link goes down, occupied or in
        // the window; a card that reads present with its presence changed was
        // replaced within the poll, and is asked for after the removal.
        for from in [SlotState::Occupied, full]
        {
            assert_eq!(
                next(from, present | SLOTSTA_PRESENCE_CHANGED, false),
                (SlotState::Removing { asked: true }, Action::Remove)
            );
            assert_eq!(
                removal_cause(from, present | SLOTSTA_PRESENCE_CHANGED, false),
                "card removed or replaced, or its link lost"
            );
            assert_eq!(
                next(from, SLOTSTA_PRESENCE_CHANGED, false),
                (removing, Action::Remove)
            );
            assert_eq!(
                next(from, present | SLOTSTA_LINK_CHANGED, true),
                (removing, Action::Remove)
            );
        }
        // Removing acts on no reading until the job completes, but keeps a
        // card inserted or a press, and keeps it whatever it reads after.
        let inserted = present | SLOTSTA_PRESENCE_CHANGED;
        let asked = SlotState::Removing { asked: true };
        for status in [0, present, SLOTSTA_PRESENCE_CHANGED, SLOTSTA_BUTTON]
        {
            assert_eq!(next(removing, status, false), (removing, Action::None));
            assert_eq!(next(asked, status, false), (asked, Action::None));
        }
        for status in [pressed, inserted]
        {
            assert_eq!(next(removing, status, false), (asked, Action::None));
        }
        // Completed: empty when no card is present, or when one was inserted
        // or the button pressed while removing or at the completion, so the
        // next poll powers the card up; else off, with the card the removal
        // removed. Any other state is left as it is.
        assert_eq!(completed(removing, present), SlotState::Off);
        assert_eq!(completed(asked, present), SlotState::Empty);
        assert_eq!(completed(removing, inserted), SlotState::Empty);
        assert_eq!(completed(removing, pressed), SlotState::Empty);
        assert_eq!(next(SlotState::Empty, present, false).1, Action::PowerUp);
        for from in [removing, asked]
        {
            assert_eq!(completed(from, 0), SlotState::Empty);
            assert_eq!(completed(from, SLOTSTA_PRESENCE_CHANGED), SlotState::Empty);
            assert_eq!(completed(from, u16::MAX), SlotState::Empty);
        }
        for other in [SlotState::Empty, SlotState::Occupied, SlotState::Off, full]
        {
            assert_eq!(completed(other, present), other);
        }
        // Off: powered up again by a press or a new insertion, empty once the
        // card is gone, else left off.
        assert_eq!(
            next(SlotState::Off, pressed, false),
            (SlotState::Off, Action::PowerUp)
        );
        assert_eq!(
            next(SlotState::Off, present | SLOTSTA_PRESENCE_CHANGED, false),
            (SlotState::Off, Action::PowerUp)
        );
        assert_eq!(
            next(SlotState::Off, present, false),
            (SlotState::Off, Action::None)
        );
        assert_eq!(
            next(SlotState::Off, 0, false),
            (SlotState::Empty, Action::None)
        );
        // A port that does not answer changes nothing.
        for state in [
            SlotState::Empty,
            SlotState::Occupied,
            SlotState::Failed,
            full,
            removing,
            asked,
            SlotState::Off,
        ]
        {
            assert_eq!(next(state, u16::MAX, true), (state, Action::None));
        }
    }

    #[test]
    fn a_removal_is_asked_for_again_only_by_a_changed_card_or_a_second_press()
    {
        let present = SLOTSTA_PRESENT;
        let pressed = present | SLOTSTA_BUTTON;
        let window = SlotState::Pressed {
            polls_left: ABORT_POLLS,
        };
        let removing = SlotState::Removing { asked: false };
        for from in [SlotState::Occupied, window]
        {
            // A pull is not asked for, whatever else the poll reads.
            assert_eq!(
                next(from, SLOTSTA_PRESENCE_CHANGED | SLOTSTA_BUTTON, false),
                (removing, Action::Remove)
            );
            // A card swapped in is.
            assert_eq!(
                next(from, present | SLOTSTA_PRESENCE_CHANGED, false),
                (SlotState::Removing { asked: true }, Action::Remove)
            );
        }
        // The link lost in the poll of a press: a first press asks for the
        // removal, so the card stays off after it; a second press in the
        // window asks to keep the card, so it is added again.
        let lost = pressed | SLOTSTA_LINK_CHANGED;
        assert_eq!(
            next(SlotState::Occupied, lost, true),
            (removing, Action::Remove)
        );
        assert_eq!(completed(removing, present), SlotState::Off);
        assert_eq!(
            next(window, lost, true),
            (SlotState::Removing { asked: true }, Action::Remove)
        );
    }

    /// The Q35 root port's Slot Capabilities: attention button, power
    /// controller, attention and power indicators, hot-plug surprise and
    /// capable.
    const CAPS: u32 = 0x000a_007b;

    /// What a slot does with a present card when it is powered off.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Unplug
    {
        /// QEMU's: the card is unplugged (`DEVICE_DELETED`).
        OnPowerOff,
        /// The card stays in.
        Never,
    }

    /// A native hotplug slot as QEMU models it (hw/pci/pcie.c), or one whose
    /// card stays in when it is powered off.
    struct ModelSlot
    {
        unplug: Unplug,
        control: u16,
        status: u16,
        card: bool,
        /// Cards QEMU unplugged (`DEVICE_DELETED`).
        deleted: usize,
    }

    impl ModelSlot
    {
        fn new(unplug: Unplug) -> Self
        {
            // Powered off, both indicators off, as the firmware leaves it.
            Self {
                unplug,
                control: 0x07C0,
                status: 0,
                card: false,
                deleted: 0,
            }
        }

        fn powered_off(control: u16) -> bool
        {
            control & SLOTCTL_POWER_OFF != 0
                && control & SLOTCTL_POWER_INDICATOR == SLOTCTL_POWER_INDICATOR_OFF
        }

        /// `device_add`: present, with the presence change and a button
        /// press latched.
        fn plug(&mut self)
        {
            self.card = true;
            self.status |= SLOTSTA_PRESENT | SLOTSTA_PRESENCE_CHANGED | SLOTSTA_BUTTON;
        }

        /// `device_del`: refused while the indicator blinks or the slot is
        /// powered off; else the button is pressed.
        fn device_del(&mut self) -> bool
        {
            let indicator = self.control & SLOTCTL_POWER_INDICATOR;
            if indicator == SLOTCTL_POWER_INDICATOR_BLINK
                || indicator == SLOTCTL_POWER_INDICATOR_OFF
                || !self.card
            {
                return false;
            }
            self.status |= SLOTSTA_BUTTON;
            true
        }

        fn press(&mut self)
        {
            self.status |= SLOTSTA_BUTTON;
        }

        /// A surprise removal: the card is pulled.
        fn pull(&mut self)
        {
            self.card = false;
            self.status = (self.status & !SLOTSTA_PRESENT) | SLOTSTA_PRESENCE_CHANGED;
        }

        /// A Slot Control write: QEMU unplugs a present card on the write
        /// that leaves the slot powered off from a state that was not.
        fn write(&mut self, value: u16)
        {
            let old = self.control;
            self.control = value;
            if self.unplug == Unplug::OnPowerOff
                && self.card
                && Self::powered_off(value)
                && !Self::powered_off(old)
            {
                self.card = false;
                self.deleted += 1;
                self.status = (self.status & !SLOTSTA_PRESENT) | SLOTSTA_PRESENCE_CHANGED;
            }
        }

        fn indicator(&self) -> u16
        {
            self.control & SLOTCTL_POWER_INDICATOR
        }

        /// Read Slot Status and clear its latches, as a poll does.
        fn read_and_clear(&mut self) -> u16
        {
            let status = self.status;
            self.status &= !SLOTSTA_LATCHES;
            status
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum ModelJob
    {
        Added,
        Removed,
    }

    /// The poller and the control thread of devmgr over one model slot: the
    /// jobs posted, in order, the completions, and the functions recorded.
    struct Model
    {
        slot: ModelSlot,
        state: SlotState,
        jobs: std::collections::VecDeque<ModelJob>,
        completions: usize,
        /// The live records behind the slot, each with its driver.
        live: usize,
        /// Functions withdrawn, each counted once.
        withdrawn: usize,
    }

    impl Model
    {
        fn new(unplug: Unplug) -> Self
        {
            Self {
                slot: ModelSlot::new(unplug),
                state: SlotState::Empty,
                jobs: std::collections::VecDeque::new(),
                completions: 0,
                live: 0,
                withdrawn: 0,
            }
        }

        /// One poller pass: power off each slot whose removal completed,
        /// then read, clear and act on Slot Status, as src/hotplug.rs does.
        fn poll(&mut self) -> Action
        {
            while self.completions > 0
            {
                self.completions -= 1;
                // Every function behind the slot is withdrawn before its power
                // goes off, and no job of it is left.
                assert_eq!(self.live, 0);
                let off = power_controller_off(self.slot.control, CAPS);
                self.slot.write(off);
                self.slot.write(indicator_off(off, CAPS));
                let status = self.slot.read_and_clear();
                self.state = completed(self.state, status);
            }
            let status = self.slot.read_and_clear();
            let (state, action) = next(self.state, status, false);
            self.state = match action
            {
                Action::None => state,
                Action::Blink =>
                {
                    self.slot.write(blink(self.slot.control, CAPS));
                    state
                }
                Action::Cancel =>
                {
                    self.slot.write(indicator_on(self.slot.control, CAPS));
                    state
                }
                Action::Remove =>
                {
                    self.jobs.push_back(ModelJob::Removed);
                    state
                }
                Action::PowerUp =>
                {
                    // The slot is reusable only once its previous occupant is
                    // withdrawn: no add follows a removal still pending.
                    assert!(!self.jobs.contains(&ModelJob::Removed));
                    assert_eq!(self.live, 0);
                    self.slot.write(power_on(self.slot.control, CAPS));
                    self.jobs.push_back(ModelJob::Added);
                    SlotState::Occupied
                }
            };
            action
        }

        /// The control thread: run every posted job, in order, each to its
        /// end. An add records the card's function if it is still there; a
        /// removal withdraws every live one and completes.
        fn control(&mut self)
        {
            while let Some(job) = self.jobs.pop_front()
            {
                match job
                {
                    ModelJob::Added =>
                    {
                        if self.slot.card
                        {
                            self.live += 1;
                        }
                    }
                    ModelJob::Removed =>
                    {
                        self.withdrawn += self.live;
                        self.live = 0;
                        self.completions += 1;
                    }
                }
            }
        }

        /// Poll until the abort window of a press ends; the action of the
        /// last poll.
        fn wait_window(&mut self) -> Action
        {
            let mut action = Action::None;
            for _ in 0..ABORT_POLLS
            {
                action = self.poll();
            }
            action
        }
    }

    #[test]
    fn a_button_removal_withdraws_then_powers_off_and_the_slot_takes_a_new_card()
    {
        let mut m = Model::new(Unplug::OnPowerOff);
        m.slot.plug();
        assert_eq!(m.poll(), Action::PowerUp);
        m.control();
        assert_eq!(
            (m.live, m.slot.indicator()),
            (1, SLOTCTL_POWER_INDICATOR_ON)
        );
        assert!(m.slot.device_del());
        assert_eq!(m.poll(), Action::Blink);
        assert_eq!(m.slot.indicator(), SLOTCTL_POWER_INDICATOR_BLINK);
        // QEMU refuses a second `device_del` while the indicator blinks.
        assert!(!m.slot.device_del());
        assert_eq!(m.wait_window(), Action::Remove);
        // Nothing is powered off before the control thread runs the job.
        assert_eq!(m.poll(), Action::None);
        assert!(m.slot.card);
        m.control();
        assert_eq!(m.withdrawn, 1);
        assert_eq!(m.poll(), Action::None);
        assert_eq!((m.slot.deleted, m.state), (1, SlotState::Empty));
        assert!(ModelSlot::powered_off(m.slot.control));
        // A card plugged again is brought up from empty.
        m.slot.plug();
        assert_eq!(m.poll(), Action::PowerUp);
        m.control();
        assert_eq!((m.live, m.withdrawn), (1, 1));
    }

    #[test]
    fn a_second_press_in_the_abort_window_keeps_the_card()
    {
        let mut m = Model::new(Unplug::OnPowerOff);
        m.slot.plug();
        m.poll();
        m.control();
        m.slot.press();
        assert_eq!(m.poll(), Action::Blink);
        assert_eq!(m.poll(), Action::None);
        m.slot.press();
        assert_eq!(m.poll(), Action::Cancel);
        assert_eq!(m.state, SlotState::Occupied);
        assert_eq!(m.slot.indicator(), SLOTCTL_POWER_INDICATOR_ON);
        for _ in 0..ABORT_POLLS
        {
            assert_eq!(m.poll(), Action::None);
        }
        assert!(m.jobs.is_empty());
        assert_eq!((m.live, m.slot.deleted), (1, 0));
    }

    #[test]
    fn a_surprise_removal_waits_for_its_job_before_a_new_card_is_taken()
    {
        let mut m = Model::new(Unplug::Never);
        m.slot.plug();
        m.poll();
        m.control();
        m.slot.pull();
        assert_eq!(m.poll(), Action::Remove);
        // A card inserted before the job ran is not brought up then, but
        // kept: no press is needed, so a slot with no attention button
        // brings it up too.
        m.slot.card = true;
        m.slot.status |= SLOTSTA_PRESENT | SLOTSTA_PRESENCE_CHANGED;
        assert_eq!(m.poll(), Action::None);
        assert_eq!(m.state, SlotState::Removing { asked: true });
        m.control();
        assert_eq!(m.withdrawn, 1);
        // Powered off, then the new card is powered up.
        assert_eq!(m.poll(), Action::PowerUp);
        m.control();
        assert_eq!((m.live, m.withdrawn, m.state), (1, 1, SlotState::Occupied));
        // A card swapped within one poll is removed, then added.
        m.slot.status |= SLOTSTA_PRESENT | SLOTSTA_PRESENCE_CHANGED;
        assert_eq!(m.poll(), Action::Remove);
        assert_eq!(m.state, SlotState::Removing { asked: true });
        m.control();
        assert_eq!(m.poll(), Action::PowerUp);
        m.control();
        assert_eq!((m.live, m.withdrawn, m.state), (1, 2, SlotState::Occupied));
        // A card inserted between the last poll and the power-off is kept the
        // same way.
        m.slot.pull();
        assert_eq!(m.poll(), Action::Remove);
        m.control();
        m.slot.card = true;
        m.slot.status |= SLOTSTA_PRESENT | SLOTSTA_PRESENCE_CHANGED;
        assert_eq!(m.poll(), Action::PowerUp);
        m.control();
        assert_eq!((m.live, m.withdrawn), (1, 3));
        // Pulled while off: empty.
        let mut off = Model::new(Unplug::Never);
        off.state = SlotState::Off;
        off.slot.card = true;
        off.slot.pull();
        assert_eq!(off.poll(), Action::None);
        assert_eq!(off.state, SlotState::Empty);
    }

    #[test]
    fn a_button_removal_of_a_card_that_stays_leaves_the_slot_off_until_asked()
    {
        let mut m = Model::new(Unplug::Never);
        m.slot.plug();
        m.poll();
        m.control();
        m.slot.press();
        assert_eq!(m.poll(), Action::Blink);
        assert_eq!(m.wait_window(), Action::Remove);
        m.control();
        // The card the removal removed is still in: powered off, and not
        // brought up again by its presence alone.
        assert_eq!(m.poll(), Action::None);
        assert_eq!((m.state, m.withdrawn), (SlotState::Off, 1));
        assert!(m.slot.card && ModelSlot::powered_off(m.slot.control));
        assert_eq!(m.poll(), Action::None);
        // A press asks for it again.
        m.slot.press();
        assert_eq!(m.poll(), Action::PowerUp);
        m.control();
        assert_eq!((m.live, m.state), (1, SlotState::Occupied));
    }

    #[test]
    fn a_removal_racing_an_add_runs_after_it_and_withdraws_what_it_recorded()
    {
        // The removal is asked for before the control thread ran the add.
        let mut m = Model::new(Unplug::OnPowerOff);
        m.slot.plug();
        assert_eq!(m.poll(), Action::PowerUp);
        assert!(m.slot.device_del());
        m.poll();
        assert_eq!(m.wait_window(), Action::Remove);
        assert_eq!(
            m.jobs.iter().copied().collect::<Vec<_>>(),
            [ModelJob::Added, ModelJob::Removed]
        );
        m.control();
        assert_eq!((m.live, m.withdrawn), (0, 1));
        m.poll();
        assert_eq!((m.slot.deleted, m.state), (1, SlotState::Empty));
        // The card is pulled before the add reads it: the add records
        // nothing, the removal withdraws nothing, and the slot is still
        // powered off.
        let mut m = Model::new(Unplug::OnPowerOff);
        m.slot.plug();
        m.poll();
        m.slot.pull();
        assert_eq!(m.poll(), Action::Remove);
        m.control();
        assert_eq!((m.live, m.withdrawn), (0, 0));
        m.poll();
        assert_eq!(m.state, SlotState::Empty);
        assert!(ModelSlot::powered_off(m.slot.control));
    }

    /// The configuration space, the slot, the records, the held BAR pages and
    /// the apertures.
    type Fixture = (
        Space,
        Slot,
        PciRecords,
        SpanTable<(u64, u64)>,
        SpanTable<(u64, u64)>,
    );

    /// The removal fixture: the Q35 root port at 00:03.0 with an `edu` behind
    /// it, its 1 MiB BAR placed at the window's base and held, as an add job
    /// leaves it, and the window's rest in the apertures.
    fn removal_fixture() -> Fixture
    {
        let space = Space::default();
        space.add((0, 3, 0), Q35_ROOT_PORT);
        add_edu(&space, (1, 0, 0));
        let slot = found(&space)[0];
        let window = slot.memory.unwrap();
        let mut free = SpanTable::new();
        free.insert(
            (window.base, window.end),
            window.base,
            window.end - window.base,
        )
        .unwrap();
        let mut ranges = Vec::new();
        free_ranges(free.spans(), &slot, &mut ranges).unwrap();
        let Found::Ready(edu) = place(&space, &slot, (1, 0, 0), &ranges)
        else
        {
            panic!("the edu was not placed");
        };
        space.write16(1, 0, 0, COMMAND, COMMAND_MEMORY | COMMAND_BUS_MASTER);
        let mut held = SpanTable::new();
        let spans: Vec<(u64, u64)> = bar_spans(&edu).collect();
        free.move_all(&mut held, &spans, PAGE, split_model, merge_model)
            .unwrap();
        let mut functions = Vec::new();
        scan(&space, 0, 0, 3, &mut functions).unwrap();
        let mut records = PciRecords::new(functions).unwrap();
        assert!(hold_port(&mut records, slot.port));
        assert_eq!(live(&records), 2);
        (space, slot, records, held, free)
    }

    fn live(records: &PciRecords) -> usize
    {
        (0..records.devices().len())
            .filter(|&i| records.state(i) != Some(RecordState::Removed))
            .count()
    }

    /// Every page of `window` is in exactly one of `tables`' spans, or in
    /// `out`; returns the bytes `tables` cover.
    fn each_page_once(window: Window, tables: &[&SpanTable<(u64, u64)>], out: &[(u64, u64)])
    -> u64
    {
        let mut pages = std::collections::BTreeMap::new();
        let mut add = |base: u64, end: u64| {
            let mut at = base;
            while at < end
            {
                *pages.entry(at).or_insert(0u32) += 1;
                at += PAGE;
            }
        };
        let mut covered = 0;
        for table in tables
        {
            for s in table.spans()
            {
                assert_eq!(s.slot, (s.base, s.end), "a span is the cap it records");
                add(s.base, s.end);
                covered += s.end - s.base;
            }
        }
        for &(base, end) in out
        {
            add(base, end);
        }
        let mut at = window.base;
        while at < window.end
        {
            assert_eq!(pages.get(&at), Some(&1), "page {at:#x}");
            at += PAGE;
        }
        covered
    }

    #[test]
    fn a_removal_withdraws_quiesces_and_returns_each_bar_page_once()
    {
        let (space, slot, mut records, mut held, mut free) = removal_fixture();
        let window = slot.memory.unwrap();
        let bar = (window.base, window.base + 0x10_0000);
        // The bind carved the driver's cap on the BAR's first half; the rest
        // stays held.
        let cap = held.carve_span(bar.0, 0x8_0000, PAGE, split_model).unwrap();
        each_page_once(window, &[&held, &free], &[(cap.base, cap.end)]);
        let events = RefCell::new(Vec::new());
        let removal = remove(
            &slot,
            &mut records,
            &mut held,
            &mut free,
            |at, held| {
                events.borrow_mut().push(("withdraw", at));
                // The withdrawal gives the driver's cap back to the held pages.
                held.insert(cap.slot, cap.base, cap.end - cap.base).unwrap();
            },
            |at| {
                events.borrow_mut().push(("quiesce", at));
                assert!(quiesce(&space, (at.1, at.2, at.3)));
            },
            merge_model,
        );
        // The port is not behind its own slot; the edu is, withdrawn before it
        // is quiesced.
        assert_eq!(
            events.into_inner(),
            [("withdraw", (0, 1, 0, 0)), ("quiesce", (0, 1, 0, 0))]
        );
        assert_eq!(
            removal,
            Removal {
                functions: 1,
                returned: Ok(2),
            }
        );
        assert_eq!(covered(&held), []);
        assert_eq!(
            each_page_once(window, &[&free], &[]),
            window.end - window.base
        );
        let command = space.read16(1, 0, 0, COMMAND);
        assert_eq!(command & (COMMAND_MEMORY | COMMAND_BUS_MASTER), 0);
        assert_ne!(command & COMMAND_INTERRUPT_DISABLE, 0);
        assert_eq!(live(&records), 1);
        // A second removal of the slot finds nothing: no withdrawal, and no
        // page returned twice.
        let before = covered(&free);
        let again = remove(
            &slot,
            &mut records,
            &mut held,
            &mut free,
            |_, _| panic!("a removed function is withdrawn again"),
            |_| panic!("a removed function is quiesced again"),
            |_, _| panic!("nothing returned, nothing merged"),
        );
        assert_eq!(
            again,
            Removal {
                functions: 0,
                returned: Ok(0),
            }
        );
        assert_eq!(covered(&free), before);
    }

    /// The removal fixture's `edu` bound and removed: its bind carved the
    /// driver's cap on the BAR's first half and its MSI-X table's page from
    /// the second, leaving the BAR's held pages in two pieces; the withdrawal
    /// gives both caps back to the held BAR pages, merged inside the BAR's
    /// page span through `merge`, and the removal returns what is held to the
    /// apertures through `merge`. Returns the configuration space, the slot,
    /// and the apertures after the removal.
    fn removed_after_a_bind(
        merge: impl Fn(&Span<(u64, u64)>, &Span<(u64, u64)>) -> Option<(u64, u64)> + Copy,
    ) -> (Space, Slot, SpanTable<(u64, u64)>)
    {
        let (space, slot, mut records, mut held, mut free) = removal_fixture();
        let window = slot.memory.unwrap();
        let bar = bar_page_span(window.base, 0x10_0000);
        let cap = held.carve_span(bar.0, 0x8_0000, PAGE, split_model).unwrap();
        let table = held
            .carve_span(bar.0 + 0xC_0000, PAGE, PAGE, split_model)
            .unwrap();
        assert_eq!(
            covered(&held),
            [
                (bar.0 + 0x8_0000, bar.0 + 0xC_0000),
                (bar.0 + 0xC_1000, bar.1)
            ]
        );
        let removal = remove(
            &slot,
            &mut records,
            &mut held,
            &mut free,
            |_, held| {
                for c in [cap, table]
                {
                    assert!(
                        held.insert_merged(c.slot, c.base, c.end - c.base, bar, merge)
                            .unwrap()
                    );
                }
            },
            |at| {
                quiesce(&space, (at.1, at.2, at.3));
            },
            merge,
        );
        assert_eq!(removal.functions, 1);
        removal.returned.unwrap();
        assert_eq!(covered(&held), []);
        each_page_once(window, &[&free], &[]);
        (space, slot, free)
    }

    /// A function with QEMU's `edu` header and one 32-bit non-prefetchable
    /// BAR 0, unassigned, of the size the writable bits `mask` give.
    fn add_card(space: &Space, bdf: (u8, u8, u8), mask: u32)
    {
        add_edu(space, bdf);
        space.funcs.borrow_mut().get_mut(&bdf).unwrap().bar_masks[0] = mask;
    }

    #[test]
    fn a_card_added_after_a_removal_spans_the_pieces_the_removal_returned()
    {
        let (space, slot, mut free) = removed_after_a_bind(merge_model);
        let window = slot.memory.unwrap();
        // The BAR's pieces merged back into one held span, returned whole, and
        // merged with the window's rest: the window is one span again.
        assert_eq!(covered(&free), [(window.base, window.end)]);
        // A card whose 2 MiB BAR takes the whole window, across the BAR the
        // removal returned and the rest, is placed and held.
        add_card(&space, (1, 0, 0), 0xFFE0_0000);
        let mut ranges = Vec::new();
        free_ranges(free.spans(), &slot, &mut ranges).unwrap();
        let Found::Ready(card) = place(&space, &slot, (1, 0, 0), &ranges)
        else
        {
            panic!("a BAR the free window holds was not placed");
        };
        assert_eq!(card.bar_phys[0], window.base);
        let spans: Vec<(u64, u64)> = bar_spans(&card).collect();
        assert_eq!(spans, [(window.base, window.end - window.base)]);
        let mut held = SpanTable::new();
        free.move_all(&mut held, &spans, PAGE, split_model, merge_model)
            .unwrap();
        assert_eq!(covered(&held), [(window.base, window.end)]);
        assert_eq!(covered(&free), []);
    }

    #[test]
    fn pieces_the_kernel_does_not_merge_place_no_bar_across_them()
    {
        // Every merge refused, as for caps that are not derivation siblings:
        // the window comes back in the pieces it was carved into, and a BAR
        // larger than each does not fit, although the window is free.
        let (space, slot, free) = removed_after_a_bind(|_, _| None);
        let window = slot.memory.unwrap();
        assert_eq!(covered(&free).len(), 5);
        add_card(&space, (1, 0, 0), 0xFFE0_0000);
        let mut ranges = Vec::new();
        free_ranges(free.spans(), &slot, &mut ranges).unwrap();
        assert!(matches!(
            place(&space, &slot, (1, 0, 0), &ranges),
            Found::Unplaced(_, Unplaced::NoRoom(0))
        ));
        each_page_once(window, &[&free], &[]);
    }

    #[test]
    fn a_driver_cap_not_given_back_is_lost_and_never_returned()
    {
        // The withdrawal could not revoke the driver's copies: the cap is
        // deleted, not given back, and the removal neither waits for it nor
        // returns its pages.
        let (space, slot, mut records, mut held, mut free) = removal_fixture();
        let window = slot.memory.unwrap();
        let cap = held
            .carve_span(window.base, 0x8_0000, PAGE, split_model)
            .unwrap();
        let mut asked = 0;
        let removal = remove(
            &slot,
            &mut records,
            &mut held,
            &mut free,
            |_, _| asked += 1,
            |at| {
                quiesce(&space, (at.1, at.2, at.3));
            },
            merge_model,
        );
        assert_eq!(asked, 1);
        assert_eq!(removal.functions, 1);
        assert_eq!(removal.returned, Ok(1));
        each_page_once(window, &[&held, &free], &[(cap.base, cap.end)]);
        assert_eq!(covered(&held), []);
    }

    #[test]
    fn a_removal_during_a_drivers_dma_setup_leaves_its_mapping_refused()
    {
        use crate::dma::{Confinement, DmaTable};
        use ipc::devmgr_dma_labels::{ACCESS_DEVICE_READ, ACCESS_DEVICE_WRITE};
        let (space, slot, mut records, mut held, mut free) = removal_fixture();
        let badge = 7;
        let mut table = DmaTable::new();
        let confinement = Confinement::Domain {
            handle: 3,
            limit: u64::MAX,
            interrupt_range: false,
        };
        table.register(badge, confinement, &[]).unwrap();
        // The driver is mid-way through a mapping when the removal runs.
        let pending = table
            .reserve(
                badge,
                1,
                PAGE,
                ACCESS_DEVICE_READ | ACCESS_DEVICE_WRITE,
                None,
            )
            .unwrap();
        let mut faults = crate::dma::FaultCounts::new();
        let rid = 0x0100;
        faults.track(rid).unwrap();
        let removal = remove(
            &slot,
            &mut records,
            &mut held,
            &mut free,
            |_, _| {
                assert!(table.withdraw(badge).is_some());
                faults.untrack(rid);
            },
            |at| {
                quiesce(&space, (at.1, at.2, at.3));
            },
            merge_model,
        );
        assert_eq!(removal.functions, 1);
        // The mapping's commit is refused, and the device, gone, has none.
        assert!(!table.commit(badge, pending.device_addr));
        assert!(table.withdraw(badge).is_none());
        // A fault the removed device still raises is not charged, and a card
        // added at its address starts at zero.
        assert!(!faults.record(rid, 0x1000));
        faults.track(rid).unwrap();
        assert_eq!(faults.count(rid), (0, 0));
    }

    #[test]
    fn quiesce_turns_off_decode_and_mastering_and_leaves_an_absent_function()
    {
        let space = Space::default();
        add_edu(&space, (1, 0, 0));
        space.write16(1, 0, 0, COMMAND, COMMAND_MEMORY | COMMAND_BUS_MASTER | 1);
        assert!(quiesce(&space, (1, 0, 0)));
        assert_eq!(
            space.read16(1, 0, 0, COMMAND),
            COMMAND_INTERRUPT_DISABLE | 1
        );
        assert!(!quiesce(&space, (2, 0, 0)));
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
