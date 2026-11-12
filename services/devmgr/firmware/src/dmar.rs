// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/devmgr/firmware/src/dmar.rs

//! The ACPI DMA Remapping table (DMAR): the VT-d remapping hardware units
//! (DRHDs), the reserved memory regions (RMRRs) firmware expects a device to
//! keep reaching, which unit translates a given PCI function, whether the
//! platform remaps interrupts, and the source ID each I/O APIC's interrupt
//! requests carry.
//!
//! devmgr discovers each unit here, hands the unit's register range and the
//! functions it covers to the VT-d IOMMU driver, and reads the RMRRs that name
//! a DMA-capable device before it binds one, to identity-map them in the
//! device's domain; with interrupt remapping on, the remapping entry of a
//! wired line accepts only its I/O APIC's source ID
//! (`docs/device-management.md` § IOMMU Discovery and Programming). Layouts
//! are the Intel VT-d specification's (rev. 4.1, chapter 8, "BIOS
//! Considerations"). Operates on a caller-mapped byte slice of the table, as
//! [`crate::acpi`] does. No alloc.

use crate::acpi::{SDT_HDR_LEN, sdt_length, sdt_signature};
use crate::bytes::{read_u8, read_u16, read_u64};

// ── Layout constants ──────────────────────────────────────────────────

/// First remapping structure: after the header, the host address width (u8),
/// the flags (u8), and 10 reserved bytes (VT-d section 8.1).
const DMAR_STRUCTURES_OFF: usize = SDT_HDR_LEN + 12;
/// Offset of the host address width, encoded as the width minus one; only
/// the tests' table builder writes it, since devmgr reads no DMA width from
/// the table (a unit's own `CAP` register gives its width).
#[cfg(test)]
const DMAR_OFF_HAW: usize = SDT_HDR_LEN;
/// A remapping structure's header: type (u16), length (u16).
const STRUCTURE_HDR_LEN: usize = 4;

/// Remapping structure type of a DMA Remapping Hardware Unit Definition
/// (section 8.3).
const TYPE_DRHD: u16 = 0;
/// Remapping structure type of a Reserved Memory Region Reporting structure
/// (section 8.4).
const TYPE_RMRR: u16 = 1;

/// DRHD: flags (u8) at 4, size (u8) at 5, segment (u16) at 6, register base
/// (u64) at 8, device scopes from 16.
const DRHD_SCOPES_OFF: usize = 16;
/// DRHD flag: the unit translates every function of its segment that no
/// other unit's scope names.
const DRHD_FLAG_INCLUDE_PCI_ALL: u8 = 1 << 0;
/// RMRR: reserved (u16) at 4, segment (u16) at 6, base (u64) at 8, limit
/// (u64) at 16, device scopes from 24.
const RMRR_SCOPES_OFF: usize = 24;

/// A device scope's header: type (u8), length (u8), flags (u8), reserved
/// (u8), enumeration ID (u8), start bus (u8); the path's (device, function)
/// pairs follow (section 8.3.1).
const SCOPE_PATH_OFF: usize = 6;
/// Device scope type of a PCI endpoint.
const SCOPE_PCI_ENDPOINT: u8 = 1;
/// Device scope type of a PCI sub-hierarchy: a bridge and every function
/// below it.
const SCOPE_PCI_SUB_HIERARCHY: u8 = 2;
/// Device scope type of an I/O APIC: its enumeration ID is the I/O APIC's
/// ID, and its path names the source ID of its interrupt requests.
const SCOPE_IO_APIC: u8 = 3;

/// Offset of the DMAR's flags (u8), after the host address width.
const DMAR_OFF_FLAGS: usize = SDT_HDR_LEN + 1;
/// DMAR flag: the platform supports interrupt remapping.
const DMAR_FLAG_INTR_REMAP: u8 = 1 << 0;
/// DMAR flag: the firmware asks the system not to use x2APIC destinations.
const DMAR_FLAG_X2APIC_OPT_OUT: u8 = 1 << 1;

/// Hops a device scope's path may hold: one per bridge between the start bus
/// and the function. Eight covers any topology a PCI Express root complex
/// builds in practice; a deeper path is skipped as malformed.
pub const MAX_SCOPE_PATH: usize = 8;

// ── Types ─────────────────────────────────────────────────────────────

/// A PCI function, by bus, device, and function number, in one segment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bdf
{
    pub bus: u8,
    pub device: u8,
    pub function: u8,
}

/// One device scope entry naming PCI functions: the start bus and the path
/// of (device, function) hops from it, the last hop naming the function
/// itself (an endpoint) or the bridge whose whole hierarchy is named (a
/// sub-hierarchy).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PciScope
{
    /// Whether the scope names the bridge and every function below it.
    pub sub_hierarchy: bool,
    pub start_bus: u8,
    path: [(u8, u8); MAX_SCOPE_PATH],
    path_len: usize,
}

impl PciScope
{
    /// The (device, function) hops, from the start bus to the named
    /// function or bridge.
    #[must_use]
    pub fn path(&self) -> &[(u8, u8)]
    {
        self.path.get(..self.path_len).unwrap_or_default()
    }

    /// The function the scope names: the last hop, on the bus the hops
    /// before it lead to. `secondary_bus` reads the secondary bus number of
    /// the bridge at a `Bdf` from its configuration space; `None` when a
    /// hop is not a readable bridge, which leaves the scope unresolved.
    pub fn resolve(&self, mut secondary_bus: impl FnMut(Bdf) -> Option<u8>) -> Option<Bdf>
    {
        let (&(device, function), bridges) = self.path().split_last()?;
        let mut bus = self.start_bus;
        for &(d, f) in bridges
        {
            bus = secondary_bus(Bdf {
                bus,
                device: d,
                function: f,
            })?;
        }
        Some(Bdf {
            bus,
            device,
            function,
        })
    }
}

/// One VT-d remapping hardware unit (DRHD).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DrhdUnit
{
    /// PCI segment whose functions the unit translates.
    pub segment: u16,
    /// Physical base of the unit's register set; page-aligned.
    pub register_base: u64,
    /// Pages of the register set: `2^size` for the table's size field.
    pub register_pages: u64,
    /// Whether the unit translates every function of its segment that no
    /// other unit's scope names.
    pub include_pci_all: bool,
    /// Byte range of the unit's device scopes inside the table.
    scopes: (usize, usize),
}

/// One reserved memory region (RMRR) a set of functions keeps reaching after
/// the firmware hands over.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rmrr
{
    pub segment: u16,
    /// First byte of the region.
    pub base: u64,
    /// Last byte of the region (inclusive).
    pub limit: u64,
    scopes: (usize, usize),
}

/// A remapping structure of interest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Structure
{
    Drhd(DrhdUnit),
    Rmrr(Rmrr),
}

// ── Walkers ───────────────────────────────────────────────────────────

/// The remapping structures of a DMAR, bounded by its reported length and
/// the slice. The walk ends at a structure shorter than its header or running
/// past the bound, so a truncated or malformed table yields the structures
/// before the bad one. A DRHD or RMRR too short for its fixed fields is
/// skipped, as is a structure of another type.
fn structures(dmar: &[u8]) -> impl Iterator<Item = Structure> + '_
{
    let end = if sdt_signature(dmar) == *b"DMAR"
    {
        sdt_length(dmar).map_or(0, |len| (len as usize).min(dmar.len()))
    }
    else
    {
        0
    };
    let mut off = DMAR_STRUCTURES_OFF;
    core::iter::from_fn(move || {
        while off.saturating_add(STRUCTURE_HDR_LEN) <= end
        {
            let kind = read_u16(dmar, off);
            let len = usize::from(read_u16(dmar, off.saturating_add(2)));
            if len < STRUCTURE_HDR_LEN || off.saturating_add(len) > end
            {
                off = end;
                return None;
            }
            let at = off;
            off = off.saturating_add(len);
            match kind
            {
                TYPE_DRHD if len >= DRHD_SCOPES_OFF =>
                {
                    let size = read_u8(dmar, at.saturating_add(5)) & 0x0f;
                    return Some(Structure::Drhd(DrhdUnit {
                        segment: read_u16(dmar, at.saturating_add(6)),
                        register_base: read_u64(dmar, at.saturating_add(8)),
                        register_pages: 1u64 << size,
                        include_pci_all: read_u8(dmar, at.saturating_add(4))
                            & DRHD_FLAG_INCLUDE_PCI_ALL
                            != 0,
                        scopes: (at.saturating_add(DRHD_SCOPES_OFF), at.saturating_add(len)),
                    }));
                }
                TYPE_RMRR if len >= RMRR_SCOPES_OFF =>
                {
                    return Some(Structure::Rmrr(Rmrr {
                        segment: read_u16(dmar, at.saturating_add(6)),
                        base: read_u64(dmar, at.saturating_add(8)),
                        limit: read_u64(dmar, at.saturating_add(16)),
                        scopes: (at.saturating_add(RMRR_SCOPES_OFF), at.saturating_add(len)),
                    }));
                }
                _ =>
                {}
            }
        }
        None
    })
}

/// The DMAR's remapping hardware units, in table order. A unit whose register
/// base is zero or not page-aligned is skipped.
pub fn drhd_units(dmar: &[u8]) -> impl Iterator<Item = DrhdUnit> + '_
{
    structures(dmar).filter_map(|s| match s
    {
        Structure::Drhd(u) if u.register_base != 0 && u.register_base.trailing_zeros() >= 12 =>
        {
            Some(u)
        }
        _ => None,
    })
}

/// The DMAR's reserved memory regions, in table order. A region whose limit
/// is below its base is skipped.
pub fn rmrrs(dmar: &[u8]) -> impl Iterator<Item = Rmrr> + '_
{
    structures(dmar).filter_map(|s| match s
    {
        Structure::Rmrr(r) if r.limit >= r.base => Some(r),
        _ => None,
    })
}

/// The device scopes in the byte range `scopes` of `dmar`, each as its type,
/// its enumeration ID, and its start bus and path, skipping ones whose path
/// is empty, odd, or longer than [`MAX_SCOPE_PATH`]. The walk ends at a
/// scope shorter than its header or running past the range.
fn device_scopes(
    dmar: &[u8],
    scopes: (usize, usize),
) -> impl Iterator<Item = (u8, u8, PciScope)> + '_
{
    let (mut off, end) = scopes;
    let end = end.min(dmar.len());
    core::iter::from_fn(move || {
        while off.saturating_add(SCOPE_PATH_OFF) <= end
        {
            let kind = read_u8(dmar, off);
            let len = usize::from(read_u8(dmar, off.saturating_add(1)));
            if len < SCOPE_PATH_OFF || off.saturating_add(len) > end
            {
                off = end;
                return None;
            }
            let at = off;
            off = off.saturating_add(len);
            let path_bytes = len.saturating_sub(SCOPE_PATH_OFF);
            let hops = path_bytes / 2;
            if !path_bytes.is_multiple_of(2) || hops == 0 || hops > MAX_SCOPE_PATH
            {
                continue;
            }
            let mut path = [(0u8, 0u8); MAX_SCOPE_PATH];
            for (i, hop) in path.iter_mut().take(hops).enumerate()
            {
                let p = at
                    .saturating_add(SCOPE_PATH_OFF)
                    .saturating_add(i.saturating_mul(2));
                *hop = (read_u8(dmar, p), read_u8(dmar, p.saturating_add(1)));
            }
            let scope = PciScope {
                sub_hierarchy: kind == SCOPE_PCI_SUB_HIERARCHY,
                start_bus: read_u8(dmar, at.saturating_add(5)),
                path,
                path_len: hops,
            };
            return Some((kind, read_u8(dmar, at.saturating_add(4)), scope));
        }
        None
    })
}

/// The PCI scopes in the byte range `scopes` of `dmar`, skipping scopes of
/// other types (I/O APIC, HPET, ACPI namespace devices), as
/// [`device_scopes`] reads them.
fn pci_scopes(dmar: &[u8], scopes: (usize, usize)) -> impl Iterator<Item = PciScope> + '_
{
    device_scopes(dmar, scopes).filter_map(|(kind, _, scope)| {
        matches!(kind, SCOPE_PCI_ENDPOINT | SCOPE_PCI_SUB_HIERARCHY).then_some(scope)
    })
}

/// One I/O APIC a remapping unit's scope names: the I/O APIC's ID, as the
/// MADT gives it, and the path to the function whose source ID its
/// interrupt requests carry, which an interrupt remapping entry for one of
/// its lines verifies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IoApicScope
{
    pub segment: u16,
    pub id: u8,
    pub scope: PciScope,
}

impl IoApicScope
{
    /// The source ID (bus in bits 8..16, device and function below) of the
    /// I/O APIC's interrupt requests: its path resolved as
    /// [`PciScope::resolve`] resolves it, through `secondary_bus`.
    pub fn source_id(&self, secondary_bus: impl FnMut(Bdf) -> Option<u8>) -> Option<u16>
    {
        let b = self.scope.resolve(secondary_bus)?;
        Some(
            (u16::from(b.bus) << 8) | (u16::from(b.device & 0x1f) << 3) | u16::from(b.function & 7),
        )
    }
}

/// Every I/O APIC the DMAR's remapping units name, in table order.
pub fn io_apic_scopes(dmar: &[u8]) -> impl Iterator<Item = IoApicScope> + '_
{
    drhd_units(dmar).flat_map(move |unit| {
        device_scopes(dmar, unit.scopes).filter_map(move |(kind, id, scope)| {
            (kind == SCOPE_IO_APIC).then_some(IoApicScope {
                segment: unit.segment,
                id,
                scope,
            })
        })
    })
}

/// The DMAR's flags (section 8.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DmarFlags
{
    /// The platform supports interrupt remapping (`INTR_REMAP`).
    pub interrupt_remapping: bool,
    /// The firmware asks the system not to use 32-bit (x2APIC) interrupt
    /// destinations (`X2APIC_OPT_OUT`).
    pub x2apic_opt_out: bool,
}

/// The DMAR's flags; `None` for a table that is not a DMAR or too short to
/// hold them.
#[must_use]
pub fn flags(dmar: &[u8]) -> Option<DmarFlags>
{
    if sdt_signature(dmar) != *b"DMAR" || dmar.len() <= DMAR_OFF_FLAGS
    {
        return None;
    }
    let flags = read_u8(dmar, DMAR_OFF_FLAGS);
    Some(DmarFlags {
        interrupt_remapping: flags & DMAR_FLAG_INTR_REMAP != 0,
        x2apic_opt_out: flags & DMAR_FLAG_X2APIC_OPT_OUT != 0,
    })
}

impl DrhdUnit
{
    /// The PCI functions and hierarchies the unit's scope names explicitly.
    pub fn scopes<'a>(&self, dmar: &'a [u8]) -> impl Iterator<Item = PciScope> + 'a
    {
        pci_scopes(dmar, self.scopes)
    }
}

impl Rmrr
{
    /// The PCI functions and hierarchies that keep reaching the region.
    pub fn scopes<'a>(&self, dmar: &'a [u8]) -> impl Iterator<Item = PciScope> + 'a
    {
        pci_scopes(dmar, self.scopes)
    }
}

/// Whether `scope`, resolved through `secondary_bus`, names `target`: the
/// function itself, or, for a sub-hierarchy, a bus behind the named bridge.
/// A sub-hierarchy covers the bridge's secondary bus up to its subordinate
/// bus, which `bus_range` reads for the bridge (`None` leaves it
/// unmatched).
fn scope_names(
    scope: &PciScope,
    target: Bdf,
    secondary_bus: &mut impl FnMut(Bdf) -> Option<u8>,
    bus_range: &mut impl FnMut(Bdf) -> Option<(u8, u8)>,
) -> bool
{
    let Some(named) = scope.resolve(&mut *secondary_bus)
    else
    {
        return false;
    };
    if named == target
    {
        return true;
    }
    scope.sub_hierarchy
        && bus_range(named).is_some_and(|(first, last)| (first..=last).contains(&target.bus))
}

/// The index, in [`drhd_units`] order, of the unit that translates function
/// `target` of `segment`: the first unit whose scope names it, else the
/// segment's `INCLUDE_PCI_ALL` unit (VT-d section 8.3). `None` when no unit
/// covers it, so its DMA is untranslated.
///
/// `secondary_bus` and `bus_range` read a bridge's secondary bus and its
/// (secondary, subordinate) bus range from configuration space.
pub fn unit_for(
    dmar: &[u8],
    segment: u16,
    target: Bdf,
    mut secondary_bus: impl FnMut(Bdf) -> Option<u8>,
    mut bus_range: impl FnMut(Bdf) -> Option<(u8, u8)>,
) -> Option<usize>
{
    let mut catch_all = None;
    for (index, unit) in drhd_units(dmar).enumerate()
    {
        if unit.segment != segment
        {
            continue;
        }
        if unit
            .scopes(dmar)
            .any(|s| scope_names(&s, target, &mut secondary_bus, &mut bus_range))
        {
            return Some(index);
        }
        if unit.include_pci_all && catch_all.is_none()
        {
            catch_all = Some(index);
        }
    }
    catch_all
}

/// Pass to `out` the first and last byte of each RMRR that names function
/// `target` of `segment`, in table order: the regions firmware expects it to
/// keep reaching after the hand-over, which its domain maps at their own
/// addresses before its DMA grant.
///
/// `secondary_bus` and `bus_range` read a bridge's secondary bus and its
/// (secondary, subordinate) bus range, as for [`unit_for`].
pub fn reserved_regions(
    dmar: &[u8],
    segment: u16,
    target: Bdf,
    mut secondary_bus: impl FnMut(Bdf) -> Option<u8>,
    mut bus_range: impl FnMut(Bdf) -> Option<(u8, u8)>,
    mut out: impl FnMut(u64, u64),
)
{
    for r in rmrrs(dmar)
    {
        if r.segment == segment
            && r.scopes(dmar)
                .any(|s| scope_names(&s, target, &mut secondary_bus, &mut bus_range))
        {
            out(r.base, r.limit);
        }
    }
}

/// PCI functions one resolved device scope names: the function itself, or
/// every function on a bridge's secondary through subordinate bus.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resolved
{
    /// One function.
    Function(Bdf),
    /// Every function on buses `.0..=.1`.
    Buses(u8, u8),
}

impl DrhdUnit
{
    /// The unit's explicit scope resolved against the PCI topology, passing
    /// each named function, and each sub-hierarchy's bus range, to `out`,
    /// so a consumer that reads no configuration space can match functions
    /// to the unit as [`unit_for`] does. A scope that does not resolve names
    /// nothing, as in [`unit_for`]; a sub-hierarchy whose bridge's bus range
    /// is unreadable names the bridge alone.
    pub fn resolve_scopes(
        &self,
        dmar: &[u8],
        mut secondary_bus: impl FnMut(Bdf) -> Option<u8>,
        mut bus_range: impl FnMut(Bdf) -> Option<(u8, u8)>,
        mut out: impl FnMut(Resolved),
    )
    {
        for scope in self.scopes(dmar)
        {
            let Some(named) = scope.resolve(&mut secondary_bus)
            else
            {
                continue;
            };
            out(Resolved::Function(named));
            if scope.sub_hierarchy
                && let Some((first, last)) = bus_range(named)
                && first <= last
            {
                out(Resolved::Buses(first, last));
            }
        }
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    const fn bdf(bus: u8, device: u8, function: u8) -> Bdf
    {
        Bdf {
            bus,
            device,
            function,
        }
    }

    /// A DMAR with host address width `haw` holding `structures`.
    fn dmar(haw: u8, structures: &[Vec<u8>]) -> Vec<u8>
    {
        let body: usize = structures.iter().map(Vec::len).sum();
        let len = DMAR_STRUCTURES_OFF + body;
        let mut b = vec![0u8; len];
        b[0..4].copy_from_slice(b"DMAR");
        b[4..8].copy_from_slice(&u32::try_from(len).unwrap().to_le_bytes());
        b[DMAR_OFF_HAW] = haw - 1;
        let mut off = DMAR_STRUCTURES_OFF;
        for s in structures
        {
            b[off..off + s.len()].copy_from_slice(s);
            off += s.len();
        }
        b
    }

    /// A device scope of `kind` from `start_bus` along `path`.
    fn scope(kind: u8, start_bus: u8, path: &[(u8, u8)]) -> Vec<u8>
    {
        let mut s = vec![
            kind,
            u8::try_from(SCOPE_PATH_OFF + 2 * path.len()).unwrap(),
            0,
            0,
            0,
        ];
        s.push(start_bus);
        for &(d, f) in path
        {
            s.push(d);
            s.push(f);
        }
        s
    }

    fn drhd(flags: u8, size: u8, segment: u16, base: u64, scopes: &[Vec<u8>]) -> Vec<u8>
    {
        let body: usize = scopes.iter().map(Vec::len).sum();
        let len = u16::try_from(DRHD_SCOPES_OFF + body).unwrap();
        let mut s = Vec::new();
        s.extend_from_slice(&TYPE_DRHD.to_le_bytes());
        s.extend_from_slice(&len.to_le_bytes());
        s.push(flags);
        s.push(size);
        s.extend_from_slice(&segment.to_le_bytes());
        s.extend_from_slice(&base.to_le_bytes());
        for sc in scopes
        {
            s.extend_from_slice(sc);
        }
        s
    }

    fn rmrr(segment: u16, base: u64, limit: u64, scopes: &[Vec<u8>]) -> Vec<u8>
    {
        let body: usize = scopes.iter().map(Vec::len).sum();
        let len = u16::try_from(RMRR_SCOPES_OFF + body).unwrap();
        let mut s = Vec::new();
        s.extend_from_slice(&TYPE_RMRR.to_le_bytes());
        s.extend_from_slice(&len.to_le_bytes());
        s.extend_from_slice(&[0, 0]);
        s.extend_from_slice(&segment.to_le_bytes());
        s.extend_from_slice(&base.to_le_bytes());
        s.extend_from_slice(&limit.to_le_bytes());
        for sc in scopes
        {
            s.extend_from_slice(sc);
        }
        s
    }

    /// No bridge is readable: only single-hop scopes resolve.
    fn no_bridges(_: Bdf) -> Option<u8>
    {
        None
    }

    fn no_ranges(_: Bdf) -> Option<(u8, u8)>
    {
        None
    }

    #[test]
    fn a_q35_style_catch_all_unit_is_found_with_its_register_range()
    {
        // q35's intel-iommu: one INCLUDE_PCI_ALL unit at 0xfed90000.
        let table = dmar(
            39,
            &[drhd(DRHD_FLAG_INCLUDE_PCI_ALL, 0, 0, 0xfed9_0000, &[])],
        );
        let units: Vec<_> = drhd_units(&table).collect();
        assert_eq!(units.len(), 1);
        assert_eq!(units[0].register_base, 0xfed9_0000);
        assert_eq!(units[0].register_pages, 1);
        assert!(units[0].include_pci_all);
        assert_eq!(
            unit_for(&table, 0, bdf(0, 3, 0), no_bridges, no_ranges),
            Some(0)
        );
    }

    /// An I/O APIC device scope for I/O APIC `id` at `start_bus` along
    /// `path`.
    fn io_apic_scope(id: u8, start_bus: u8, path: &[(u8, u8)]) -> Vec<u8>
    {
        let mut s = scope(SCOPE_IO_APIC, start_bus, path);
        s[4] = id;
        s
    }

    #[test]
    fn a_q35_io_apic_scope_gives_the_io_apics_source_id()
    {
        // QEMU q35 with interrupt remapping: the catch-all unit names I/O
        // APIC 0 at ff:00.0, beside a PCI endpoint the I/O APIC walk skips.
        let table = dmar(
            39,
            &[drhd(
                DRHD_FLAG_INCLUDE_PCI_ALL,
                0,
                0,
                0xfed9_0000,
                &[
                    scope(SCOPE_PCI_ENDPOINT, 0, &[(2, 0)]),
                    io_apic_scope(0, 0xff, &[(0, 0)]),
                ],
            )],
        );
        let found: Vec<_> = io_apic_scopes(&table).collect();
        assert_eq!(found.len(), 1);
        assert_eq!((found[0].segment, found[0].id), (0, 0));
        assert_eq!(found[0].source_id(no_bridges), Some(0xff00));
        // The I/O APIC scope names no PCI function for the unit.
        assert_eq!(drhd_units(&table).next().unwrap().scopes(&table).count(), 1);
    }

    #[test]
    fn an_io_apic_behind_a_bridge_resolves_through_it()
    {
        let table = dmar(
            39,
            &[drhd(
                0,
                0,
                0,
                0xfed9_0000,
                &[io_apic_scope(8, 0, &[(0x1c, 0), (0x1f, 7)])],
            )],
        );
        let apic = io_apic_scopes(&table).next().unwrap();
        assert_eq!(apic.id, 8);
        let bridge = |b: Bdf| (b == bdf(0, 0x1c, 0)).then_some(5);
        assert_eq!(apic.source_id(bridge), Some(0x05ff));
        assert_eq!(apic.source_id(no_bridges), None);
    }

    #[test]
    fn the_dmar_flags_say_whether_interrupts_are_remapped()
    {
        let mut table = dmar(39, &[]);
        assert_eq!(
            flags(&table),
            Some(DmarFlags {
                interrupt_remapping: false,
                x2apic_opt_out: false,
            })
        );
        table[DMAR_OFF_FLAGS] = DMAR_FLAG_INTR_REMAP | DMAR_FLAG_X2APIC_OPT_OUT;
        assert_eq!(
            flags(&table),
            Some(DmarFlags {
                interrupt_remapping: true,
                x2apic_opt_out: true,
            })
        );
        table[0..4].copy_from_slice(b"APIC");
        assert_eq!(flags(&table), None);
        assert_eq!(flags(b"DMAR"), None);
    }

    #[test]
    fn a_register_set_size_field_gives_a_power_of_two_page_count()
    {
        let table = dmar(48, &[drhd(0, 2, 0, 0xfed9_0000, &[])]);
        assert_eq!(drhd_units(&table).next().map(|u| u.register_pages), Some(4));
    }

    #[test]
    fn a_unit_with_a_zero_or_unaligned_register_base_is_skipped()
    {
        let table = dmar(
            39,
            &[
                drhd(0, 0, 0, 0, &[]),
                drhd(0, 0, 0, 0xfed9_0010, &[]),
                drhd(0, 0, 0, 0xfed9_1000, &[]),
            ],
        );
        let bases: Vec<_> = drhd_units(&table).map(|u| u.register_base).collect();
        assert_eq!(bases, vec![0xfed9_1000]);
    }

    #[test]
    fn an_explicit_scope_wins_over_the_catch_all_unit()
    {
        let gpu = scope(SCOPE_PCI_ENDPOINT, 0, &[(2, 0)]);
        let table = dmar(
            39,
            &[
                drhd(0, 0, 0, 0xfed9_0000, &[gpu]),
                drhd(DRHD_FLAG_INCLUDE_PCI_ALL, 0, 0, 0xfed9_1000, &[]),
            ],
        );
        assert_eq!(
            unit_for(&table, 0, bdf(0, 2, 0), no_bridges, no_ranges),
            Some(0)
        );
        assert_eq!(
            unit_for(&table, 0, bdf(0, 3, 0), no_bridges, no_ranges),
            Some(1)
        );
    }

    #[test]
    fn a_function_of_another_segment_gets_no_unit()
    {
        let table = dmar(
            39,
            &[drhd(DRHD_FLAG_INCLUDE_PCI_ALL, 0, 0, 0xfed9_0000, &[])],
        );
        assert_eq!(
            unit_for(&table, 1, bdf(0, 3, 0), no_bridges, no_ranges),
            None
        );
    }

    #[test]
    fn a_multi_hop_path_resolves_through_the_bridges_secondary_buses()
    {
        // Root port 00:1c.0 leads to bus 2; the endpoint is 02:00.0.
        let ep = scope(SCOPE_PCI_ENDPOINT, 0, &[(0x1c, 0), (0, 0)]);
        let table = dmar(39, &[drhd(0, 0, 0, 0xfed9_0000, &[ep])]);
        let secondary = |b: Bdf| (b == bdf(0, 0x1c, 0)).then_some(2);
        assert_eq!(
            unit_for(&table, 0, bdf(2, 0, 0), secondary, no_ranges),
            Some(0)
        );
        // With the bridge unreadable the scope does not resolve.
        assert_eq!(
            unit_for(&table, 0, bdf(2, 0, 0), no_bridges, no_ranges),
            None
        );
    }

    #[test]
    fn a_sub_hierarchy_scope_covers_every_bus_behind_its_bridge()
    {
        let tree = scope(SCOPE_PCI_SUB_HIERARCHY, 0, &[(0x1c, 0)]);
        let table = dmar(39, &[drhd(0, 0, 0, 0xfed9_0000, &[tree])]);
        let range = |b: Bdf| (b == bdf(0, 0x1c, 0)).then_some((2, 4));
        assert_eq!(
            unit_for(&table, 0, bdf(3, 0, 0), no_bridges, range),
            Some(0)
        );
        assert_eq!(unit_for(&table, 0, bdf(5, 0, 0), no_bridges, range), None);
    }

    #[test]
    fn non_pci_and_malformed_scopes_are_skipped()
    {
        let ioapic = scope(3, 0, &[(0x1f, 0)]);
        let empty = scope(SCOPE_PCI_ENDPOINT, 0, &[]);
        let deep = scope(SCOPE_PCI_ENDPOINT, 0, &[(1, 0); MAX_SCOPE_PATH + 1]);
        let ep = scope(SCOPE_PCI_ENDPOINT, 0, &[(4, 0)]);
        let table = dmar(
            39,
            &[drhd(0, 0, 0, 0xfed9_0000, &[ioapic, empty, deep, ep])],
        );
        let unit = drhd_units(&table).next().unwrap();
        let found: Vec<_> = unit.scopes(&table).map(|s| s.path().to_vec()).collect();
        assert_eq!(found, vec![vec![(4, 0)]]);
    }

    /// The reserved regions `reserved_regions` passes for `target`.
    fn regions_of(
        table: &[u8],
        segment: u16,
        target: Bdf,
        range: impl FnMut(Bdf) -> Option<(u8, u8)>,
    ) -> Vec<(u64, u64)>
    {
        let mut found = Vec::new();
        reserved_regions(table, segment, target, no_bridges, range, |b, l| {
            found.push((b, l));
        });
        found
    }

    #[test]
    fn the_rmrrs_naming_a_function_are_its_reserved_regions()
    {
        let usb = scope(SCOPE_PCI_ENDPOINT, 0, &[(0x14, 0)]);
        let gpu = scope(SCOPE_PCI_ENDPOINT, 0, &[(2, 0)]);
        let table = dmar(
            39,
            &[
                drhd(DRHD_FLAG_INCLUDE_PCI_ALL, 0, 0, 0xfed9_0000, &[]),
                rmrr(0, 0x7c00_0000, 0x7c0f_ffff, &[usb.clone()]),
                rmrr(0, 0x8000_0000, 0x8fff_ffff, &[gpu]),
                rmrr(0, 0x000e_8000, 0x000e_8fff, &[usb]),
            ],
        );
        assert_eq!(
            regions_of(&table, 0, bdf(0, 0x14, 0), no_ranges),
            [(0x7c00_0000, 0x7c0f_ffff), (0x000e_8000, 0x000e_8fff)]
        );
        assert_eq!(
            regions_of(&table, 0, bdf(0, 2, 0), no_ranges),
            [(0x8000_0000, 0x8fff_ffff)]
        );
        assert!(regions_of(&table, 0, bdf(0, 3, 0), no_ranges).is_empty());
        assert!(regions_of(&table, 1, bdf(0, 0x14, 0), no_ranges).is_empty());
    }

    #[test]
    fn an_rmrr_naming_a_sub_hierarchy_reserves_for_every_function_behind_it()
    {
        let tree = scope(SCOPE_PCI_SUB_HIERARCHY, 0, &[(0x1c, 0)]);
        let table = dmar(39, &[rmrr(0, 0x7c00_0000, 0x7c00_0fff, &[tree])]);
        let range = |b: Bdf| (b == bdf(0, 0x1c, 0)).then_some((2, 4));
        assert_eq!(
            regions_of(&table, 0, bdf(3, 0, 0), range),
            [(0x7c00_0000, 0x7c00_0fff)]
        );
        assert!(regions_of(&table, 0, bdf(5, 0, 0), range).is_empty());
    }

    #[test]
    fn a_units_scope_resolves_to_its_functions_and_bridged_bus_ranges()
    {
        let ep = scope(SCOPE_PCI_ENDPOINT, 0, &[(4, 0)]);
        let behind = scope(SCOPE_PCI_ENDPOINT, 0, &[(1, 0), (0, 0)]);
        let sub = scope(SCOPE_PCI_SUB_HIERARCHY, 0, &[(2, 0)]);
        let lost = scope(SCOPE_PCI_ENDPOINT, 0, &[(9, 0), (0, 0)]);
        let table = dmar(39, &[drhd(0, 0, 0, 0xfed9_0000, &[ep, behind, sub, lost])]);
        let unit = drhd_units(&table).next().unwrap();
        let mut found = Vec::new();
        unit.resolve_scopes(
            &table,
            |b| (b == bdf(0, 1, 0)).then_some(7),
            |b| (b == bdf(0, 2, 0)).then_some((3, 5)),
            |r| found.push(r),
        );
        assert_eq!(
            found,
            [
                Resolved::Function(bdf(0, 4, 0)),
                Resolved::Function(bdf(7, 0, 0)),
                Resolved::Function(bdf(0, 2, 0)),
                Resolved::Buses(3, 5),
            ]
        );
    }

    #[test]
    fn an_rmrr_whose_limit_is_below_its_base_is_skipped()
    {
        let table = dmar(39, &[rmrr(0, 0x2000, 0x1000, &[])]);
        assert_eq!(rmrrs(&table).count(), 0);
    }

    #[test]
    fn the_walk_ends_at_a_structure_running_past_the_table()
    {
        let good = drhd(0, 0, 0, 0xfed9_0000, &[]);
        let mut bad = drhd(0, 0, 0, 0xfed9_1000, &[]);
        bad[2..4].copy_from_slice(&0x400u16.to_le_bytes());
        let after = drhd(0, 0, 0, 0xfed9_2000, &[]);
        let table = dmar(39, &[good, bad, after]);
        let bases: Vec<_> = drhd_units(&table).map(|u| u.register_base).collect();
        assert_eq!(bases, vec![0xfed9_0000]);
    }

    #[test]
    fn a_table_that_is_not_a_dmar_yields_nothing()
    {
        let mut table = dmar(
            39,
            &[drhd(DRHD_FLAG_INCLUDE_PCI_ALL, 0, 0, 0xfed9_0000, &[])],
        );
        table[0..4].copy_from_slice(b"APIC");
        assert_eq!(drhd_units(&table).count(), 0);
    }
}
