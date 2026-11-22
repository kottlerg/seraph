// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/acpid/src/bridge.rs

//! The PCI host bridges of the namespace and what acpid evaluates on each:
//! the `_OSC` grant of native control of the PCI Express features, the
//! windows its `_CRS` decodes, and the interrupt routes of its root bus that
//! its `_PRT` gives, each in the form devmgr's `OSC_RESULT`,
//! `BRIDGE_WINDOWS` and `PRT_TABLE` carry; and the PCI-to-PCI bridges below
//! them that have a `_PRT` of their own, whose routes `PRT_TABLE` carries too.

use aml::namespace::NodeId;
use aml::resource::{self, Resource};
use aml::value::Base;
use aml::{Data, Evaluator};
use ipc::devmgr_labels;

use crate::hotplug::{self, Route, Unresolved};
use crate::{Failure, Why, child};

/// The EISA id of a PCI host bridge, `PNP0A03`, as a `_HID` integer holds it.
pub const PCI_HOST_BRIDGE: u32 = eisa_id(*b"PNP0A03");
/// The EISA id of a PCI Express host bridge, `PNP0A08`.
pub const PCI_EXPRESS_HOST_BRIDGE: u32 = eisa_id(*b"PNP0A08");

/// The `_OSC` UUID of a PCI host bridge, `33DB4D5B-1FF7-401C-9657-7441C03DD766`
/// (PCI Firmware Specification 3.3 § 4.5.1), in the byte order `ToUUID`
/// gives.
pub const PCI_OSC_UUID: [u8; 16] = [
    0x5B, 0x4D, 0xDB, 0x33, 0xF7, 0x1F, 0x1C, 0x40, 0x96, 0x57, 0x74, 0x41, 0xC0, 0x3D, 0xD7, 0x66,
];
/// The `_OSC` support dword acpid passes: extended configuration space,
/// ASPM, clock power management, segments and MSI (bits 0 to 4), the
/// features Seraph's PCI support uses or leaves as the firmware set them.
pub const OSC_SUPPORT: u32 = 0x1F;
/// The `_OSC` control dword acpid asks for: native PCI Express hotplug,
/// SHPC hotplug, PME, AER and the PCI Express capability structure (bits 0
/// to 4).
pub const OSC_CONTROL: u32 = 0x1F;

/// The compressed EISA id of the seven-character id `id` (three letters,
/// four hexadecimal digits), as a `_HID` or `_CID` integer holds it.
#[must_use]
pub const fn eisa_id(id: [u8; 7]) -> u32
{
    let vendor = (eisa_letter(id[0]) << 10) | (eisa_letter(id[1]) << 5) | eisa_letter(id[2]);
    let product = (eisa_digit(id[3]) << 12)
        | (eisa_digit(id[4]) << 8)
        | (eisa_digit(id[5]) << 4)
        | eisa_digit(id[6]);
    // The id's bytes in order are the vendor, then the product, each
    // big-endian; the integer reads them little-endian.
    ((vendor >> 8) & 0xFF)
        | ((vendor & 0xFF) << 8)
        | (((product >> 8) & 0xFF) << 16)
        | ((product & 0xFF) << 24)
}

/// The five bits of the EISA id letter `c` (`A` is 1).
const fn eisa_letter(c: u8) -> u32
{
    (c.wrapping_sub(0x40) & 0x1F) as u32
}

/// The value of the EISA id hexadecimal digit `c` (upper case).
const fn eisa_digit(c: u8) -> u32
{
    (match c
    {
        b'0'..=b'9' => c.wrapping_sub(b'0'),
        b'A'..=b'F' => c.wrapping_sub(b'A').wrapping_add(10),
        _ => 0,
    }) as u32
}

/// Whether the `_HID` or `_CID` value `id` names a PCI or PCI Express host
/// bridge: an EISA id integer, an id string, or (`_CID`) a package of
/// either.
#[must_use]
pub fn names_host_bridge(id: &Data) -> bool
{
    match id
    {
        Data::Integer(v) =>
        {
            *v == u64::from(PCI_HOST_BRIDGE) || *v == u64::from(PCI_EXPRESS_HOST_BRIDGE)
        }
        Data::String(s) => s == b"PNP0A03" || s == b"PNP0A08",
        Data::Package(ids) => ids
            .iter()
            .any(|i| matches!(i, Data::Integer(_) | Data::String(_)) && names_host_bridge(i)),
        Data::Uninitialized | Data::Buffer(_) | Data::Name(_) | Data::Ref(_) => false,
    }
}

/// A PCI host bridge: its device and the segment and bus its `_SEG` and
/// `_BBN` give (0 when absent).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bridge
{
    /// The bridge's device.
    pub node: NodeId,
    /// Its PCI segment group.
    pub segment: u16,
    /// Its root bus.
    pub bus: u8,
}

/// The host bridges among the devices `present`, in segment, then bus
/// order, and the evaluations that failed on the way. A device whose
/// `_HID` or `_CID` cannot be evaluated is not taken for a bridge; a
/// bridge whose `_SEG` or `_BBN` fails, or is out of range, is left out.
pub fn host_bridges(ev: &mut Evaluator<'_>, present: &[NodeId]) -> (Vec<Bridge>, Vec<Failure>)
{
    let mut bridges = Vec::new();
    let mut failures = Vec::new();
    for &node in present
    {
        let mut is_bridge = false;
        for name in [*b"_HID", *b"_CID"]
        {
            match evaluate(ev, node, name)
            {
                Some(Ok(id)) => is_bridge |= names_host_bridge(&id),
                Some(Err(why)) => failures.push(Failure { node, name, why }),
                None =>
                {}
            }
        }
        if !is_bridge
        {
            continue;
        }
        let segment = number(ev, node, *b"_SEG", &mut failures);
        let bus = number(ev, node, *b"_BBN", &mut failures);
        if let (Some(segment), Some(bus)) = (segment, bus)
        {
            bridges.push(Bridge { node, segment, bus });
        }
    }
    bridges.sort_by_key(|b| (b.segment, b.bus));
    (bridges, failures)
}

/// A PCI-to-PCI bridge below a host bridge that the namespace gives a
/// `_PRT` of its own, which routes the interrupts of the functions below it
/// (ACPI 6.5 § 6.2.13).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PciBridge
{
    /// The bridge's device.
    pub node: NodeId,
    /// The way to it from its host bridge's root bus, it last.
    pub route: Route,
}

/// The PCI-to-PCI bridges among the devices `present` that have a `_PRT`,
/// each below one of `bridges` through PCI devices
/// ([`hotplug::bridge_route`]), the deepest first; and the evaluations that
/// failed on the way, an `_ADR` of the bridge or of a device above it
/// recorded against the bridge. A device with a `_PRT` that is a host
/// bridge, or that is not below one through devices with an `_ADR`, is none.
pub fn pci_bridges(
    ev: &mut Evaluator<'_>,
    bridges: &[Bridge],
    present: &[NodeId],
) -> (Vec<PciBridge>, Vec<Failure>)
{
    let mut found = Vec::new();
    let mut failures = Vec::new();
    for &node in present
    {
        if bridges.iter().any(|b| b.node == node) || child(ev.namespace(), node, *b"_PRT").is_none()
        {
            continue;
        }
        match hotplug::bridge_route(ev, bridges, node)
        {
            Ok(route) => found.push(PciBridge { node, route }),
            Err(Unresolved::Address(why)) => failures.push(Failure {
                node,
                name: *b"_ADR",
                why,
            }),
            Err(Unresolved::NotPci | Unresolved::RootBus | Unresolved::NoBridge) =>
            {}
        }
    }
    found.sort_by_key(|b| core::cmp::Reverse(b.route.hops.len()));
    (found, failures)
}

/// The value of the child `name` of `node` as a `T`, 0 when it is absent;
/// `None`, with the failure recorded, when it faults or does not fit.
fn number<T: TryFrom<u64> + Default>(
    ev: &mut Evaluator<'_>,
    node: NodeId,
    name: aml::encoding::Seg,
    failures: &mut Vec<Failure>,
) -> Option<T>
{
    let why = match evaluate(ev, node, name)
    {
        None => return Some(T::default()),
        Some(Ok(Data::Integer(v))) => match T::try_from(v)
        {
            Ok(v) => return Some(v),
            Err(_) => Why::Shape,
        },
        Some(Ok(_)) => Why::Shape,
        Some(Err(why)) => why,
    };
    failures.push(Failure { node, name, why });
    None
}

/// Evaluate the child `name` of `node` with no arguments; `None` when it
/// does not exist.
fn evaluate(
    ev: &mut Evaluator<'_>,
    node: NodeId,
    name: aml::encoding::Seg,
) -> Option<Result<Data, Why>>
{
    let id = child(ev.namespace(), node, name)?;
    Some(ev.evaluate(id, Vec::new()).map_err(Why::Fault))
}

/// The outcome of a bridge's `_OSC`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Osc
{
    /// The bridge has no `_OSC`.
    Absent,
    /// The evaluation failed.
    Failed(Why),
    /// It returned: its status dword and its control dword, the features
    /// whose native control the firmware grants.
    Returned
    {
        /// The status dword (capabilities buffer dword 1).
        status: u32,
        /// The control dword (dword 3).
        control: u32,
    },
}

/// Evaluate the `_OSC` of `bridge` with the PCI host bridge UUID, revision
/// 1, [`OSC_SUPPORT`] and [`OSC_CONTROL`], the query flag clear, so that
/// the firmware grants the control it returns.
pub fn osc(ev: &mut Evaluator<'_>, bridge: NodeId) -> Osc
{
    let Some(id) = child(ev.namespace(), bridge, *b"_OSC")
    else
    {
        return Osc::Absent;
    };
    let mut caps = Vec::with_capacity(12);
    for dword in [0, OSC_SUPPORT, OSC_CONTROL]
    {
        caps.extend(dword.to_le_bytes());
    }
    let args = vec![
        Data::Buffer(PCI_OSC_UUID.to_vec()),
        Data::Integer(1),
        Data::Integer(3),
        Data::Buffer(caps),
    ];
    let out = match ev.evaluate(id, args)
    {
        Ok(Data::Buffer(out)) => out,
        Ok(_) => return Osc::Failed(Why::Shape),
        Err(f) => return Osc::Failed(Why::Fault(f)),
    };
    let dword = |i: usize| {
        out.get(i..i.saturating_add(4))
            .and_then(|b| <[u8; 4]>::try_from(b).ok())
            .map(u32::from_le_bytes)
    };
    match (dword(0), dword(8))
    {
        (Some(status), Some(control)) => Osc::Returned { status, control },
        _ => Osc::Failed(Why::Shape),
    }
}

/// One window of a host bridge: a `devmgr_labels::WINDOW_*` kind, and its
/// base and length on the bus side of the bridge (the descriptor's minimum
/// and length; the translation to the processor side is not applied).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Window
{
    /// `WINDOW_MEMORY`, `WINDOW_IO` or `WINDOW_BUS`.
    pub kind: u64,
    /// The first address, port or bus.
    pub base: u64,
    /// The length.
    pub len: u64,
}

/// The windows of `bridge` its `_CRS` gives: every address-space
/// descriptor of the memory, I/O or bus-number space with a length, in
/// template order; `Ok(None)` when the bridge has no `_CRS`.
///
/// The producer flag is not read, as firmware often leaves it wrong on a
/// host bridge's windows; the fixed I/O and I/O descriptors a host bridge
/// consumes (the configuration ports) are not address-space descriptors and
/// are not windows.
///
/// # Errors
///
/// [`Why::Fault`] when `_CRS` faults, [`Why::Shape`] when it returns no
/// buffer or a malformed template, and [`Why::Bound`] for more windows than
/// `devmgr_labels::MAX_BRIDGE_WINDOWS`.
pub fn windows(ev: &mut Evaluator<'_>, bridge: NodeId) -> Result<Option<Vec<Window>>, Why>
{
    let crs = match evaluate(ev, bridge, *b"_CRS")
    {
        None => return Ok(None),
        Some(Ok(Data::Buffer(crs))) => crs,
        Some(Ok(_)) => return Err(Why::Shape),
        Some(Err(why)) => return Err(why),
    };
    let mut windows = Vec::new();
    for descriptor in resource::descriptors(&crs)
    {
        let Resource::Address(a) = descriptor.map_err(|_| Why::Shape)?
        else
        {
            continue;
        };
        let kind = match a.space
        {
            resource::SPACE_MEMORY => devmgr_labels::WINDOW_MEMORY,
            resource::SPACE_IO => devmgr_labels::WINDOW_IO,
            resource::SPACE_BUS => devmgr_labels::WINDOW_BUS,
            _ => continue,
        };
        if a.length == 0
        {
            continue;
        }
        if windows.len() == devmgr_labels::MAX_BRIDGE_WINDOWS
        {
            return Err(Why::Bound);
        }
        windows.push(Window {
            kind,
            base: a.min,
            len: a.length,
        });
    }
    Ok(Some(windows))
}

/// The routes of a bus, a host bridge's root bus or a PCI-to-PCI bridge's
/// secondary bus, in `PRT_TABLE`'s form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Routes
{
    /// One word per device 0 to 31: the line of pin `INTA` to `INTD` in its
    /// 16-bit lanes 0 to 3, `devmgr_labels::PRT_NO_ROUTE` for a pin no entry
    /// routes.
    pub lanes: [u64; 32],
    /// The entries that gave a line.
    pub routed: usize,
    /// The entries that could not be read, and the link devices whose
    /// current resources could not be: their pins stay unrouted.
    pub failures: Vec<Failure>,
}

/// The routes `bridge`'s `_PRT` gives in the interrupt model selected now;
/// `Ok(None)` when the bridge has no `_PRT`.
///
/// An entry whose source is 0 routes its pin to the line its source index
/// names. Any other entry names a link device, whose `_CRS` is read once:
/// the pin takes the interrupt of that template the source index selects
/// (the IRQ descriptors' lines, then the extended interrupt descriptors', in
/// template order). A link whose current interrupt is 0 is disabled, and its
/// pins stay unrouted, as do the pins of an entry that cannot be read and of
/// a link whose `_CRS` cannot; each of those is a failure in the result.
///
/// # Errors
///
/// [`Why::Fault`] when `_PRT` faults and [`Why::Shape`] when it returns no
/// package.
pub fn routes(ev: &mut Evaluator<'_>, bridge: NodeId) -> Result<Option<Routes>, Why>
{
    let entries = match evaluate(ev, bridge, *b"_PRT")
    {
        None => return Ok(None),
        Some(Ok(Data::Package(entries))) => entries,
        Some(Ok(_)) => return Err(Why::Shape),
        Some(Err(why)) => return Err(why),
    };
    let mut routes = Routes {
        lanes: [prt_unrouted(); 32],
        routed: 0,
        failures: Vec::new(),
    };
    let mut cache: Vec<(NodeId, Option<Vec<u64>>)> = Vec::new();
    for entry in &entries
    {
        let Some((device, pin, source, index)) = prt_entry(ev, bridge, entry)
        else
        {
            routes.failures.push(Failure {
                node: bridge,
                name: *b"_PRT",
                why: Why::Shape,
            });
            continue;
        };
        let line = match source
        {
            None => Some(index),
            Some(link) => link_line(ev, link, index, &mut cache, &mut routes.failures),
        };
        let Some(line) = line.filter(|&l| l < devmgr_labels::PRT_NO_ROUTE)
        else
        {
            continue;
        };
        if let Some(word) = routes.lanes.get_mut(device)
        {
            // A pin is at most 3, so the shift stays inside the word.
            let shift = pin.saturating_mul(16);
            *word = (*word & !(0xFFFF << shift)) | (line << shift);
            routes.routed = routes.routed.saturating_add(1);
        }
    }
    Ok(Some(routes))
}

/// A device word with every pin unrouted.
const fn prt_unrouted() -> u64
{
    let n = devmgr_labels::PRT_NO_ROUTE;
    n | (n << 16) | (n << 32) | (n << 48)
}

/// The device, pin, link device (`None` for a source of 0) and source index
/// of the `_PRT` entry `entry` of `bridge`; `None` for an entry that is
/// not a package of an address, a pin 0 to 3, a source and an index, whose
/// device is past 31, or whose link name resolves to nothing.
fn prt_entry(
    ev: &Evaluator<'_>,
    bridge: NodeId,
    entry: &Data,
) -> Option<(usize, u64, Option<NodeId>, u64)>
{
    let Data::Package(fields) = entry
    else
    {
        return None;
    };
    let [
        Data::Integer(address),
        Data::Integer(pin),
        source,
        Data::Integer(index),
        ..,
    ] = fields.as_slice()
    else
    {
        return None;
    };
    let device = usize::try_from(address >> 16).ok().filter(|&d| d < 32)?;
    if *pin > 3
    {
        return None;
    }
    let ns = ev.namespace();
    let link = match source
    {
        Data::Integer(0) => None,
        Data::Ref(r) if r.path.is_empty() => match r.base
        {
            Base::Node { node, .. } => Some(node),
            Base::Local { .. } | Base::Arg { .. } | Base::Value(_) => return None,
        },
        Data::Name(name) => Some(ns.resolve(bridge, name)?),
        Data::Uninitialized
        | Data::Integer(_)
        | Data::String(_)
        | Data::Buffer(_)
        | Data::Package(_)
        | Data::Ref(_) => return None,
    };
    Some((device, *pin, link.and_then(|l| ns.follow(l)), *index))
}

/// The interrupt `index` of link device `link`'s current resources, read
/// once into `cache`; `None` when the link is disabled (its interrupt is
/// 0), has no such interrupt, or its `_CRS` cannot be read, which is
/// recorded in `failures` the first time.
fn link_line(
    ev: &mut Evaluator<'_>,
    link: NodeId,
    index: u64,
    cache: &mut Vec<(NodeId, Option<Vec<u64>>)>,
    failures: &mut Vec<Failure>,
) -> Option<u64>
{
    let interrupts = if let Some((_, known)) = cache.iter().find(|(l, _)| *l == link)
    {
        known.clone()
    }
    else
    {
        let read = match link_lines(ev, link)
        {
            Ok(read) => Some(read),
            Err(why) =>
            {
                failures.push(Failure {
                    node: link,
                    name: *b"_CRS",
                    why,
                });
                None
            }
        };
        cache.push((link, read.clone()));
        read
    };
    let irq = *interrupts?.get(usize::try_from(index).ok()?)?;
    (irq != 0).then_some(irq)
}

/// The interrupts of link device `link`'s `_CRS`, in the order
/// [`link_line`] indexes them.
fn link_lines(ev: &mut Evaluator<'_>, link: NodeId) -> Result<Vec<u64>, Why>
{
    let crs = match evaluate(ev, link, *b"_CRS")
    {
        Some(Ok(Data::Buffer(crs))) => crs,
        Some(Ok(_)) | None => return Err(Why::Shape),
        Some(Err(why)) => return Err(why),
    };
    let mut lines = Vec::new();
    for descriptor in resource::descriptors(&crs)
    {
        match descriptor.map_err(|_| Why::Shape)?
        {
            Resource::Irq(irq) =>
            {
                lines.extend((0..16u64).filter(|&bit| irq.mask & (1 << bit) != 0));
            }
            Resource::ExtendedIrq(irq) => lines.extend(irq.lines().map(u64::from)),
            Resource::Io { .. }
            | Resource::FixedIo { .. }
            | Resource::Memory24 { .. }
            | Resource::Memory32 { .. }
            | Resource::FixedMemory32 { .. }
            | Resource::Address(_)
            | Resource::GenericRegister { .. }
            | Resource::Other { .. } =>
            {}
        }
    }
    Ok(lines)
}

#[cfg(test)]
mod tests
{
    use aml::Evaluator;
    use aml::encoding::Seg;

    use super::*;
    use crate::sim::{self, Sim, buffer, device, dword, name, package};

    /// `\_SB.` then the one-segment name `seg`, as a `NameString`.
    fn sb(seg: [u8; 4]) -> Vec<u8>
    {
        [&b"\\\x2E_SB_"[..], &seg].concat()
    }

    /// The fixture `config` after its module-level code, on [`Sim::new`].
    fn machine(config: &str) -> (aml::Namespace, Sim)
    {
        let mut ns = sim::fixture(config);
        let mut host = Sim::new();
        sim::run_module_code(&mut ns, &mut host);
        (ns, host)
    }

    /// The one host bridge of `ev`'s namespace, found among every device.
    fn only_bridge(ev: &mut Evaluator<'_>) -> Bridge
    {
        let all: Vec<NodeId> = ev.namespace().nodes().collect();
        let (bridges, failures) = host_bridges(ev, &all);
        assert_eq!(bridges.len(), 1, "{bridges:?} {failures:?}");
        bridges[0]
    }

    fn lane(routes: &Routes, device: usize, pin: u32) -> u64
    {
        (routes.lanes[device] >> (16 * pin)) & 0xFFFF
    }

    #[test]
    fn host_bridge_ids_are_matched_as_integers_strings_and_cid_packages()
    {
        // The PNP0A03 and PNP0A08 integers of the ACPI specification's
        // EisaId examples.
        assert_eq!(PCI_HOST_BRIDGE, 0x030A_D041);
        assert_eq!(PCI_EXPRESS_HOST_BRIDGE, 0x080A_D041);
        assert!(names_host_bridge(&Data::Integer(0x080A_D041)));
        assert!(names_host_bridge(&Data::String(b"PNP0A03".to_vec())));
        assert!(names_host_bridge(&Data::Package(vec![
            Data::Integer(u64::from(eisa_id(*b"PNP0C02"))),
            Data::String(b"PNP0A08".to_vec()),
        ])));
        assert!(!names_host_bridge(&Data::Integer(u64::from(eisa_id(
            *b"PNP0A05"
        )))));
        assert!(!names_host_bridge(&Data::Package(vec![Data::Package(
            vec![Data::Integer(u64::from(PCI_HOST_BRIDGE))]
        )])));
    }

    #[test]
    fn a_bridge_with_a_bad_bbn_is_left_out_and_bridges_sort_by_segment_and_bus()
    {
        let hid = name(b"_HID", &dword(PCI_EXPRESS_HOST_BRIDGE));
        let body = [
            device(
                &sb(*b"B___"),
                &[hid.clone(), name(b"_BBN", &[0x0A, 0x80])].concat(),
            ),
            device(
                &sb(*b"A___"),
                &[hid.clone(), name(b"_SEG", &[0x01])].concat(),
            ),
            device(&sb(*b"C___"), &hid),
            // A bus past 255.
            device(&sb(*b"D___"), &[hid, name(b"_BBN", &dword(0x100))].concat()),
        ]
        .concat();
        let mut ns = sim::namespace(&[sim::table(&body)]);
        let mut host = Sim::new();
        let mut ev = Evaluator::new(&mut ns, &mut host);
        let all: Vec<NodeId> = ev.namespace().nodes().collect();
        let (bridges, failures) = host_bridges(&mut ev, &all);
        let ns = ev.namespace();
        let found: Vec<(Seg, u16, u8)> = bridges
            .iter()
            .map(|b| (ns.name(b.node).unwrap(), b.segment, b.bus))
            .collect();
        assert_eq!(
            found,
            [(*b"C___", 0, 0), (*b"B___", 0, 0x80), (*b"A___", 1, 0)]
        );
        assert_eq!(failures.len(), 1);
        assert_eq!(
            (ns.name(failures[0].node), failures[0].name, failures[0].why),
            (Some(*b"D___"), *b"_BBN", Why::Shape)
        );
    }

    #[test]
    fn osc_withholds_native_hotplug_only_while_acpi_hotplug_is_on()
    {
        for (config, expected) in [
            ("x86-default", (0x10, 0x1E)),
            ("riscv64-rootport", (0x10, 0x1E)),
            ("x86-rootport-native", (0, 0x1F)),
        ]
        {
            let (mut ns, mut host) = machine(config);
            let mut ev = Evaluator::new(&mut ns, &mut host);
            let bridge = only_bridge(&mut ev);
            assert_eq!(
                osc(&mut ev, bridge.node),
                Osc::Returned {
                    status: expected.0,
                    control: expected.1
                },
                "{config}"
            );
        }
    }

    #[test]
    fn the_q35_windows_are_the_bus_io_and_memory_windows_of_crs()
    {
        let (mut ns, mut host) = machine("x86-default");
        let mut ev = Evaluator::new(&mut ns, &mut host);
        let bridge = only_bridge(&mut ev);
        let windows = windows(&mut ev, bridge.node).unwrap().unwrap();
        let w = |kind, base, len| Window { kind, base, len };
        let (mem, io, bus) = (
            devmgr_labels::WINDOW_MEMORY,
            devmgr_labels::WINDOW_IO,
            devmgr_labels::WINDOW_BUS,
        );
        assert_eq!(windows.len(), 7, "{windows:x?}");
        for expected in [
            w(bus, 0, 0x100),
            w(io, 0, 0xCF8),
            w(io, 0xD00, 0xF300),
            w(mem, 0xA_0000, 0x2_0000),
            w(mem, 0xF000_0000, 0x0EC0_0000),
        ]
        {
            assert!(
                windows.contains(&expected),
                "{expected:x?} not in {windows:x?}"
            );
        }
    }

    #[test]
    fn windows_past_the_push_bound_and_a_crs_that_is_no_buffer_are_errors()
    {
        // A WordBusNumber descriptor of one bus.
        let word_bus = [0x88, 0x0D, 0x00, 2, 0x0C, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0];
        let template = |n: usize| {
            let mut t: Vec<u8> = word_bus.repeat(n);
            t.extend([0x79, 0x00]);
            t
        };
        let body = [
            device(
                &sb(*b"A___"),
                &name(
                    b"_CRS",
                    &buffer(&template(devmgr_labels::MAX_BRIDGE_WINDOWS)),
                ),
            ),
            device(
                &sb(*b"B___"),
                &name(
                    b"_CRS",
                    &buffer(&template(devmgr_labels::MAX_BRIDGE_WINDOWS + 1)),
                ),
            ),
            device(&sb(*b"C___"), &name(b"_CRS", &dword(1))),
            device(&sb(*b"D___"), &[]),
        ]
        .concat();
        let mut ns = sim::namespace(&[sim::table(&body)]);
        let mut host = Sim::new();
        let mut ev = Evaluator::new(&mut ns, &mut host);
        let mut at = |p: &str| {
            let node = ev.namespace().find(p).unwrap();
            windows(&mut ev, node).map(|w| w.map(|w| w.len()))
        };
        assert_eq!(at("\\_SB.A"), Ok(Some(devmgr_labels::MAX_BRIDGE_WINDOWS)));
        assert_eq!(at("\\_SB.B"), Err(Why::Bound));
        assert_eq!(at("\\_SB.C"), Err(Why::Shape));
        assert_eq!(at("\\_SB.D"), Ok(None));
    }

    #[test]
    fn q35_routes_read_the_pirq_routing_in_the_pic_model_and_gsis_in_the_apic_model()
    {
        let (mut ns, mut host) = machine("x86-default");
        let mut ev = Evaluator::new(&mut ns, &mut host);
        let bridge = only_bridge(&mut ev);
        let pic = routes(&mut ev, bridge.node).unwrap().unwrap();
        assert_eq!(pic.routed, 128, "{:?}", pic.failures);
        assert_eq!(pic.failures, []);
        for device in 0..32
        {
            for pin in 0..4
            {
                assert!(matches!(lane(&pic, device, pin), 10 | 11), "{device}/{pin}");
            }
        }
        ev.evaluate_path("\\_PIC", vec![Data::Integer(1)]).unwrap();
        let apic = routes(&mut ev, bridge.node).unwrap().unwrap();
        assert_eq!(apic.routed, 128, "{:?}", apic.failures);
        for device in 0..32
        {
            for pin in 0..4
            {
                assert!(
                    (16..=23).contains(&lane(&apic, device, pin)),
                    "{device}/{pin}"
                );
            }
        }
    }

    #[test]
    fn riscv64_routes_are_the_virt_swizzle()
    {
        let (mut ns, mut host) = machine("riscv64-rootport");
        let mut ev = Evaluator::new(&mut ns, &mut host);
        let bridge = only_bridge(&mut ev);
        let routes = routes(&mut ev, bridge.node).unwrap().unwrap();
        assert_eq!(routes.routed, 128, "{:?}", routes.failures);
        for device in 0..32
        {
            for pin in 0..4u32
            {
                let expected = 0x20 + (device as u64 + u64::from(pin)) % 4;
                assert_eq!(lane(&routes, device, pin), expected, "{device}/{pin}");
            }
        }
    }

    #[test]
    fn the_pci_to_pci_bridges_with_a_prt_are_found_below_the_host_bridges_deepest_first()
    {
        let hid = name(b"_HID", &dword(PCI_EXPRESS_HOST_BRIDGE));
        let adr = |a: u32| name(b"_ADR", &dword(a));
        let prt = name(b"_PRT", &package(&[]));
        // Root port RP01 (00:1c.0) with a _PRT; below it a switch's upstream
        // port SW00 without one, and below that a downstream port DN01 at
        // device 1 with one. Root port RP02 (00:1c.1) without one. A device
        // with a _PRT outside any host bridge, and one below the host bridge
        // with no _ADR.
        let dn01 = device(b"DN01", &[adr(0x0001_0000), prt.clone()].concat());
        let sw00 = device(b"SW00", &[adr(0), dn01].concat());
        let rp01 = device(b"RP01", &[adr(0x001C_0000), prt.clone(), sw00].concat());
        let rp02 = device(b"RP02", &adr(0x001C_0001));
        let noad = device(b"NOAD", &prt);
        let body = [
            device(
                &sb(*b"PCI0"),
                &[hid, prt.clone(), rp01, rp02, noad].concat(),
            ),
            device(&sb(*b"OUT_"), &prt),
        ]
        .concat();
        let mut ns = sim::namespace(&[sim::table(&body)]);
        let mut host = Sim::new();
        let mut ev = Evaluator::new(&mut ns, &mut host);
        let bridge = only_bridge(&mut ev);
        let all: Vec<NodeId> = ev.namespace().nodes().collect();
        let (found, failures) = pci_bridges(&mut ev, &[bridge], &all);
        assert_eq!(failures, []);
        let ns = ev.namespace();
        let found: Vec<(Seg, Route)> = found
            .into_iter()
            .map(|b| (ns.name(b.node).unwrap(), b.route))
            .collect();
        let route = |hops: Vec<(u8, u8)>| Route {
            segment: 0,
            bus: 0,
            hops,
        };
        assert_eq!(
            found,
            [
                (*b"DN01", route(vec![(0x1C, 0), (0, 0), (1, 0)])),
                (*b"RP01", route(vec![(0x1C, 0)])),
            ]
        );
    }

    #[test]
    fn a_direct_route_is_kept_and_disabled_links_and_bad_entries_stay_unrouted()
    {
        let entry = |address: u32, pin: u8, source: Vec<u8>, index: u8| {
            package(&[dword(address), vec![0x0A, pin], source, vec![0x0A, index]])
        };
        // An IRQ descriptor with no line: a disabled link.
        let disabled = buffer(&[0x22, 0x00, 0x00, 0x79, 0x00]);
        let body = [
            device(&sb(*b"LNKZ"), &name(b"_CRS", &disabled)),
            device(
                &sb(*b"B___"),
                &name(
                    b"_PRT",
                    &package(&[
                        entry(0x0001_FFFF, 0, vec![0x00], 0x30),
                        entry(0x0002_FFFF, 1, b"LNKZ".to_vec(), 0),
                        entry(0x0003_FFFF, 5, vec![0x00], 1),
                        entry(0x0020_FFFF, 0, vec![0x00], 1),
                        entry(0x0004_FFFF, 0, b"NOPE".to_vec(), 0),
                    ]),
                ),
            ),
        ]
        .concat();
        let mut ns = sim::namespace(&[sim::table(&body)]);
        let mut host = Sim::new();
        let mut ev = Evaluator::new(&mut ns, &mut host);
        let node = ev.namespace().find("\\_SB.B").unwrap();
        let routes = routes(&mut ev, node).unwrap().unwrap();
        assert_eq!(routes.routed, 1);
        assert_eq!(lane(&routes, 1, 0), 0x30);
        let unrouted = routes
            .lanes
            .iter()
            .enumerate()
            .filter(|&(d, &w)| d != 1 && w == prt_unrouted())
            .count();
        assert_eq!(unrouted, 31);
        assert_eq!(routes.failures.len(), 3, "{:?}", routes.failures);
    }
}
