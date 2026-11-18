// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/acpid/src/hotplug.rs

//! The PCI hotplug events of a slot the firmware drives: which `Notify` a
//! slot's device takes ([`Event`]), the port that leads to the slot
//! ([`route`], [`port`]), and the slot's `_EJ0` and `_OST` acpid runs
//! once devmgr's job ends (services/acpid/README.md § Hotplug).

use aml::encoding::Seg;
use aml::host::{Host, PciAddress, Width};
use aml::namespace::NodeId;
use aml::{Data, Evaluator, Fault, Namespace};

use crate::bridge::Bridge;
use crate::{Why, child};

/// `Notify` value: Bus Check, re-enumerate below the device.
pub const BUS_CHECK: u64 = 0;
/// `Notify` value: Device Check, a device inserted or removed.
pub const DEVICE_CHECK: u64 = 1;
/// `Notify` value: Eject Request.
pub const EJECT_REQUEST: u64 = 3;

/// `_OST` status: success.
pub const OST_SUCCESS: u64 = 0;
/// `_OST` status: a failure the codes of the event do not name.
pub const OST_FAILURE: u64 = 1;
/// `_OST` status: the `Notify` value is not one the OS handles.
pub const OST_UNRECOGNIZED: u64 = 2;
/// `_OST` status of an Eject Request: ejection not supported by the OS.
pub const OST_EJECT_NOT_SUPPORTED: u64 = 0x80;

/// The configuration offset of a type-1 header's Secondary Bus Number.
pub const SECONDARY_BUS: u64 = 0x19;

/// A hotplug event of a slot's device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event
{
    /// A Bus Check or a Device Check: a card may have been added.
    Check,
    /// An Eject Request: the card is to be removed, then ejected.
    Eject,
}

impl Event
{
    /// The event of `Notify` value `value`; `None` for any other value.
    #[must_use]
    pub const fn of(value: u64) -> Option<Self>
    {
        match value
        {
            BUS_CHECK | DEVICE_CHECK => Some(Self::Check),
            EJECT_REQUEST => Some(Self::Eject),
            _ => None,
        }
    }

    /// The event's name in a log line.
    #[must_use]
    pub const fn name(self) -> &'static str
    {
        match self
        {
            Self::Check => "device check",
            Self::Eject => "eject request",
        }
    }
}

/// A `Notify` of a hotplug event the evaluated code made: the object's
/// absolute path, root first, and the value.
pub type HotplugNote = (Vec<Seg>, u64);

/// What [`keep`] did with a `Notify`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kept
{
    /// Kept for the evaluation thread.
    Kept,
    /// Not kept: the notes hold the same event of the same object already.
    Repeat,
    /// Not kept: its value is no hotplug event ([`Event::of`]).
    NotHotplug,
    /// Not kept: no memory was left to keep it.
    NoMemory,
}

/// Keep the `Notify` of `path` with `value` in `notes`, for the evaluation
/// thread to act on once the evaluation ends: a hotplug event ([`Event::of`])
/// that `notes` does not hold for the same object already. `notes` thus
/// holds at most one note per object and event, a bound the namespace's
/// objects set, and no event the firmware reports once (a device check,
/// whose QEMU register clears as the method reads it) is lost to a bound.
pub fn keep(notes: &mut Vec<HotplugNote>, path: &[Seg], value: u64) -> Kept
{
    let Some(event) = Event::of(value)
    else
    {
        return Kept::NotHotplug;
    };
    if notes
        .iter()
        .any(|(at, held)| at.as_slice() == path && Event::of(*held) == Some(event))
    {
        return Kept::Repeat;
    }
    let mut copy = Vec::new();
    if notes.try_reserve(1).is_err() || copy.try_reserve_exact(path.len()).is_err()
    {
        return Kept::NoMemory;
    }
    copy.extend_from_slice(path);
    notes.push((copy, value));
    Kept::Kept
}

/// The node of the absolute path `path`, root first, as the evaluator hands
/// a `Notify` target to its host.
#[must_use]
pub fn target(ns: &Namespace, path: &[Seg]) -> Option<NodeId>
{
    path.iter()
        .try_fold(NodeId::ROOT, |node, &seg| ns.child(node, seg))
}

/// The way from a host bridge's root bus to the port above a slot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Route
{
    /// The host bridge's segment.
    pub segment: u16,
    /// The host bridge's root bus.
    pub bus: u8,
    /// The device and function of each PCI-to-PCI bridge from the root bus
    /// down, the port above the slot last; never empty.
    pub hops: Vec<(u8, u8)>,
}

/// Why a `Notify` target names no slot below a port.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unresolved
{
    /// The target has no `_ADR`: it is not a PCI device.
    NotPci,
    /// The target's parent is a host bridge: it lies on a root bus, which
    /// no port leads to.
    RootBus,
    /// No host bridge acpid found lies above the target through PCI devices.
    NoBridge,
    /// The `_ADR` of a device above the target faulted, or names no single
    /// function.
    Address(Why),
}

/// The route to the port above `target`, a device below a PCI-to-PCI bridge
/// of one of `bridges`: the target's parent is the port, and each device
/// above it, up to the host bridge, a PCI-to-PCI bridge, each named by its
/// `_ADR`.
///
/// # Errors
///
/// The [`Unresolved`] that names why `target` has no such route.
pub fn route(
    ev: &mut Evaluator<'_>,
    bridges: &[Bridge],
    target: NodeId,
) -> Result<Route, Unresolved>
{
    if child(ev.namespace(), target, *b"_ADR").is_none()
    {
        return Err(Unresolved::NotPci);
    }
    let mut hops = Vec::new();
    let mut node = ev.namespace().parent(target).ok_or(Unresolved::NoBridge)?;
    loop
    {
        if let Some(bridge) = bridges.iter().find(|b| b.node == node)
        {
            if hops.is_empty()
            {
                return Err(Unresolved::RootBus);
            }
            hops.reverse();
            return Ok(Route {
                segment: bridge.segment,
                bus: bridge.bus,
                hops,
            });
        }
        let Some(adr) = child(ev.namespace(), node, *b"_ADR")
        else
        {
            return Err(Unresolved::NoBridge);
        };
        let value = ev
            .evaluate(adr, Vec::new())
            .map_err(|f| Unresolved::Address(Why::Fault(f)))?;
        hops.push(function(&value).ok_or(Unresolved::Address(Why::Shape))?);
        node = ev.namespace().parent(node).ok_or(Unresolved::NoBridge)?;
    }
}

/// The device and function an `_ADR` value names: the device in bits 16 to
/// 31, the function in bits 0 to 15; `None` for a value that is not an
/// integer or names no single function.
fn function(value: &Data) -> Option<(u8, u8)>
{
    let Data::Integer(adr) = *value
    else
    {
        return None;
    };
    let device = u8::try_from(adr >> 16).ok().filter(|&d| d < 32)?;
    let function = u8::try_from(adr & 0xFFFF).ok().filter(|&f| f < 8)?;
    Some((device, function))
}

/// The address of the port `route` ends at: each bridge above it read for
/// its Secondary Bus Number through `secondary`, which reads that register
/// ([`SECONDARY_BUS`]) of a function. `None` when a read fails.
pub fn port(
    route: &Route,
    mut secondary: impl FnMut(PciAddress) -> Option<u8>,
) -> Option<PciAddress>
{
    let (&(device, function), above) = route.hops.split_last()?;
    let mut bus = route.bus;
    for &(device, function) in above
    {
        bus = secondary(PciAddress {
            segment: route.segment,
            bus,
            device,
            function,
        })?;
    }
    Some(PciAddress {
        segment: route.segment,
        bus,
        device,
        function,
    })
}

/// The Secondary Bus Number of the bridge `function` ([`SECONDARY_BUS`]),
/// read through `host`; `None` when the read fails.
pub fn secondary_bus(host: &mut impl Host, function: PciAddress) -> Option<u8>
{
    host.pci_read(function, SECONDARY_BUS, Width::Byte)
        .ok()
        .and_then(|bus| u8::try_from(bus).ok())
}

/// A hotplug event of a slot, held until devmgr's job of it ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HotplugJob
{
    /// The slot's device, which the `Notify` named.
    pub slot: NodeId,
    /// The `Notify` value, which the slot's `_OST` answers.
    pub value: u64,
    /// The event the value reports.
    pub event: Event,
    /// The port above the slot, as `devmgr_labels::pci_function` packs it.
    pub port: u64,
}

/// What [`HotplugSlots::hold`] did with an event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Held
{
    /// Held, and no other event of its slot is: ask devmgr for its job now.
    Ask(HotplugJob),
    /// Held behind the event of its slot that devmgr was asked for.
    Queued,
    /// Not held: no memory was left to hold it.
    NoMemory,
}

/// The firmware's hotplug slots as acpid serves them: the PCI host bridges
/// whose ports lead to them, and the events held per slot, in `Notify`
/// order. One event of a slot at a time is asked of devmgr; the slot's
/// later events wait behind it. A slot holds at most one event of each
/// kind, so the held events are bounded by the slots the namespace holds.
#[derive(Debug, Default)]
pub struct HotplugSlots
{
    bridges: Vec<Bridge>,
    /// Each held event, and whether devmgr was asked for its job.
    held: Vec<(HotplugJob, bool)>,
}

impl HotplugSlots
{
    /// The slots behind the ports of `bridges`, holding no event.
    #[must_use]
    pub const fn new(bridges: Vec<Bridge>) -> Self
    {
        Self {
            bridges,
            held: Vec::new(),
        }
    }

    /// The host bridges whose ports lead to the slots.
    #[must_use]
    pub fn bridges(&self) -> &[Bridge]
    {
        &self.bridges
    }

    /// Whether `slot` holds an `event` already: the firmware's repeat of it.
    #[must_use]
    pub fn holds(&self, slot: NodeId, event: Event) -> bool
    {
        self.held
            .iter()
            .any(|(job, _)| job.slot == slot && job.event == event)
    }

    /// Hold `job`, which the caller has checked its slot does not hold
    /// ([`HotplugSlots::holds`]). It is marked asked when no other event of
    /// its slot is held, and the caller then asks devmgr for its job.
    pub fn hold(&mut self, job: HotplugJob) -> Held
    {
        if self.held.try_reserve(1).is_err()
        {
            return Held::NoMemory;
        }
        let queued = self.held.iter().any(|(held, _)| held.slot == job.slot);
        self.held.push((job, !queued));
        if queued { Held::Queued } else { Held::Ask(job) }
    }

    /// End the asked event of `slot`, whose devmgr job ended: the event,
    /// and the slot's next held event, marked asked, which the caller asks
    /// devmgr for next. `None` when `slot` has no asked event.
    pub fn end(&mut self, slot: NodeId) -> Option<(HotplugJob, Option<HotplugJob>)>
    {
        let at = self
            .held
            .iter()
            .position(|(job, asked)| job.slot == slot && *asked)?;
        let (ended, _) = self.held.remove(at);
        let next = self
            .held
            .iter_mut()
            .find(|(job, _)| job.slot == slot)
            .map(|(job, asked)| {
                *asked = true;
                *job
            });
        Some((ended, next))
    }
}

/// How devmgr's job of an event ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome
{
    /// The job ran, and for an Eject Request `_EJ0` succeeded.
    Done,
    /// devmgr refused the job: the slot is not one whose hotplug it takes
    /// from the firmware.
    Refused,
    /// The call to devmgr, or `_EJ0`, failed.
    Failed,
}

/// The `_OST` status of `event` that ended with `outcome`.
#[must_use]
pub const fn ost_status(event: Event, outcome: Outcome) -> u64
{
    match (event, outcome)
    {
        (_, Outcome::Done) => OST_SUCCESS,
        (Event::Eject, Outcome::Refused) => OST_EJECT_NOT_SUPPORTED,
        (_, Outcome::Refused | Outcome::Failed) => OST_FAILURE,
    }
}

/// Run `slot`'s `_EJ0(1)`; `None` when it has none.
pub fn eject(ev: &mut Evaluator<'_>, slot: NodeId) -> Option<Result<(), Fault>>
{
    let ej0 = child(ev.namespace(), slot, *b"_EJ0")?;
    Some(ev.evaluate(ej0, vec![Data::Integer(1)]).map(drop))
}

/// Run `slot`'s `_OST` with the `Notify` value `value` it answers,
/// `status`, and no status information; `None` when it has none.
pub fn ost(
    ev: &mut Evaluator<'_>,
    slot: NodeId,
    value: u64,
    status: u64,
) -> Option<Result<(), Fault>>
{
    let ost = child(ev.namespace(), slot, *b"_OST")?;
    Some(
        ev.evaluate(
            ost,
            vec![
                Data::Integer(value),
                Data::Integer(status),
                Data::Buffer(Vec::new()),
            ],
        )
        .map(drop),
    )
}

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::bridge::host_bridges;
    use crate::sim::{self, Sim, device, dword, name, pkg};

    /// `Method (name, args) { body }`.
    fn method_args(name: &[u8], args: u8, body: &[u8]) -> Vec<u8>
    {
        let mut out = vec![0x14];
        out.extend(pkg(&[name, &[args], body].concat()));
        out
    }

    /// `Store (ArgN, name)`.
    fn store_arg(arg: u8, name: &[u8]) -> Vec<u8>
    {
        [&[0x70, 0x68 + arg][..], name].concat()
    }

    /// A slot device `S00_` at device 0, with `_EJ0` and `_OST` that keep
    /// their arguments in `EJ__`, `OE__` and `OS__`.
    fn slot() -> Vec<u8>
    {
        device(
            b"S00_",
            &[
                name(b"_ADR", &dword(0)),
                name(b"EJ__", &dword(0xFF)),
                name(b"OE__", &dword(0xFF)),
                name(b"OS__", &dword(0xFF)),
                method_args(b"_EJ0", 1, &store_arg(0, b"EJ__")),
                method_args(
                    b"_OST",
                    3,
                    &[store_arg(0, b"OE__"), store_arg(1, b"OS__")].concat(),
                ),
            ]
            .concat(),
        )
    }

    /// A machine whose host bridge `\PCI0` has a bridge `BR0_` (device 2)
    /// with a port `PRT0` (device 0) below it and the slot below that; a
    /// slot on the root bus (`ROOT`), a device with no `_ADR` (`NOAD`), a
    /// port whose `_ADR` names every function (`ALLF`), and a slot outside
    /// every host bridge (`\DEV_.S01_`).
    fn machine() -> (Namespace, Sim)
    {
        let pci0 = device(
            b"PCI0",
            &[
                device(
                    b"BR0_",
                    &[
                        name(b"_ADR", &dword(0x0002_0000)),
                        device(b"PRT0", &[name(b"_ADR", &dword(0)), slot()].concat()),
                    ]
                    .concat(),
                ),
                device(b"ROOT", &name(b"_ADR", &dword(0x0003_0000))),
                device(b"NOAD", &[]),
                device(
                    b"ALLF",
                    &[
                        name(b"_ADR", &dword(0x0004_FFFF)),
                        device(b"S02_", &name(b"_ADR", &dword(0))),
                    ]
                    .concat(),
                ),
            ]
            .concat(),
        );
        let outside = device(b"DEV_", &device(b"S01_", &name(b"_ADR", &dword(0))));
        let ns = sim::namespace(&[sim::table(&[pci0, outside].concat())]);
        (ns, Sim::new())
    }

    fn bridge(ns: &Namespace) -> Bridge
    {
        Bridge {
            node: ns.find("\\PCI0").unwrap(),
            segment: 0,
            bus: 0,
        }
    }

    #[test]
    fn notify_values_name_the_checks_and_the_eject_request()
    {
        assert_eq!(Event::of(0), Some(Event::Check));
        assert_eq!(Event::of(1), Some(Event::Check));
        assert_eq!(Event::of(3), Some(Event::Eject));
        for other in [2, 4, 0x80]
        {
            assert_eq!(Event::of(other), None);
        }
    }

    #[test]
    fn the_q35_root_port_slot_leads_to_its_port()
    {
        let mut ns = sim::fixture("x86-rootport");
        let mut host = Sim::new();
        sim::run_module_code(&mut ns, &mut host);
        let slot = target(&ns, &[*b"_SB_", *b"PCI0", *b"SE0_", *b"S00_"]).unwrap();
        let mut ev = Evaluator::new(&mut ns, &mut host);
        let all: Vec<NodeId> = ev.namespace().nodes().collect();
        let (bridges, _) = host_bridges(&mut ev, &all);
        let route = route(&mut ev, &bridges, slot).unwrap();
        assert_eq!(
            route,
            Route {
                segment: 0,
                bus: 0,
                hops: vec![(0x1C, 0)]
            }
        );
        let port = port(&route, |_| panic!("a root port needs no bus read")).unwrap();
        assert_eq!(
            (port.segment, port.bus, port.device, port.function),
            (0, 0, 0x1C, 0)
        );
        // QEMU's slot has `_EJ0` and no `_OST`.
        assert!(child(ev.namespace(), slot, *b"_EJ0").is_some());
        assert_eq!(ost(&mut ev, slot, EJECT_REQUEST, OST_SUCCESS), None);
    }

    #[test]
    fn a_port_below_a_bridge_takes_the_bus_the_bridge_reads()
    {
        let (mut ns, mut host) = machine();
        let bridges = [bridge(&ns)];
        let slot = ns.find("\\PCI0.BR0_.PRT0.S00_").unwrap();
        let mut ev = Evaluator::new(&mut ns, &mut host);
        let route = route(&mut ev, &bridges, slot).unwrap();
        assert_eq!(route.hops, vec![(2, 0), (0, 0)]);
        let mut read = Vec::new();
        let port = port(&route, |f| {
            read.push((f.segment, f.bus, f.device, f.function));
            Some(5)
        })
        .unwrap();
        assert_eq!(read, vec![(0, 0, 2, 0)]);
        assert_eq!((port.bus, port.device, port.function), (5, 0, 0));
        // A bridge that reads no bus leaves the port unknown.
        assert_eq!(super::port(&route, |_| None), None);
    }

    #[test]
    fn a_target_off_every_port_is_unresolved()
    {
        let (mut ns, mut host) = machine();
        let bridges = [bridge(&ns)];
        let cases = [
            ("\\PCI0.ROOT", Unresolved::RootBus),
            ("\\PCI0.NOAD", Unresolved::NotPci),
            ("\\PCI0.ALLF.S02_", Unresolved::Address(Why::Shape)),
            ("\\DEV_.S01_", Unresolved::NoBridge),
        ];
        let nodes: Vec<(NodeId, Unresolved)> = cases
            .iter()
            .map(|&(path, why)| (ns.find(path).unwrap(), why))
            .collect();
        let mut ev = Evaluator::new(&mut ns, &mut host);
        for (node, why) in nodes
        {
            assert_eq!(route(&mut ev, &bridges, node), Err(why));
        }
    }

    #[test]
    fn eject_and_ost_run_the_slot_methods_with_their_arguments()
    {
        let (mut ns, mut host) = machine();
        let slot = ns.find("\\PCI0.BR0_.PRT0.S00_").unwrap();
        let mut ev = Evaluator::new(&mut ns, &mut host);
        assert_eq!(eject(&mut ev, slot), Some(Ok(())));
        assert_eq!(
            ost(
                &mut ev,
                slot,
                EJECT_REQUEST,
                ost_status(Event::Eject, Outcome::Refused)
            ),
            Some(Ok(()))
        );
        let read = |ev: &mut Evaluator<'_>, n: &str| {
            ev.evaluate_path(&format!("\\PCI0.BR0_.PRT0.S00_.{n}"), Vec::new())
                .unwrap()
        };
        assert_eq!(read(&mut ev, "EJ__"), Data::Integer(1));
        assert_eq!(read(&mut ev, "OE__"), Data::Integer(EJECT_REQUEST));
        assert_eq!(
            read(&mut ev, "OS__"),
            Data::Integer(OST_EJECT_NOT_SUPPORTED)
        );
        // A device without the methods runs neither.
        let root = ev.namespace().find("\\PCI0.ROOT").unwrap();
        assert_eq!(eject(&mut ev, root), None);
        assert_eq!(ost(&mut ev, root, DEVICE_CHECK, OST_SUCCESS), None);
    }

    #[test]
    fn ost_status_names_success_refusal_and_failure()
    {
        assert_eq!(ost_status(Event::Check, Outcome::Done), OST_SUCCESS);
        assert_eq!(ost_status(Event::Eject, Outcome::Done), OST_SUCCESS);
        assert_eq!(ost_status(Event::Check, Outcome::Refused), OST_FAILURE);
        assert_eq!(ost_status(Event::Check, Outcome::Failed), OST_FAILURE);
        assert_eq!(
            ost_status(Event::Eject, Outcome::Refused),
            OST_EJECT_NOT_SUPPORTED
        );
        assert_eq!(ost_status(Event::Eject, Outcome::Failed), OST_FAILURE);
    }

    #[test]
    fn a_note_is_kept_once_per_object_and_hotplug_event()
    {
        let slot: [Seg; 4] = [*b"_SB_", *b"PCI0", *b"SE0_", *b"S00_"];
        let other: [Seg; 4] = [*b"_SB_", *b"PCI0", *b"SE0_", *b"S08_"];
        let mut notes = Vec::new();
        assert_eq!(keep(&mut notes, &slot, DEVICE_CHECK), Kept::Kept);
        // A Bus Check is the same event as a Device Check.
        assert_eq!(keep(&mut notes, &slot, BUS_CHECK), Kept::Repeat);
        assert_eq!(keep(&mut notes, &slot, EJECT_REQUEST), Kept::Kept);
        assert_eq!(keep(&mut notes, &slot, EJECT_REQUEST), Kept::Repeat);
        assert_eq!(keep(&mut notes, &other, DEVICE_CHECK), Kept::Kept);
        // Device Wake, and a value past the hotplug ones, are not kept.
        assert_eq!(keep(&mut notes, &slot, 2), Kept::NotHotplug);
        assert_eq!(keep(&mut notes, &slot, 0x80), Kept::NotHotplug);
        assert_eq!(
            notes,
            vec![
                (slot.to_vec(), DEVICE_CHECK),
                (slot.to_vec(), EJECT_REQUEST),
                (other.to_vec(), DEVICE_CHECK)
            ]
        );
        // Many slots, each notified once, are all kept: no fixed bound
        // drops a device check.
        let mut many = Vec::new();
        for device in 0..=255u8
        {
            let path = [*b"_SB_", *b"PCI0", [b'S', b'0', b'0', device]];
            assert_eq!(keep(&mut many, &path, DEVICE_CHECK), Kept::Kept);
        }
        assert_eq!(many.len(), 256);
    }

    #[test]
    fn a_slot_asks_one_event_at_a_time_in_notify_order()
    {
        let ns = Namespace::new().unwrap();
        let (a, b) = (NodeId::ROOT, target(&ns, &[*b"_SB_"]).unwrap());
        let job = |slot, value, event| HotplugJob {
            slot,
            value,
            event,
            port: 0x1c0,
        };
        let check = job(a, DEVICE_CHECK, Event::Check);
        let eject = job(a, EJECT_REQUEST, Event::Eject);
        let other = job(b, BUS_CHECK, Event::Check);
        let mut slots = HotplugSlots::new(Vec::new());
        assert_eq!(slots.bridges(), &[]);
        assert_eq!(slots.hold(check), Held::Ask(check));
        assert!(slots.holds(a, Event::Check));
        assert!(!slots.holds(a, Event::Eject));
        // A later event of the slot waits behind the asked one; another
        // slot's is asked at once.
        assert_eq!(slots.hold(eject), Held::Queued);
        assert_eq!(slots.hold(other), Held::Ask(other));
        // An end with no asked event of its slot ends nothing.
        assert_eq!(HotplugSlots::default().end(a), None);
        assert_eq!(slots.end(a), Some((check, Some(eject))));
        assert!(!slots.holds(a, Event::Check));
        assert_eq!(slots.end(a), Some((eject, None)));
        assert_eq!(slots.end(a), None);
        assert_eq!(slots.end(b), Some((other, None)));
        assert_eq!(slots.end(b), None);
    }
}
