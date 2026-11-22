// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/devmgr/firmware/src/pci_records.rs

//! The PCI device records: every PCI function devmgr knows, the boot scan's
//! in record order (segment, bus, device, function), then each function
//! appended later in its order of arrival, with each record's place in the
//! bind passes ([`RecordState`]) and the pin and device number its `INTx`
//! reaches its root bus with ([`host_intx`])
//! ([docs/driver-binding.md](../../../../docs/driver-binding.md) § Device
//! Records).
//!
//! A record is never moved or taken out: a removed function's record stays,
//! [`RecordState::Removed`], so every record's index, and every catalog
//! entry and instance ordinal its driver was given, stays as it was, and a
//! function that arrives again at the same address is a record of its own.

extern crate alloc;

use alloc::collections::TryReserveError;
use alloc::vec::Vec;

use crate::scan::PciDevice;

/// Where a record stands in the bind passes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordState
{
    /// Neither a driver devmgr started nor devmgr itself holds the
    /// function; a pass may bind it.
    Unbound,
    /// A driver was started for the function, or devmgr took it itself: as a
    /// RISC-V IOMMU unit for the IOMMU driver, whether or not that driver
    /// starts, or as the port of a hotplug slot its poller manages; no pass
    /// binds it again.
    Bound,
    /// The function is gone: no pass matches the record again, and its
    /// address is free for a function that arrives there later.
    Removed,
}

/// Why [`PciRecords::append`] refused a function.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppendError
{
    /// A record that is not removed already holds the function's address.
    Present,
    /// The records could not grow; they are as they were.
    NoMemory,
}

/// The PCI device records, in record order, each with its state.
pub struct PciRecords
{
    devices: Vec<PciDevice>,
    /// The state of each record of `devices`, in the same order.
    states: Vec<RecordState>,
}

impl PciRecords
{
    /// The records of the boot scan's `devices`, sorted into record order,
    /// none bound, each given its `INTx` route to its root bus
    /// ([`host_intx`]); `None` when the states cannot be allocated.
    #[must_use]
    pub fn new(mut devices: Vec<PciDevice>) -> Option<Self>
    {
        devices.sort_unstable_by_key(address);
        let mut states = Vec::new();
        states.try_reserve_exact(devices.len()).ok()?;
        states.resize(devices.len(), RecordState::Unbound);
        // In place, with no temporary to allocate: `host_intx` reads no
        // record's route, only its address, pin and bridge buses.
        for index in 0..devices.len()
        {
            let route = devices.get(index).and_then(|d| host_intx(&devices, d));
            if let Some(device) = devices.get_mut(index)
            {
                device.host_intx = route;
            }
        }
        Some(Self { devices, states })
    }

    /// Every record, removed ones included, in record order.
    #[must_use]
    pub fn devices(&self) -> &[PciDevice]
    {
        &self.devices
    }

    /// The state of the record at `index`; `None` past the last record.
    #[must_use]
    pub fn state(&self, index: usize) -> Option<RecordState>
    {
        self.states.get(index).copied()
    }

    /// The function of the record at `index` when no driver has been
    /// started for it and it is not removed: one a pass may bind.
    #[must_use]
    pub fn unbound_at(&self, index: usize) -> Option<&PciDevice>
    {
        self.devices
            .get(index)
            .filter(|_| self.state(index) == Some(RecordState::Unbound))
    }

    /// Every record a pass may bind, with its index, in record order.
    pub fn unbound(&self) -> impl Iterator<Item = (usize, &PciDevice)>
    {
        self.devices
            .iter()
            .zip(&self.states)
            .enumerate()
            .filter(|(_, (_, state))| **state == RecordState::Unbound)
            .map(|(index, (device, _))| (index, device))
    }

    /// Record that the function of the record at `index` is held: a driver
    /// was started for it, or devmgr took it as a RISC-V IOMMU unit or a
    /// managed hotplug slot's port. Returns
    /// whether it was unbound; a bound or removed record is left as it is.
    pub fn mark_bound(&mut self, index: usize) -> bool
    {
        match self.states.get_mut(index)
        {
            Some(state @ RecordState::Unbound) =>
            {
                *state = RecordState::Bound;
                true
            }
            _ => false,
        }
    }

    /// Record that the function of the record at `index` is gone. Returns
    /// whether the record was not removed already.
    pub fn remove(&mut self, index: usize) -> bool
    {
        match self.states.get_mut(index)
        {
            Some(state) if *state != RecordState::Removed =>
            {
                *state = RecordState::Removed;
                true
            }
            _ => false,
        }
    }

    /// Append `device`, a function that arrived after the boot scan, as an
    /// unbound record after every other, given its `INTx` route through the
    /// records' bridges, and return its index.
    ///
    /// # Errors
    /// [`AppendError::Present`] when a record that is not removed holds its
    /// address; [`AppendError::NoMemory`] when the records cannot grow. The
    /// records are unchanged on either.
    pub fn append(&mut self, device: PciDevice) -> Result<usize, AppendError>
    {
        self.append_reserving(device, |devices, states| {
            devices.try_reserve(1)?;
            states.try_reserve(1)
        })
    }

    /// [`Self::append`], with `reserve` making room for one more record in
    /// each list before anything is changed.
    fn append_reserving<R>(
        &mut self,
        mut device: PciDevice,
        reserve: R,
    ) -> Result<usize, AppendError>
    where
        R: FnOnce(&mut Vec<PciDevice>, &mut Vec<RecordState>) -> Result<(), TryReserveError>,
    {
        let present = self
            .devices
            .iter()
            .zip(&self.states)
            .any(|(d, &s)| s != RecordState::Removed && address(d) == address(&device));
        if present
        {
            return Err(AppendError::Present);
        }
        reserve(&mut self.devices, &mut self.states).map_err(|_| AppendError::NoMemory)?;
        device.host_intx = host_intx(&self.devices, &device);
        let index = self.devices.len();
        self.devices.push(device);
        self.states.push(RecordState::Unbound);
        Ok(index)
    }
}

/// A function's address: segment, bus, device, function.
fn address(device: &PciDevice) -> (u16, u8, u8, u8)
{
    (device.segment, device.bus, device.dev, device.func)
}

/// The `INTx` pin and device number `function`'s interrupt pin reaches its
/// root bus with ([`intx_route`] with no bridge routing it).
#[must_use]
pub fn host_intx(records: &[PciDevice], function: &PciDevice) -> Option<(u8, u8)>
{
    intx_route(records, function, |_| false).map(|route| (route.pin, route.dev))
}

/// Where a function's `INTx` is routed: on the secondary bus of a
/// PCI-to-PCI bridge that routes it, or on its root bus.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IntxRoute
{
    /// The address (segment, bus, device, function) of the bridge whose
    /// secondary bus the interrupt is routed on; `None` for the root bus.
    pub bridge: Option<(u16, u8, u8, u8)>,
    /// The bus: the bridge's secondary bus, or the root bus.
    pub bus: u8,
    /// The pin, `INTA`..=`INTD` (1..=4), the interrupt reaches that bus with.
    pub pin: u8,
    /// The device number on that bus it reaches it at.
    pub dev: u8,
}

/// Where `function`'s interrupt pin is routed: walking up from its bus, on
/// the secondary bus of the first bridge `routes` holds for one that routes
/// its own buses (a PCI-to-PCI bridge with a `_PRT`), else on its root bus;
/// the pin swizzled at each bridge passed on the way by the device number
/// below it (PCI-to-PCI Bridge Architecture Specification § 9.1). A bridge is
/// one of `records`, in `function`'s segment, whose secondary bus is the bus
/// the walk is on; a bus no such bridge leads to is a root bus. A bridge whose
/// secondary bus is not above its own bus is not configured and leads
/// nowhere, so every step climbs to a lower bus and the walk ends. `None` for
/// a function with no pin (`INTA`..=`INTD`, 1..=4).
#[must_use]
pub fn intx_route(
    records: &[PciDevice],
    function: &PciDevice,
    routes: impl Fn((u16, u8, u8, u8)) -> bool,
) -> Option<IntxRoute>
{
    if !(1..=4).contains(&function.irq_pin)
    {
        return None;
    }
    let (mut pin, mut dev, mut bus) = (function.irq_pin, function.dev, function.bus);
    while let Some(bridge) = records.iter().find(|b| {
        b.segment == function.segment
            && b.bridge_buses
                .is_some_and(|(secondary, _)| secondary == bus && secondary > b.bus)
    })
    {
        if routes(address(bridge))
        {
            return Some(IntxRoute {
                bridge: Some(address(bridge)),
                bus,
                pin,
                dev,
            });
        }
        pin = swizzle(pin, dev);
        dev = bridge.dev;
        bus = bridge.bus;
    }
    Some(IntxRoute {
        bridge: None,
        bus,
        pin,
        dev,
    })
}

/// The pin on a bridge's primary side that pin `pin` (1..=4) of device
/// `dev` on its secondary bus is wired to (PCI-to-PCI Bridge Architecture
/// Specification § 9.1, Table 9-1).
fn swizzle(pin: u8, dev: u8) -> u8
{
    // `pin` is 1..=4, so each step stays below 8.
    (pin.saturating_sub(1).saturating_add(dev % 4) % 4).saturating_add(1)
}

#[cfg(test)]
mod tests
{
    use super::*;
    use virtio_core::VirtioPciStartupInfo;

    use crate::scan::MAX_BARS;

    /// A function at `(segment, bus, dev, func)` with `INTx` pin `pin`, a
    /// bridge to `bridge` (secondary, subordinate) when given.
    fn function(at: (u16, u8, u8, u8), pin: u8, bridge: Option<(u8, u8)>) -> PciDevice
    {
        PciDevice {
            segment: at.0,
            bus: at.1,
            dev: at.2,
            func: at.3,
            vendor_id: 0x1B36,
            device_id: 0x0001,
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
            bridge_buses: bridge,
            host_intx: None,
            msi: None,
            msix: None,
        }
    }

    fn addresses(records: &PciRecords) -> Vec<(u16, u8, u8, u8)>
    {
        records.devices().iter().map(address).collect()
    }

    /// A boot scan of three functions on bus 0, given out of order.
    fn boot() -> PciRecords
    {
        PciRecords::new(vec![
            function((0, 0, 3, 0), 1, None),
            function((0, 0, 1, 0), 1, None),
            function((0, 0, 2, 0), 1, None),
        ])
        .expect("states allocated")
    }

    #[test]
    fn appended_records_follow_the_boot_scan_in_arrival_order()
    {
        let mut records = boot();
        assert_eq!(records.append(function((0, 5, 0, 0), 1, None)), Ok(3));
        assert_eq!(records.append(function((0, 4, 0, 0), 1, None)), Ok(4));
        assert_eq!(
            addresses(&records),
            [
                (0, 0, 1, 0),
                (0, 0, 2, 0),
                (0, 0, 3, 0),
                (0, 5, 0, 0),
                (0, 4, 0, 0)
            ]
        );
        assert_eq!(records.state(4), Some(RecordState::Unbound));
    }

    #[test]
    fn a_removed_record_is_never_offered_to_a_pass_again()
    {
        let mut records = boot();
        assert!(records.remove(1));
        assert!(!records.remove(1));
        assert!(!records.mark_bound(1));
        assert_eq!(records.state(1), Some(RecordState::Removed));
        assert!(records.unbound_at(1).is_none());
        let offered: Vec<usize> = records.unbound().map(|(i, _)| i).collect();
        assert_eq!(offered, [0, 2]);
        // A bound record is not offered either, and stays bound.
        assert!(records.mark_bound(0));
        assert!(!records.mark_bound(0));
        let offered: Vec<usize> = records.unbound().map(|(i, _)| i).collect();
        assert_eq!(offered, [2]);
    }

    #[test]
    fn a_function_again_at_a_removed_address_is_a_new_record()
    {
        let mut records = boot();
        let again = function((0, 0, 2, 0), 1, None);
        assert_eq!(records.append(again), Err(AppendError::Present));
        assert!(records.mark_bound(1));
        assert!(records.remove(1));
        assert_eq!(records.append(again), Ok(3));
        assert_eq!(records.state(1), Some(RecordState::Removed));
        assert_eq!(records.state(3), Some(RecordState::Unbound));
        let offered: Vec<usize> = records.unbound().map(|(i, _)| i).collect();
        assert_eq!(offered, [0, 2, 3]);
    }

    #[test]
    fn a_refused_growth_leaves_the_records_as_they_were()
    {
        let mut records = boot();
        assert!(records.mark_bound(0));
        let refused = records.append_reserving(function((0, 6, 0, 0), 1, None), |_, _| {
            Vec::<u8>::new().try_reserve(usize::MAX)
        });
        assert_eq!(refused, Err(AppendError::NoMemory));
        assert_eq!(
            addresses(&records),
            [(0, 0, 1, 0), (0, 0, 2, 0), (0, 0, 3, 0)]
        );
        assert_eq!(records.state(0), Some(RecordState::Bound));
        assert_eq!(records.state(3), None);
        // The records still grow once memory allows.
        assert_eq!(records.append(function((0, 6, 0, 0), 1, None)), Ok(3));
    }

    #[test]
    fn a_root_bus_function_keeps_its_own_pin_and_device()
    {
        let records = boot();
        for device in records.devices()
        {
            assert_eq!(device.host_intx, Some((1, device.dev)));
        }
        let none = PciRecords::new(vec![function((0, 0, 4, 0), 0, None)]).expect("allocated");
        assert_eq!(none.devices()[0].host_intx, None);
    }

    #[test]
    fn the_pin_swizzles_at_each_bridge_on_the_way_to_the_root_bus()
    {
        // Root port 00:03.0 to bus 1; on it, a switch port 01:00.0 to bus 2.
        let records = PciRecords::new(vec![
            function((0, 0, 3, 0), 1, Some((1, 2))),
            function((0, 1, 0, 0), 1, Some((2, 2))),
            function((0, 1, 0, 1), 2, None),
            function((0, 2, 5, 0), 2, None),
        ])
        .expect("allocated");
        let route = |at| {
            records
                .devices()
                .iter()
                .find(|d| address(d) == at)
                .and_then(|d| d.host_intx)
        };
        // 01:00.1 INTB: device 0 leaves it INTB at the root port 00:03.
        assert_eq!(route((0, 1, 0, 1)), Some((2, 3)));
        // 02:05.0 INTB: device 5 turns it INTC on bus 1, and device 0 leaves
        // it INTC at the root port 00:03.
        assert_eq!(route((0, 2, 5, 0)), Some((3, 3)));
        // The bridges themselves, on their own pins.
        assert_eq!(route((0, 1, 0, 0)), Some((1, 3)));
        assert_eq!(route((0, 0, 3, 0)), Some((1, 3)));
    }

    #[test]
    fn a_bridge_that_routes_its_buses_ends_the_walk_at_its_secondary_bus()
    {
        // Root port 00:1c.0 to buses 1..=3; on bus 1, a switch's upstream port
        // 01:00.0 to buses 2..=3; on bus 2, a downstream port 02:01.0 to bus 3;
        // on bus 3, a function 03:00.0 on INTB.
        let records = PciRecords::new(vec![
            function((0, 0, 0x1C, 0), 1, Some((1, 3))),
            function((0, 1, 0, 0), 1, Some((2, 3))),
            function((0, 2, 1, 0), 1, Some((3, 3))),
            function((0, 3, 0, 0), 2, None),
        ])
        .expect("allocated");
        let leaf = records.devices()[3];
        let route = |routes: &[(u16, u8, u8, u8)]| {
            intx_route(records.devices(), &leaf, |at| routes.contains(&at))
        };
        // No bridge routes: INTB of device 0 on bus 3, INTB at device 1 on
        // bus 2, INTC at device 0 on bus 1, INTC at the root port 00:1c.
        assert_eq!(
            route(&[]),
            Some(IntxRoute {
                bridge: None,
                bus: 0,
                pin: 3,
                dev: 0x1C
            })
        );
        // The root port routes its buses: the walk ends on bus 1, the pin
        // swizzled across the two switch ports only.
        assert_eq!(
            route(&[(0, 0, 0x1C, 0)]),
            Some(IntxRoute {
                bridge: Some((0, 0, 0x1C, 0)),
                bus: 1,
                pin: 3,
                dev: 0
            })
        );
        // The nearest bridge that routes wins.
        assert_eq!(
            route(&[(0, 0, 0x1C, 0), (0, 2, 1, 0)]),
            Some(IntxRoute {
                bridge: Some((0, 2, 1, 0)),
                bus: 3,
                pin: 2,
                dev: 0
            })
        );
    }

    #[test]
    fn an_appended_function_is_routed_through_the_boot_bridges()
    {
        let mut records =
            PciRecords::new(vec![function((0, 0, 2, 0), 1, Some((7, 7)))]).expect("allocated");
        let index = records
            .append(function((0, 7, 0, 0), 4, None))
            .expect("appended");
        // INTD of device 0 is INTD at the port 00:02.
        assert_eq!(records.devices()[index].host_intx, Some((4, 2)));
    }

    #[test]
    fn an_unconfigured_bridge_or_another_segment_leads_nowhere()
    {
        let records = PciRecords::new(vec![
            // Secondary bus 0: never configured.
            function((0, 0, 2, 0), 1, Some((0, 0))),
            // A bridge to bus 3 in segment 1.
            function((1, 0, 4, 0), 1, Some((3, 3))),
            function((0, 3, 1, 0), 1, None),
        ])
        .expect("allocated");
        for device in records.devices()
        {
            assert_eq!(device.host_intx, Some((1, device.dev)));
        }
    }

    #[test]
    fn every_pin_and_device_swizzles_as_the_bridge_specification_tabulates()
    {
        // Table 9-1: device 0 keeps the pin, each further device turns it one
        // further, INTD wrapping to INTA.
        assert_eq!(swizzle(1, 0), 1);
        assert_eq!(swizzle(1, 1), 2);
        assert_eq!(swizzle(4, 1), 1);
        assert_eq!(swizzle(3, 2), 1);
        assert_eq!(swizzle(2, 7), 1);
        assert_eq!(swizzle(4, 31), 3);
    }
}
