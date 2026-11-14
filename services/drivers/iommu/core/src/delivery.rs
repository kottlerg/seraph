// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/drivers/iommu/core/src/delivery.rs

//! What an IOMMU driver takes from the resource list devmgr delivers it
//! (`driver_binding::resources`), and the unit lookup over the scopes it
//! carries.
//!
//! The IOMMU record's list is one group per remapping unit, in unit-index
//! order: the unit's `IOMMU_UNIT` round (its PCI segment, whether it
//! translates every function of its segment no other unit names, and its
//! scope), then the unit's register `Mmio` range and, when devmgr gives it
//! one, its fault interrupt; then the end round, with the driver's service
//! endpoint and its devmgr query cap. devmgr parses the firmware's
//! description of the units (the ACPI DMAR on x86-64, the ACPI RIMT on
//! riscv64) and resolves each scope entry against the PCI topology before it
//! encodes it, so the driver reads no firmware table.

use alloc::vec::Vec;

use driver_binding::resources::{
    IommuUnit, MAX_IOMMU_UNITS, MAX_UNIT_REGISTER_PAGES, Resource, ResourceList,
};
use syscall_abi::PAGE_SIZE;

/// Every unit the list delivered, in unit-index order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Units(pub Vec<IommuUnit>);

impl Units
{
    /// The index of the unit that translates function `bdf` of `segment`:
    /// the first unit of the segment whose scope names it, else the
    /// segment's first include-all unit. `None` when no unit translates it.
    #[must_use]
    pub fn unit_for(&self, segment: u16, bdf: u16) -> Option<usize>
    {
        let mut catch_all = None;
        for (index, unit) in self.0.iter().enumerate()
        {
            if unit.segment != segment
            {
                continue;
            }
            if unit.scopes.iter().any(|s| s.covers(bdf))
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
}

/// One unit's register `Mmio` cap and the pages it spans.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Registers
{
    /// The `Mmio` cap.
    pub cap: u64,
    /// Pages the cap spans, 1 to [`MAX_UNIT_REGISTER_PAGES`].
    pub pages: u64,
}

/// What the IOMMU driver takes from its resource list.
#[derive(Debug, PartialEq, Eq)]
pub struct Delivery
{
    /// Each unit's register cap, by unit index.
    pub registers: Vec<Registers>,
    /// Each unit's fault interrupt, by unit index: the `Interrupt` resource
    /// of its group, `None` for a unit given none.
    pub faults: Vec<Option<Resource>>,
    /// Each unit's segment and scope, by unit index.
    pub units: Units,
    /// The driver's service endpoint.
    pub service_ep: u64,
    /// The driver's devmgr query cap, for `DRIVER_READY`.
    pub devmgr_query: u64,
}

/// Why a resource list is not an IOMMU record's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeliveryError
{
    /// The list has no end round, lacks the service or devmgr query
    /// endpoint, or carries a DMA capability; it holds no unit or more than
    /// [`MAX_IOMMU_UNITS`]; a resource comes before the first unit; or a
    /// unit's group is not one register `Mmio` range of 1 to
    /// [`MAX_UNIT_REGISTER_PAGES`] whole pages and at most one interrupt.
    Malformed,
    /// The unit tables could not be allocated.
    OutOfMemory,
}

/// The register range and fault interrupt of one unit's group.
fn group(resources: &[Resource]) -> Result<(Registers, Option<Resource>), DeliveryError>
{
    let mut registers = None;
    let mut fault = None;
    for &resource in resources
    {
        match resource
        {
            Resource::Mmio { cap, bytes, .. } if registers.is_none() =>
            {
                let pages = bytes / PAGE_SIZE;
                if bytes % PAGE_SIZE != 0 || !(1..=MAX_UNIT_REGISTER_PAGES).contains(&pages)
                {
                    return Err(DeliveryError::Malformed);
                }
                registers = Some(Registers { cap, pages });
            }
            Resource::Interrupt { .. } if fault.is_none() => fault = Some(resource),
            Resource::Mmio { .. } | Resource::IoPort { .. } | Resource::Interrupt { .. } =>
            {
                return Err(DeliveryError::Malformed);
            }
        }
    }
    let registers = registers.ok_or(DeliveryError::Malformed)?;
    Ok((registers, fault))
}

impl Delivery
{
    /// Read a complete resource list as an IOMMU record's.
    ///
    /// # Errors
    /// [`DeliveryError`].
    pub fn from_list(list: &ResourceList) -> Result<Self, DeliveryError>
    {
        let endpoints = list.endpoints().ok_or(DeliveryError::Malformed)?;
        let count = list.iommu_units().count();
        if endpoints.service == 0
            || endpoints.devmgr_query == 0
            || endpoints.dma != 0
            || !list.ungrouped().is_empty()
            || !(1..=MAX_IOMMU_UNITS).contains(&count)
        {
            return Err(DeliveryError::Malformed);
        }
        let mut registers = Vec::new();
        let mut faults = Vec::new();
        let mut units = Vec::new();
        registers
            .try_reserve_exact(count)
            .map_err(|_| DeliveryError::OutOfMemory)?;
        faults
            .try_reserve_exact(count)
            .map_err(|_| DeliveryError::OutOfMemory)?;
        units
            .try_reserve_exact(count)
            .map_err(|_| DeliveryError::OutOfMemory)?;
        for (unit, resources) in list.iommu_units()
        {
            let (register, fault) = group(resources)?;
            let mut scopes = Vec::new();
            scopes
                .try_reserve_exact(unit.scopes.len())
                .map_err(|_| DeliveryError::OutOfMemory)?;
            scopes.extend_from_slice(&unit.scopes);
            registers.push(register);
            faults.push(fault);
            units.push(IommuUnit {
                segment: unit.segment,
                include_pci_all: unit.include_pci_all,
                scopes,
            });
        }
        Ok(Self {
            registers,
            faults,
            units: Units(units),
            service_ep: endpoints.service,
            devmgr_query: endpoints.devmgr_query,
        })
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    use driver_binding::resources::{Endpoints, InterruptKind, Round, Scope};
    use ipc::bootstrap::BootstrapRound;
    use syscall_abi::{MSG_CAP_SLOTS_MAX, MSG_DATA_WORDS_MAX};

    fn received(sent: &Round) -> BootstrapRound
    {
        let mut r = BootstrapRound {
            caps: [0; MSG_CAP_SLOTS_MAX],
            cap_count: sent.caps().len(),
            data: [0; MSG_DATA_WORDS_MAX],
            data_words: sent.data().len(),
            done: sent.done(),
        };
        r.caps[..sent.caps().len()].copy_from_slice(sent.caps());
        r.data[..sent.data().len()].copy_from_slice(sent.data());
        r
    }

    fn list(rounds: &[Round]) -> ResourceList
    {
        let mut list = ResourceList::new();
        for round in rounds
        {
            list.absorb(&received(round)).expect("well-formed round");
        }
        list
    }

    /// The round of a unit of `segment` that translates the functions
    /// `scopes` names.
    fn unit(segment: u16, scopes: &[Scope]) -> Round
    {
        Round::iommu_unit(&IommuUnit {
            segment,
            include_pci_all: false,
            scopes: scopes.to_vec(),
        })
        .expect("the scopes fit")
    }

    /// The round of a unit of segment 0 that translates every function no
    /// other unit names.
    fn catch_all() -> Round
    {
        Round::iommu_unit(&IommuUnit {
            segment: 0,
            include_pci_all: true,
            scopes: Vec::new(),
        })
        .expect("no scopes fit")
    }

    fn end(dma: u64) -> Round
    {
        Round::end(&Endpoints {
            service: 70,
            devmgr_query: 71,
            dma,
        })
    }

    fn registers(cap: u64, pages: u64) -> Round
    {
        Round::mmio(cap, None, 0xFED9_0000, pages * PAGE_SIZE)
    }

    #[test]
    fn a_function_named_by_a_scope_goes_to_that_unit_before_the_catch_all()
    {
        let units = Units(vec![
            IommuUnit {
                segment: 0,
                include_pci_all: true,
                scopes: vec![],
            },
            IommuUnit {
                segment: 0,
                include_pci_all: false,
                scopes: vec![Scope::Function(0x0010)],
            },
            IommuUnit {
                segment: 1,
                include_pci_all: false,
                scopes: vec![Scope::Function(0x0018)],
            },
        ]);
        assert_eq!(units.unit_for(0, 0x0010), Some(1));
        assert_eq!(units.unit_for(0, 0x0018), Some(0));
        assert_eq!(units.unit_for(1, 0x0018), Some(2));
        assert_eq!(units.unit_for(1, 0x0010), None);
    }

    #[test]
    fn every_unit_its_registers_scope_and_fault_interrupt_are_taken()
    {
        let scopes = [Scope::Function(0x0008), Scope::Buses { first: 4, last: 5 }];
        let fault = Round::interrupts(InterruptKind::Msi, 0, 0, &[52]).expect("one vector");
        let d = Delivery::from_list(&list(&[
            unit(3, &scopes),
            registers(50, 1),
            fault,
            catch_all(),
            registers(51, 2),
            end(0),
        ]))
        .expect("an IOMMU delivery");
        assert_eq!(
            d.registers,
            [
                Registers { cap: 50, pages: 1 },
                Registers { cap: 51, pages: 2 }
            ]
        );
        assert!(matches!(
            d.faults[0],
            Some(Resource::Interrupt { cap: 52, .. })
        ));
        assert_eq!(d.faults[1], None);
        assert_eq!(d.units.0[0].segment, 3);
        assert!(!d.units.0[0].include_pci_all);
        assert_eq!(d.units.0[0].scopes, scopes);
        assert!(d.units.0[1].include_pci_all);
        assert_eq!((d.service_ep, d.devmgr_query), (70, 71));
    }

    #[test]
    fn a_list_that_is_no_iommu_records_is_refused()
    {
        let malformed = Err(DeliveryError::Malformed);
        let fault = || Round::interrupts(InterruptKind::Msi, 0, 0, &[52]).expect("one vector");
        let cases: &[&[Round]] = &[
            // No unit.
            &[registers(50, 1), end(0)],
            // A resource before the first unit.
            &[registers(49, 1), catch_all(), registers(50, 1), end(0)],
            // A unit without registers, with two ranges, with an I/O port.
            &[catch_all(), end(0)],
            &[catch_all(), registers(50, 1), registers(51, 1), end(0)],
            &[
                catch_all(),
                registers(50, 1),
                Round::io_port(51, 0x3F8, 8),
                end(0),
            ],
            // Two interrupts.
            &[catch_all(), registers(50, 1), fault(), fault(), end(0)],
            // A span of no pages' multiple, or past the bound.
            &[catch_all(), Round::mmio(50, None, 0, PAGE_SIZE + 8), end(0)],
            &[
                catch_all(),
                registers(50, MAX_UNIT_REGISTER_PAGES + 1),
                end(0),
            ],
            // A DMA capability.
            &[catch_all(), registers(50, 1), end(72)],
        ];
        for rounds in cases
        {
            assert_eq!(Delivery::from_list(&list(rounds)), malformed);
        }
        // No service endpoint.
        let no_service = Round::end(&Endpoints {
            service: 0,
            devmgr_query: 71,
            dma: 0,
        });
        let l = list(&[catch_all(), registers(50, 1), no_service]);
        assert_eq!(Delivery::from_list(&l), malformed);
        // No end round.
        let l = list(&[catch_all(), registers(50, 1)]);
        assert_eq!(Delivery::from_list(&l), malformed);
    }

    #[test]
    fn the_most_units_a_list_carries_are_taken()
    {
        let mut rounds = Vec::new();
        for cap in 0..MAX_IOMMU_UNITS as u64
        {
            rounds.push(if cap == 0 { catch_all() } else { unit(0, &[]) });
            rounds.push(registers(cap + 1, MAX_UNIT_REGISTER_PAGES));
        }
        rounds.push(end(0));
        let d = Delivery::from_list(&list(&rounds)).expect("an IOMMU delivery");
        assert_eq!(d.registers.len(), MAX_IOMMU_UNITS);
    }
}
