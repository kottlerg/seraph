// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/drivers/iommu/core/src/lib.rs

//! The part of an IOMMU driver that does not depend on the IOMMU family.
//!
//! devmgr spawns one IOMMU driver per family (VT-d on x86-64; the RISC-V
//! IOMMU), delivers it each remapping unit's register cap, the root page it
//! keeps for the unit (its anchor), and the PCI functions the unit
//! translates in its resource list (`driver_binding::resources`), and drives
//! it over `ipc::iommu_labels`; it restarts the driver after a death, the
//! new instance adopting the units translating from their anchors.
//! This crate holds what every family shares: what the driver takes from
//! that list and the unit lookup over the units' scopes ([`delivery`]), the
//! request handling with its version check, reply framing, and per-domain
//! bookkeeping, which bounds each request and catches overlap and misuse
//! before the family's code runs ([`service`]), the queue of polled faults
//! ([`faults`]), the [`TableStore`] each family's translation structures are
//! built in ([`table`]), the write rule a restarted driver's commit copies
//! its staged root entries into the anchors by ([`anchor`]), and the
//! [`Backend`] trait each family implements. A
//! family binary is its `main` and its [`Backend`]. See
//! `docs/device-management.md` § IOMMU Discovery and Programming.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub mod anchor;
pub mod delivery;
pub mod faults;
pub mod service;
pub mod table;

pub use delivery::{Delivery, DeliveryError, Registers, Units};
pub use driver_binding::resources::{IommuUnit, Scope};
pub use faults::{Fault, FaultQueue};
pub use service::{CapOps, KernelCaps, Lock, MAX_REMAP_ENTRIES, MemoryCap, Service};
pub use table::TableStore;

/// Why a [`Backend`] operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackendError
{
    /// The request names a page, address, or entry the unit's tables cannot
    /// hold.
    Invalid,
    /// The backend could not take memory for a table.
    OutOfMemory,
    /// The unit did not complete a command within the backend's bound; the
    /// unit is treated as failed from then on.
    Timeout,
}

/// How a backend sets its units up ([`Backend::init_unit`]), from the resource
/// list's restart flag ([`Units::start`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Start
{
    /// Program each unit empty, its anchor the root, whatever an earlier
    /// owner (the firmware) left on.
    Reset,
    /// Adopt each unit translating from its anchor through a dead
    /// instance's tables, and stage this instance's tables until
    /// [`Backend::commit`].
    Adopt,
}

/// How a mapping lets the device reach its frames ([`Backend::map`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access
{
    /// The device may read the frames only.
    Read,
    /// The device may read and write the frames.
    ReadWrite,
}

/// The translation limits of one unit ([`Backend::query`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnitInfo
{
    /// The widest IOVA the unit's tables translate, in bits.
    pub width_bits: u8,
    /// Domain IDs the unit supports, the reserved ones included.
    pub domain_ids: u32,
}

/// What one interrupt remapping entry delivers ([`Backend::remap_set`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RemapEntry
{
    /// The destination CPU's interrupt controller ID: 32-bit when the
    /// remapping was set up with extended destinations, else 8-bit.
    pub destination: u32,
    /// The vector the destination CPU takes.
    pub vector: u8,
    /// Level-triggered; edge-triggered when false.
    pub level: bool,
    /// The source ID (bus, device, function) of the only requester the
    /// entry accepts.
    pub source_id: u16,
}

/// The family-specific half of an IOMMU driver: the registers and the
/// translation structures of its units.
///
/// [`Service`] calls every method with its request already checked: the unit
/// index names a unit the resource list delivered, a domain is one this backend
/// attached and has not blocked, and a range or an interrupt file's page is
/// page-aligned, nonempty, within the unit's width, and clear of every other
/// range of the domain, and a remapping entry's handle lies below the
/// table's entries, its destination within the width the setup gave, and its
/// vector at 16 or above.
/// Every method that changes what a device reaches returns only once the
/// hardware has done it, the invalidation it needs included.
pub trait Backend
{
    /// One attached function's state: its place in the unit's tables.
    type Domain;

    /// Program unit `unit` with its anchor as an empty root and turn
    /// translation on: from the return on, every function the unit
    /// translates reaches nothing until it is attached.
    ///
    /// A backend built to adopt (a restarted driver's) instead requires the
    /// unit to be translating from its anchor, leaves translation and
    /// interrupt remapping as they stand, replaces only the unit's queues,
    /// and builds every later attach under a staging root of its own until
    /// [`Self::commit`]: the unit keeps translating through the dead
    /// instance's tables until then.
    ///
    /// # Errors
    /// [`BackendError::Timeout`] when the unit does not complete a command;
    /// [`BackendError::OutOfMemory`] when no root structure or queue can be
    /// had; [`BackendError::Invalid`] when the unit offers no table format
    /// the backend builds, or, adopting, does not translate from its anchor
    /// in the format the backend builds.
    fn init_unit(&mut self, unit: usize) -> Result<(), BackendError>;

    /// Turn translation off on every unit [`Self::init_unit`] turned it on
    /// for, so a driver that cannot finish its setup leaves no device
    /// blocked behind a unit nothing programs. A backend that adopted its
    /// units turns nothing off: they keep translating through the tables
    /// they hold.
    fn disable_all(&mut self);

    /// Copy each staged root entry into every unit's anchor by the
    /// [`anchor`] write rule, then invalidate each unit's translation
    /// caches, draining the device accesses in flight; from the return on
    /// every unit translates through this backend's tables alone, and every
    /// later change is made to them in place (`iommu_labels::COMMIT`). On
    /// VT-d, every remapping entry not set since the adoption is made not
    /// present too.
    ///
    /// # Errors
    /// [`BackendError::Invalid`] from a backend that did not adopt;
    /// [`BackendError::Timeout`] when a unit does not complete an
    /// invalidation.
    fn commit(&mut self) -> Result<(), BackendError>;

    /// Point the function `bdf` (bus in bits 8..16, device and function
    /// below) of unit `unit` at a new empty domain with the domain ID `did`.
    ///
    /// # Errors
    /// As [`Self::init_unit`].
    fn attach(&mut self, unit: usize, bdf: u16, did: u32) -> Result<Self::Domain, BackendError>;

    /// Install `len` bytes from the physical address `phys` at `iova` in
    /// `domain`, reachable by the device as `access` allows.
    ///
    /// # Errors
    /// As [`Self::init_unit`]; nothing is installed on an error.
    fn map(
        &mut self,
        domain: &mut Self::Domain,
        iova: u64,
        phys: u64,
        len: u64,
        access: Access,
    ) -> Result<(), BackendError>;

    /// Make the interrupt file whose page is at the physical address `file`
    /// reachable by `domain`'s device at that address, so the device's MSI
    /// writes to it reach it (`iommu_labels::MAP_MSI`).
    ///
    /// # Errors
    /// As [`Self::init_unit`], nothing being installed on an error;
    /// [`BackendError::Invalid`] from a family whose MSIs its DMA
    /// translation does not reach.
    fn map_msi(&mut self, domain: &mut Self::Domain, file: u64) -> Result<(), BackendError>;

    /// Remove the `len` bytes at `iova` from `domain`.
    ///
    /// # Errors
    /// As [`Self::init_unit`].
    fn unmap(&mut self, domain: &mut Self::Domain, iova: u64, len: u64)
    -> Result<(), BackendError>;

    /// Block the function `domain` belongs to: it reaches no frame from the
    /// return on, every range of the domain included.
    ///
    /// # Errors
    /// As [`Self::init_unit`].
    fn block(&mut self, domain: &mut Self::Domain) -> Result<(), BackendError>;

    /// The translation limits of unit `unit`.
    fn query(&self, unit: usize) -> UnitInfo;

    /// Read and clear the faults every unit has recorded since the last
    /// call, passing each to `record`.
    fn poll_faults(&mut self, record: &mut dyn FnMut(Fault));

    /// Point every unit at one interrupt remapping table of `entries`
    /// entries ([`service::MAX_REMAP_ENTRIES`] at most, a power of two) in
    /// the zeroed, physically contiguous memory of the Memory cap `table`,
    /// which the backend keeps, none present, and turn interrupt remapping
    /// on with interrupts in the compatibility format blocked: from the
    /// return on, an interrupt message reaches a CPU only through an entry
    /// [`Self::remap_set`] made. `extended` asks for 32-bit destinations;
    /// the return says whether every unit gave them. A backend that
    /// adopted its units instead requires every unit to be remapping from
    /// `table` already, in the destination width this call would give, and
    /// adopts the table with its entries as they stand.
    ///
    /// # Errors
    /// [`BackendError::Invalid`] from a family that does not remap
    /// interrupts, when a unit offers no interrupt remapping, or, adopting,
    /// when a unit does not remap from `table`;
    /// [`BackendError::OutOfMemory`] when the table cannot be mapped;
    /// [`BackendError::Timeout`] when a unit does not complete a command.
    /// Interrupt remapping is off on every unit after an error, except on
    /// units the backend adopted, which are left as they stood.
    #[expect(
        clippy::fn_params_excessive_bools,
        reason = "`extended` is the units' extended interrupt mode, which each backend writes to \
                  its unit"
    )]
    fn remap_enable(
        &mut self,
        entries: u32,
        extended: bool,
        table: u64,
    ) -> Result<bool, BackendError>;

    /// Turn interrupt remapping off on every unit [`Self::remap_enable`]
    /// turned it on for; none on units the backend adopted.
    fn remap_disable(&mut self);

    /// Make entry `handle` of the remapping table deliver as `entry` says,
    /// replacing what it held.
    ///
    /// # Errors
    /// [`BackendError::Timeout`] when a unit does not complete the
    /// invalidation of its cached copy; [`BackendError::Invalid`] from a
    /// family that does not remap interrupts.
    fn remap_set(&mut self, handle: u16, entry: RemapEntry) -> Result<(), BackendError>;

    /// Make entry `handle` of the remapping table not present: an interrupt
    /// naming it is blocked and faulted from the return on.
    ///
    /// # Errors
    /// As [`Self::remap_set`].
    fn remap_clear(&mut self, handle: u16) -> Result<(), BackendError>;
}
