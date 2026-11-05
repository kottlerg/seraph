// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/drivers/iommu/core/src/lib.rs

//! The part of an IOMMU driver that does not depend on the IOMMU family.
//!
//! devmgr spawns one IOMMU driver per family (VT-d on x86-64; the RISC-V
//! IOMMU), hands it each remapping unit's register cap and the PCI functions
//! the unit translates in the bootstrap rounds [`bootstrap`] specifies, and
//! drives it over `ipc::iommu_labels`. This crate holds what every family
//! shares: the bootstrap decode and the units' scopes ([`bootstrap`]), the
//! request handling with its version check, reply framing, and per-domain
//! bookkeeping, which bounds each request and catches overlap and misuse
//! before the family's code runs ([`service`]), the queue of polled faults
//! ([`faults`]), and the [`Backend`] trait each family implements. A family
//! binary is its `main` and its [`Backend`]. See
//! `docs/device-management.md` § IOMMU Discovery and Programming.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub mod bootstrap;
pub mod faults;
pub mod service;

pub use bootstrap::{Bootstrap, Registers, Scope, Units};
pub use faults::{Fault, FaultQueue};
pub use service::{CapOps, KernelCaps, Lock, MemoryCap, Service};

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

/// The translation limits of one unit ([`Backend::query`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnitInfo
{
    /// The widest IOVA the unit's tables translate, in bits.
    pub width_bits: u8,
    /// Domain IDs the unit supports, the reserved ones included.
    pub domain_ids: u32,
}

/// The family-specific half of an IOMMU driver: the registers and the
/// translation structures of its units.
///
/// [`Service`] calls every method with its request already checked: the unit
/// index names a unit the bootstrap delivered, a domain is one this backend
/// attached and has not blocked, and a range is page-aligned, nonempty,
/// within the unit's width, and clear of every other range of the domain.
/// Every method that changes what a device reaches returns only once the
/// hardware has done it, the invalidation it needs included.
pub trait Backend
{
    /// One attached function's state: its place in the unit's tables.
    type Domain;

    /// Program unit `unit` empty and turn translation on: from the return
    /// on, every function the unit translates reaches nothing until it is
    /// attached.
    ///
    /// # Errors
    /// [`BackendError::Timeout`] when the unit does not complete a command;
    /// [`BackendError::OutOfMemory`] when no root structure can be had;
    /// [`BackendError::Invalid`] when the unit offers no table format the
    /// backend builds.
    fn init_unit(&mut self, unit: usize) -> Result<(), BackendError>;

    /// Turn translation off on every unit [`Self::init_unit`] turned it on
    /// for, so a driver that cannot finish its setup leaves no device
    /// blocked behind a unit nothing programs.
    fn disable_all(&mut self);

    /// Point the function `bdf` (bus in bits 8..16, device and function
    /// below) of unit `unit` at a new empty domain with the domain ID `did`.
    ///
    /// # Errors
    /// As [`Self::init_unit`].
    fn attach(&mut self, unit: usize, bdf: u16, did: u32) -> Result<Self::Domain, BackendError>;

    /// Install `len` bytes from the physical address `phys` at `iova` in
    /// `domain`, readable by the device and, when `write`, writable.
    ///
    /// # Errors
    /// As [`Self::init_unit`]; nothing is installed on an error.
    fn map(
        &mut self,
        domain: &mut Self::Domain,
        iova: u64,
        phys: u64,
        len: u64,
        write: bool,
    ) -> Result<(), BackendError>;

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
}
