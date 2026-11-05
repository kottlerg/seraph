// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/drivers/iommu/vtd/src/backend.rs

//! The VT-d [`Backend`]: each unit's registers, root table, and context
//! tables, and each attached function's second-level page tables.
//!
//! Units run in legacy translation mode with register-based invalidation
//! (queued invalidation stays off), each command polled to completion within
//! [`INVALIDATION_TIMEOUT`] before the request it serves is answered. Fault
//! events stay masked; the fault recording registers are polled.

use std::sync::atomic::{Ordering, fence};
use std::time::{Duration, Instant};

use iommu_core::{Backend, BackendError, Fault, UnitInfo};
use iommu_vtd::regs::{self, Capability};
use iommu_vtd::tables::{
    SL_READ, SL_WRITE, SecondLevel, TableError, TableStore, context_entry, context_index,
    root_entry,
};

use crate::store::Store;

/// How long a unit may take to complete one command (a root-pointer set,
/// a translation enable or disable, a write-buffer flush, or a context-cache
/// or IOTLB invalidation) before the driver treats the unit as failed. A
/// register-based command completes in microseconds on hardware and at once
/// under QEMU; the bound is a hang guard, not a tuning value.
/// `docs/limits.md` classifies it.
pub const INVALIDATION_TIMEOUT: Duration = Duration::from_secs(1);

/// One remapping unit: its mapped registers, decoded capabilities, root
/// table, and the context table of each bus that has an attached function.
pub struct Unit
{
    /// Virtual address of the unit's register set.
    regs: u64,
    /// Bytes of the register set mapped from `regs`.
    regs_len: u64,
    cap: Capability,
    /// Byte offset of the IOTLB invalidation register.
    iotlb: usize,
    /// Second-level table depth the unit's domains get.
    levels: u32,
    /// IOVA width the unit's domains translate, in bits.
    width_bits: u8,
    /// Physical address of the root table; 0 before the unit is set up.
    root: u64,
    /// Physical address of each bus's context table; 0 for none yet.
    context: [u64; 256],
    enabled: bool,
}

impl Unit
{
    /// A unit whose registers are mapped `regs_len` bytes from `regs`.
    pub fn new(regs: u64, regs_len: u64) -> Self
    {
        Self {
            regs,
            regs_len,
            cap: Capability::decode(0),
            iotlb: 0,
            levels: 0,
            width_bits: 0,
            root: 0,
            context: [0; 256],
            enabled: false,
        }
    }

    fn checked(&self, off: usize, width: u64) -> Option<u64>
    {
        let off = off as u64;
        (off + width <= self.regs_len).then_some(self.regs + off)
    }

    fn read32(&self, off: usize) -> u32
    {
        let Some(addr) = self.checked(off, 4)
        else
        {
            return u32::MAX;
        };
        // SAFETY: `addr` lies in the register set mapped from `regs` for the
        // driver's life (`checked`), reached only through raw volatile
        // accesses; every VT-d register is naturally aligned.
        unsafe { core::ptr::read_volatile(addr as *const u32) }
    }

    /// Write a 32-bit register. Every write the driver makes starts or
    /// configures a unit operation that may read the translation structures,
    /// so it is fenced after every table store the driver made before it.
    fn write32(&self, off: usize, value: u32)
    {
        fence(Ordering::SeqCst);
        if let Some(addr) = self.checked(off, 4)
        {
            // SAFETY: as in `read32`.
            unsafe { core::ptr::write_volatile(addr as *mut u32, value) };
        }
    }

    fn read64(&self, off: usize) -> u64
    {
        let Some(addr) = self.checked(off, 8)
        else
        {
            return u64::MAX;
        };
        // SAFETY: as in `read32`.
        unsafe { core::ptr::read_volatile(addr as *const u64) }
    }

    /// Write a 64-bit register, fenced as [`Self::write32`] is.
    fn write64(&self, off: usize, value: u64)
    {
        fence(Ordering::SeqCst);
        if let Some(addr) = self.checked(off, 8)
        {
            // SAFETY: as in `read32`.
            unsafe { core::ptr::write_volatile(addr as *mut u64, value) };
        }
    }

    /// Poll until `done` holds, at most [`INVALIDATION_TIMEOUT`].
    fn wait(&self, mut done: impl FnMut(&Self) -> bool) -> Result<(), BackendError>
    {
        let start = Instant::now();
        loop
        {
            if done(self)
            {
                return Ok(());
            }
            if start.elapsed() > INVALIDATION_TIMEOUT
            {
                return Err(BackendError::Timeout);
            }
            core::hint::spin_loop();
        }
    }

    /// Set a persistent `GCMD` state and wait for `GSTS` to report it.
    fn enable(&self, bit: u32) -> Result<(), BackendError>
    {
        let gsts = self.read32(regs::GSTS);
        self.write32(regs::GCMD, regs::gcmd_set(gsts, bit));
        self.wait(|u| u.read32(regs::GSTS) & bit != 0)
    }

    /// Clear a persistent `GCMD` state and wait for `GSTS` to report it.
    fn disable(&self, bit: u32) -> Result<(), BackendError>
    {
        let gsts = self.read32(regs::GSTS);
        self.write32(regs::GCMD, regs::gcmd_clear(gsts, bit));
        self.wait(|u| u.read32(regs::GSTS) & bit == 0)
    }

    /// Set the root table pointer from `RTADDR`.
    fn set_root(&self) -> Result<(), BackendError>
    {
        let gsts = self.read32(regs::GSTS);
        self.write32(regs::GCMD, regs::gcmd_set(gsts, regs::G_SRTP));
        self.wait(|u| u.read32(regs::GSTS) & regs::G_SRTP != 0)
    }

    /// Flush the unit's write buffer, when it requires it.
    fn flush_write_buffer(&self) -> Result<(), BackendError>
    {
        if !self.cap.write_buffer_flush
        {
            return Ok(());
        }
        let gsts = self.read32(regs::GSTS);
        self.write32(regs::GCMD, regs::gcmd_set(gsts, regs::G_WBF));
        self.wait(|u| u.read32(regs::GSTS) & regs::G_WBF == 0)
    }

    /// Invalidate the whole context cache.
    fn invalidate_context(&self) -> Result<(), BackendError>
    {
        self.write64(regs::CCMD, regs::ccmd_global());
        self.wait(|u| u.read64(regs::CCMD) & regs::CCMD_ICC == 0)
    }

    /// Invalidate the IOTLB with `command` (`iotlb_global`, `iotlb_domain`).
    fn invalidate_iotlb(&self, command: u64) -> Result<(), BackendError>
    {
        self.write64(self.iotlb, command);
        self.wait(|u| u.read64(u.iotlb) & regs::IOTLB_IVT == 0)
    }

    /// Clear every fault recording register and the overflow flag.
    fn clear_faults(&self)
    {
        for i in 0..self.cap.fault_count
        {
            self.write64(self.cap.fault_offset + i * 16 + 8, regs::FAULT_CLEAR);
        }
        self.write32(regs::FSTS, regs::FSTS_PFO);
    }
}

/// One attached function: its unit, place in the unit's tables, domain ID,
/// and second-level tables.
pub struct VtdDomain
{
    unit: usize,
    bus: usize,
    entry: usize,
    did: u16,
    tables: SecondLevel,
}

/// Every unit the driver serves and the store of their table pages.
pub struct Vtd
{
    units: Vec<Unit>,
    store: Store,
}

impl Vtd
{
    /// A backend over `units`, building its tables in `store`.
    pub fn new(units: Vec<Unit>, store: Store) -> Self
    {
        Self { units, store }
    }

    /// Write a two-word entry of the table page `table` at word `index`, the
    /// high word first, so the unit never reads a present low word beside a
    /// stale high one, and flush it. The stores are volatile, so they reach
    /// memory in that order (x86-64 keeps stores in program order).
    fn write_entry(&mut self, table: u64, index: usize, words: [u64; 2])
    {
        let t = self.store.table(table);
        // SAFETY: both words lie in the table page `t` borrows exclusively.
        unsafe {
            core::ptr::write_volatile(&raw mut t[index + 1], words[1]);
            core::ptr::write_volatile(&raw mut t[index], words[0]);
        }
        self.store.flush(table, (index * 8) as u64, 16);
    }

    /// Make the unit see a changed context entry: flush its write buffer,
    /// then invalidate the context cache and the IOTLB of domain `did`.
    fn context_changed(&self, unit: usize, did: u16) -> Result<(), BackendError>
    {
        let u = &self.units[unit];
        u.flush_write_buffer()?;
        u.invalidate_context()?;
        u.invalidate_iotlb(regs::iotlb_domain(did))
    }

    /// Set unit `unit` up empty, then turn translation on.
    fn setup(&mut self, unit: usize) -> Result<(), BackendError>
    {
        let u = &mut self.units[unit];
        u.cap = Capability::decode(u.read64(regs::CAP));
        let ecap = u.read64(regs::ECAP);
        u.iotlb = regs::iotlb_offset(ecap);
        let (levels, bits) = u.cap.table_depth().ok_or(BackendError::Invalid)?;
        u.levels = levels;
        u.width_bits = bits.min(u.cap.mgaw);
        let last_fault = u.cap.fault_offset + u.cap.fault_count * 16;
        if u.checked(u.iotlb, 8).is_none() || u.checked(last_fault - 8, 8).is_none()
        {
            return Err(BackendError::Invalid);
        }
        // Firmware may leave translation or queued invalidation on; both are
        // turned off before the root pointer changes.
        let gsts = u.read32(regs::GSTS);
        if gsts & regs::G_TE != 0
        {
            u.disable(regs::G_TE)?;
        }
        if gsts & regs::G_QIE != 0
        {
            u.disable(regs::G_QIE)?;
        }
        u.write32(regs::FECTL, regs::FECTL_IM);
        u.clear_faults();
        let root = self.store.alloc().ok_or(BackendError::OutOfMemory)?;
        let u = &mut self.units[unit];
        u.root = root;
        u.write64(regs::RTADDR, root);
        u.set_root()?;
        u.flush_write_buffer()?;
        u.invalidate_context()?;
        u.invalidate_iotlb(regs::iotlb_global())?;
        u.enable(regs::G_TE)?;
        u.enabled = true;
        Ok(())
    }
}

/// The backend error for a table operation's failure.
fn table_error(e: TableError) -> BackendError
{
    match e
    {
        TableError::OutOfMemory => BackendError::OutOfMemory,
        TableError::Invalid | TableError::InUse | TableError::NotMapped => BackendError::Invalid,
    }
}

impl Backend for Vtd
{
    type Domain = VtdDomain;

    fn init_unit(&mut self, unit: usize) -> Result<(), BackendError>
    {
        self.setup(unit)
    }

    fn disable_all(&mut self)
    {
        for u in &mut self.units
        {
            if u.enabled && u.disable(regs::G_TE).is_ok()
            {
                u.enabled = false;
            }
        }
    }

    fn attach(&mut self, unit: usize, bdf: u16, did: u32) -> Result<VtdDomain, BackendError>
    {
        let did = u16::try_from(did).map_err(|_| BackendError::Invalid)?;
        let [bus, devfn] = bdf.to_be_bytes();
        let bus = usize::from(bus);
        if self.units[unit].context[bus] == 0
        {
            let table = self.store.alloc().ok_or(BackendError::OutOfMemory)?;
            let root = self.units[unit].root;
            self.write_entry(root, bus * 2, root_entry(table));
            self.units[unit].context[bus] = table;
        }
        let levels = self.units[unit].levels;
        let tables = SecondLevel::new(&mut self.store, levels).ok_or(BackendError::OutOfMemory)?;
        let entry = context_index(devfn >> 3, devfn & 7);
        let context = self.units[unit].context[bus];
        self.write_entry(context, entry, context_entry(tables.root(), levels, did));
        self.context_changed(unit, did)?;
        Ok(VtdDomain {
            unit,
            bus,
            entry,
            did,
            tables,
        })
    }

    fn map(
        &mut self,
        domain: &mut VtdDomain,
        iova: u64,
        phys: u64,
        len: u64,
        write: bool,
    ) -> Result<(), BackendError>
    {
        let rights = if write { SL_READ | SL_WRITE } else { SL_READ };
        let mapped = domain.tables.map(&mut self.store, iova, phys, len, rights);
        let u = &self.units[domain.unit];
        u.flush_write_buffer()?;
        // A map that failed part-way undid the entries it wrote, which the
        // unit may have cached meanwhile; a unit in caching mode may cache
        // the not-present entries a range replaced. Either needs the
        // domain's IOTLB invalidated.
        if mapped.is_err() || u.cap.caching_mode
        {
            u.invalidate_iotlb(regs::iotlb_domain(domain.did))?;
        }
        mapped.map_err(table_error)
    }

    fn unmap(&mut self, domain: &mut VtdDomain, iova: u64, len: u64) -> Result<(), BackendError>
    {
        domain
            .tables
            .unmap(&mut self.store, iova, len)
            .map_err(table_error)?;
        let u = &self.units[domain.unit];
        u.flush_write_buffer()?;
        u.invalidate_iotlb(regs::iotlb_domain(domain.did))
    }

    fn block(&mut self, domain: &mut VtdDomain) -> Result<(), BackendError>
    {
        let context = self.units[domain.unit].context[domain.bus];
        // The low word, which holds the present bit, is cleared first; the
        // stores are volatile, so they reach memory in that order.
        let t = self.store.table(context);
        // SAFETY: both words lie in the table page `t` borrows exclusively.
        unsafe {
            core::ptr::write_volatile(&raw mut t[domain.entry], 0);
            core::ptr::write_volatile(&raw mut t[domain.entry + 1], 0);
        }
        self.store.flush(context, (domain.entry * 8) as u64, 16);
        self.context_changed(domain.unit, domain.did)
    }

    fn query(&self, unit: usize) -> UnitInfo
    {
        let u = &self.units[unit];
        UnitInfo {
            width_bits: u.width_bits,
            domain_ids: u.cap.domains,
        }
    }

    fn poll_faults(&mut self, record: &mut dyn FnMut(Fault))
    {
        for (index, u) in self.units.iter().enumerate()
        {
            if !u.enabled
            {
                continue;
            }
            let fsts = u.read32(regs::FSTS);
            if fsts & regs::FSTS_PPF != 0
            {
                let first = regs::fault_record_index(fsts);
                for i in 0..u.cap.fault_count
                {
                    let off = u.cap.fault_offset + ((first + i) % u.cap.fault_count) * 16;
                    let Some(f) = regs::decode_fault(u.read64(off), u.read64(off + 8))
                    else
                    {
                        continue;
                    };
                    record(Fault {
                        unit: index,
                        bdf: f.source_id,
                        reason: f.reason,
                        iova: f.address,
                    });
                    u.write64(off + 8, regs::FAULT_CLEAR);
                }
            }
            if fsts & regs::FSTS_PFO != 0
            {
                u.write32(regs::FSTS, regs::FSTS_PFO);
            }
        }
    }
}
