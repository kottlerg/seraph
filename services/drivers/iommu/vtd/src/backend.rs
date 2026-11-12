// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/drivers/iommu/vtd/src/backend.rs

//! The VT-d [`Backend`]: each unit's registers, invalidation queue, root
//! table, and context tables, each attached function's second-level page
//! tables, and the one interrupt remapping table every unit shares.
//!
//! Units run in legacy translation mode with queued invalidation: every
//! invalidation is a batch of descriptors ended by a wait descriptor whose
//! status write is polled within [`INVALIDATION_TIMEOUT`] before the request
//! it serves is answered. Fault events stay masked; the fault recording
//! registers are polled.

use std::sync::atomic::{Ordering, fence};
use std::time::{Duration, Instant};

use iommu_core::{Access, Backend, BackendError, Fault, RemapEntry, UnitInfo};
use iommu_vtd::queue::{self, Descriptor, QUEUE_ENTRIES};
use iommu_vtd::regs::{self, Capability};
use iommu_vtd::remap;
use iommu_vtd::tables::{
    SL_READ, SL_WRITE, SecondLevel, TableError, TableStore, context_entry, context_index,
    root_entry,
};

use iommu_store::Store;
use syscall_abi::PAGE_SIZE;

/// How long a unit may take to complete one command (a root-pointer or
/// remapping-table-pointer set, a translation, queued-invalidation, or
/// interrupt-remapping enable or disable, a write-buffer flush, or one batch
/// of queued invalidations) before the driver treats the unit as failed. A
/// command completes in microseconds on hardware and at once under QEMU; the
/// bound is a hang guard, not a tuning value. `docs/limits.md` classifies
/// it.
pub const INVALIDATION_TIMEOUT: Duration = Duration::from_secs(1);

/// One remapping unit: its mapped registers, decoded capabilities,
/// invalidation queue, root table, and the context table of each bus that
/// has an attached function.
pub struct Unit
{
    /// Virtual address of the unit's register set.
    regs: u64,
    /// Bytes of the register set mapped from `regs`.
    regs_len: u64,
    cap: Capability,
    /// The extended capability register's value.
    ecap: u64,
    /// Physical address of the invalidation queue's page.
    queue: u64,
    /// The queue slot the next descriptor goes to.
    tail: usize,
    /// Physical address of the page whose first word each batch's wait
    /// descriptor writes.
    status: u64,
    /// The status data the last batch's wait descriptor wrote.
    token: u32,
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
            ecap: 0,
            queue: 0,
            tail: 0,
            status: 0,
            token: 0,
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

    /// Clear every fault recording register, the overflow flag, and an
    /// invalidation queue error.
    fn clear_faults(&self)
    {
        for i in 0..self.cap.fault_count
        {
            self.write64(self.cap.fault_offset + i * 16 + 8, regs::FAULT_CLEAR);
        }
        self.write32(regs::FSTS, regs::FSTS_PFO | regs::FSTS_IQE);
    }

    /// Turn off every persistent state a previous owner (firmware, or an
    /// earlier run of the driver) may have left on: translation, interrupt
    /// remapping, then queued invalidation, which turning the first two off
    /// does not need.
    fn reset_states(&self) -> Result<(), BackendError>
    {
        for bit in [regs::G_TE, regs::G_IRE, regs::G_QIE]
        {
            if self.read32(regs::GSTS) & bit != 0
            {
                self.disable(bit)?;
            }
        }
        Ok(())
    }
}

/// The interrupt remapping table every unit points at.
#[derive(Clone, Copy)]
struct RemapTable
{
    /// Physical address of its first page.
    base: u64,
    /// 32-bit destinations (extended interrupt mode).
    extended: bool,
}

impl RemapTable
{
    /// The table page holding entry `handle`, and the word index of the
    /// entry's low word in that page.
    // cast_possible_truncation: the word index within a page is below 512.
    #[allow(clippy::cast_possible_truncation)]
    fn slot(self, handle: u16) -> (u64, usize)
    {
        let offset = u64::from(handle) * remap::ENTRY_BYTES;
        let page = offset - offset % PAGE_SIZE;
        (self.base + page, ((offset - page) / 8) as usize)
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

/// Every unit the driver serves, the store of their table pages, and the
/// interrupt remapping table while remapping is on.
pub struct Vtd
{
    units: Vec<Unit>,
    store: Store,
    remap: Option<RemapTable>,
}

impl Vtd
{
    /// A backend over `units`, building its tables in `store`.
    pub fn new(units: Vec<Unit>, store: Store) -> Self
    {
        Self {
            units,
            store,
            remap: None,
        }
    }

    /// Place `descriptors` in unit `unit`'s invalidation queue, followed by
    /// a wait descriptor, and poll the wait's status write. A queue error (a
    /// descriptor the unit refused) is cleared and reported as the unit
    /// failing, as a wait that never completes is.
    fn submit(&mut self, unit: usize, descriptors: &[Descriptor]) -> Result<(), BackendError>
    {
        let u = &self.units[unit];
        let (queue, status) = (u.queue, u.status);
        let token = match u.token.wrapping_add(1)
        {
            0 => 1,
            t => t,
        };
        let mut tail = u.tail;
        for &d in descriptors.iter().chain(&[queue::wait(status, token)])
        {
            self.write_entry(queue, tail * 2, d);
            tail = (tail + 1) % QUEUE_ENTRIES;
        }
        let status_word = self
            .store
            .page_ptr(status)
            .ok_or(BackendError::Invalid)?
            .cast::<u32>();
        let u = &mut self.units[unit];
        u.tail = tail;
        u.token = token;
        u.write64(regs::IQT, queue::tail(tail));
        // SAFETY: `status_word` is the first word of a page of the store,
        // mapped for the driver's life and reached only through raw volatile
        // accesses, since the unit writes it.
        let written = || unsafe { core::ptr::read_volatile(status_word) } == token;
        u.wait(|u| written() || u.read32(regs::FSTS) & regs::FSTS_IQE != 0)?;
        if written()
        {
            return Ok(());
        }
        u.write32(regs::FSTS, regs::FSTS_IQE);
        Err(BackendError::Timeout)
    }

    /// Clear a two-word entry of the table page `table` at word `index`, the
    /// low word (which holds the present bit) first, and flush it. The
    /// stores are volatile, so they reach memory in that order.
    fn clear_entry(&mut self, table: u64, index: usize)
    {
        let t = self.store.table(table);
        // SAFETY: both words lie in the table page `t` borrows exclusively.
        unsafe {
            core::ptr::write_volatile(&raw mut t[index], 0);
            core::ptr::write_volatile(&raw mut t[index + 1], 0);
        }
        self.store.flush(table, (index * 8) as u64, 16);
    }

    /// Invalidate every unit's cached copy of remapping entry `handle`.
    fn invalidate_remap_entry(&mut self, handle: u16) -> Result<(), BackendError>
    {
        for unit in 0..self.units.len()
        {
            self.submit(unit, &[queue::iec_index(handle)])?;
        }
        Ok(())
    }

    /// Point unit `unit` at the remapping table `table` of `entries`
    /// entries, invalidate its interrupt entry cache, and turn remapping on
    /// with compatibility-format interrupts blocked.
    fn remap_unit(
        &mut self,
        unit: usize,
        table: RemapTable,
        entries: u32,
    ) -> Result<(), BackendError>
    {
        let u = &self.units[unit];
        u.write64(regs::IRTA, remap::irta(table.base, entries, table.extended));
        let gsts = u.read32(regs::GSTS);
        u.write32(regs::GCMD, regs::gcmd_set(gsts, regs::G_SIRTP));
        u.wait(|u| u.read32(regs::GSTS) & regs::G_SIRTP != 0)?;
        self.submit(unit, &[queue::iec_global()])?;
        let u = &self.units[unit];
        let gsts = u.read32(regs::GSTS);
        u.write32(regs::GCMD, regs::gcmd_remap_on(gsts));
        u.wait(|u| u.read32(regs::GSTS) & (regs::G_IRE | regs::G_CFI) == regs::G_IRE)
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
    fn context_changed(&mut self, unit: usize, did: u16) -> Result<(), BackendError>
    {
        self.units[unit].flush_write_buffer()?;
        self.submit(unit, &[queue::context_global(), queue::iotlb_domain(did)])
    }

    /// Set unit `unit` up empty, with queued invalidation on, then turn
    /// translation on. A unit without queued invalidation is refused: the
    /// driver invalidates no other way.
    fn setup(&mut self, unit: usize) -> Result<(), BackendError>
    {
        let u = &mut self.units[unit];
        u.cap = Capability::decode(u.read64(regs::CAP));
        u.ecap = u.read64(regs::ECAP);
        let (levels, bits) = u.cap.table_depth().ok_or(BackendError::Invalid)?;
        u.levels = levels;
        u.width_bits = bits.min(u.cap.mgaw);
        let last_fault = u.cap.fault_offset + u.cap.fault_count * 16;
        if u.ecap & regs::ECAP_QI == 0
            || u.checked(regs::IRTA, 8).is_none()
            || u.checked(last_fault - 8, 8).is_none()
        {
            return Err(BackendError::Invalid);
        }
        u.reset_states()?;
        u.write32(regs::FECTL, regs::FECTL_IM);
        u.clear_faults();
        let queue = self.store.alloc().ok_or(BackendError::OutOfMemory)?;
        let status = self.store.alloc().ok_or(BackendError::OutOfMemory)?;
        let root = self.store.alloc().ok_or(BackendError::OutOfMemory)?;
        let u = &mut self.units[unit];
        (u.queue, u.status, u.tail, u.token, u.root) = (queue, status, 0, 0, root);
        u.write64(regs::IQT, queue::tail(0));
        u.write64(regs::IQA, queue::iqa(queue));
        u.enable(regs::G_QIE)?;
        u.write64(regs::RTADDR, root);
        u.set_root()?;
        u.flush_write_buffer()?;
        self.submit(unit, &[queue::context_global(), queue::iotlb_global()])?;
        let u = &mut self.units[unit];
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
        self.remap_disable();
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
        access: Access,
    ) -> Result<(), BackendError>
    {
        let rights = match access
        {
            Access::Read => SL_READ,
            Access::ReadWrite => SL_READ | SL_WRITE,
        };
        let mapped = domain.tables.map(&mut self.store, iova, phys, len, rights);
        let u = &self.units[domain.unit];
        u.flush_write_buffer()?;
        // A map that failed part-way undid the entries it wrote, which the
        // unit may have cached meanwhile; a unit in caching mode may cache
        // the not-present entries a range replaced. Either needs the
        // domain's IOTLB invalidated.
        if mapped.is_err() || u.cap.caching_mode
        {
            self.submit(domain.unit, &[queue::iotlb_domain(domain.did)])?;
        }
        mapped.map_err(table_error)
    }

    /// Refused: a write to the interrupt address range (`0xFEEx_xxxx`) is
    /// an interrupt request, which VT-d does not translate through a
    /// domain's second-level tables (interrupt remapping governs it,
    /// [`Self::remap_set`]).
    fn map_msi(&mut self, _domain: &mut VtdDomain, _file: u64) -> Result<(), BackendError>
    {
        Err(BackendError::Invalid)
    }

    fn unmap(&mut self, domain: &mut VtdDomain, iova: u64, len: u64) -> Result<(), BackendError>
    {
        domain
            .tables
            .unmap(&mut self.store, iova, len)
            .map_err(table_error)?;
        self.units[domain.unit].flush_write_buffer()?;
        self.submit(domain.unit, &[queue::iotlb_domain(domain.did)])
    }

    fn block(&mut self, domain: &mut VtdDomain) -> Result<(), BackendError>
    {
        let context = self.units[domain.unit].context[domain.bus];
        self.clear_entry(context, domain.entry);
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
                        reason: u16::from(f.reason),
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

    fn remap_enable(&mut self, entries: u32, extended: bool) -> Result<bool, BackendError>
    {
        if self.remap.is_some() || self.units.iter().any(|u| u.ecap & regs::ECAP_IR == 0)
        {
            return Err(BackendError::Invalid);
        }
        let table = RemapTable {
            base: self
                .store
                .alloc_contiguous(remap::table_pages(entries))
                .ok_or(BackendError::OutOfMemory)?,
            extended: extended && self.units.iter().all(|u| u.ecap & regs::ECAP_EIM != 0),
        };
        for unit in 0..self.units.len()
        {
            if let Err(e) = self.remap_unit(unit, table, entries)
            {
                self.remap_disable();
                return Err(e);
            }
        }
        self.remap = Some(table);
        Ok(table.extended)
    }

    fn remap_disable(&mut self)
    {
        for u in &self.units
        {
            if u.read32(regs::GSTS) & regs::G_IRE != 0
            {
                let _ = u.disable(regs::G_IRE);
            }
        }
        self.remap = None;
    }

    /// An entry that already holds `entry` is left as it is, so a repeated
    /// set opens no gap in a source's delivery. A present entry holding
    /// anything else is made not present, and every unit's cached copy
    /// invalidated, before its new contents are written, so no unit reads
    /// an entry whose two words disagree ([`remap::update`]).
    fn remap_set(&mut self, handle: u16, entry: RemapEntry) -> Result<(), BackendError>
    {
        let table = self.remap.ok_or(BackendError::Invalid)?;
        let (page, index) = table.slot(handle);
        let words = remap::entry(entry, table.extended);
        let held = {
            let t = self.store.table(page);
            [t[index], t[index + 1]]
        };
        match remap::update(held, words)
        {
            remap::Update::Unchanged => return Ok(()),
            remap::Update::Replace =>
            {
                self.clear_entry(page, index);
                self.invalidate_remap_entry(handle)?;
            }
            remap::Update::Write => (),
        }
        self.write_entry(page, index, words);
        self.invalidate_remap_entry(handle)
    }

    fn remap_clear(&mut self, handle: u16) -> Result<(), BackendError>
    {
        let table = self.remap.ok_or(BackendError::Invalid)?;
        let (page, index) = table.slot(handle);
        self.clear_entry(page, index);
        self.invalidate_remap_entry(handle)
    }
}
