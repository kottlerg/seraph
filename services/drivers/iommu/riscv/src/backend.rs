// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/drivers/iommu/riscv/src/backend.rs

//! The RISC-V IOMMU [`Backend`]: each IOMMU's registers, command and fault
//! queues, and device directory, and each attached device's first-stage
//! page tables.
//!
//! Every command batch ends in an `IOFENCE.C` and is polled to completion,
//! `cqh` reaching the tail, within [`COMMAND_TIMEOUT`] before the request it
//! serves is answered. The queues' interrupts stay disabled; the fault queue
//! is polled.
//!
//! The IOMMU reads the device directory, the page tables, and the queues
//! from memory coherently with the processor caches, as the platform's PCI
//! host declares (`dma-coherent`) and QEMU's `riscv-iommu-pci` does; the
//! specification states no coherence rule, and a platform whose IOMMU reads
//! past the caches would need its table writes cleaned from them, which the
//! store does not do on riscv64.

use std::sync::atomic::{Ordering, fence};
use std::time::{Duration, Instant};

use iommu_core::table::TableStore;
use iommu_core::{Backend, BackendError, Fault, UnitInfo};
use iommu_riscv::regs::{
    self, COMMAND_WORDS, CQ_ENTRIES, Capability, Command, DdtMode, Directory, FAULT_RECORD_WORDS,
    FQ_ENTRIES, Fence, FirstStageMode, Translations,
};
use iommu_riscv::tables::{Access, DeviceDirectory, FirstStage, PAGE, TableError, device_context};
use iommu_store::Store;

/// How long an IOMMU may take to complete one command batch, a mode change
/// of `ddtp`, or a queue's enable or disable before the driver treats it as
/// failed. A command completes in microseconds on hardware and at once under
/// QEMU; the bound is a hang guard, not a tuning value. `docs/limits.md`
/// classifies it.
pub const COMMAND_TIMEOUT: Duration = Duration::from_secs(1);

/// Domain IDs an IOMMU supports: the 20-bit `PSCID` space.
const PSCIDS: u32 = 1 << 20;

/// One IOMMU: its mapped registers, capabilities, queues, and device
/// directory.
pub struct Unit
{
    /// Virtual address of the IOMMU's register page.
    regs: u64,
    cap: Capability,
    /// The first-stage format the IOMMU's domains get.
    mode: FirstStageMode,
    /// Physical address of the command queue's page; 0 before setup.
    cq: u64,
    /// The command-queue index the driver writes next.
    cq_tail: u32,
    /// Physical address of the fault queue's page; 0 before setup.
    fq: u64,
    /// The device directory, once the IOMMU translates through it.
    ddt: Option<DeviceDirectory>,
}

impl Unit
{
    /// An IOMMU whose register page is mapped at `regs`.
    pub fn new(regs: u64) -> Self
    {
        Self {
            regs,
            cap: Capability::decode(0),
            mode: FirstStageMode::Sv39,
            cq: 0,
            cq_tail: 0,
            fq: 0,
            ddt: None,
        }
    }

    fn read32(&self, off: usize) -> u32
    {
        // SAFETY: `off` is one of the `regs` offsets, every one inside the
        // register page mapped from `regs` for the driver's life and reached
        // only through raw volatile accesses; every register is naturally
        // aligned.
        unsafe { core::ptr::read_volatile((self.regs + off as u64) as *const u32) }
    }

    /// Write a 32-bit register. A write starts or configures an IOMMU
    /// operation that may read the in-memory structures, so it is fenced
    /// after every store the driver made to them before it.
    fn write32(&self, off: usize, value: u32)
    {
        fence(Ordering::SeqCst);
        // SAFETY: as in `read32`.
        unsafe { core::ptr::write_volatile((self.regs + off as u64) as *mut u32, value) };
    }

    fn read64(&self, off: usize) -> u64
    {
        // SAFETY: as in `read32`.
        unsafe { core::ptr::read_volatile((self.regs + off as u64) as *const u64) }
    }

    /// Write a 64-bit register, fenced as [`Self::write32`] is.
    fn write64(&self, off: usize, value: u64)
    {
        fence(Ordering::SeqCst);
        // SAFETY: as in `read32`.
        unsafe { core::ptr::write_volatile((self.regs + off as u64) as *mut u64, value) };
    }

    /// Poll until `done` holds, at most [`COMMAND_TIMEOUT`].
    fn wait(&self, mut done: impl FnMut(&Self) -> bool) -> Result<(), BackendError>
    {
        let start = Instant::now();
        loop
        {
            if done(self)
            {
                return Ok(());
            }
            if start.elapsed() > COMMAND_TIMEOUT
            {
                return Err(BackendError::Timeout);
            }
            core::hint::spin_loop();
        }
    }

    /// Write `ddtp` once the IOMMU is done with the last write, and wait for
    /// it to be done with this one.
    fn set_ddtp(&self, value: u64) -> Result<(), BackendError>
    {
        self.wait(|u| u.read64(regs::DDTP) & regs::DDTP_BUSY == 0)?;
        self.write64(regs::DDTP, value);
        self.wait(|u| u.read64(regs::DDTP) & regs::DDTP_BUSY == 0)
    }

    /// Disable the queue whose control register is at `csr` and whose
    /// active bit is `on`, and wait for it to go inactive.
    fn stop_queue(&self, csr: usize, on: u32) -> Result<(), BackendError>
    {
        self.wait(|u| u.read32(csr) & regs::CSR_BUSY == 0)?;
        self.write32(csr, 0);
        self.wait(|u| u.read32(csr) & (on | regs::CSR_BUSY) == 0)
    }

    /// Enable the queue whose control register is at `csr`, with `enable`
    /// as its enable bit and `on` its active bit, and wait for it to go
    /// active.
    fn start_queue(&self, csr: usize, enable: u32, on: u32) -> Result<(), BackendError>
    {
        self.write32(csr, enable);
        self.wait(|u| u.read32(csr) & (on | regs::CSR_BUSY) == on)
    }

    /// Return the IOMMU to Bare, passing every device's DMA through
    /// untranslated: through Off when it translates, since only a change
    /// from Off to Bare is defined. Best effort; a step that does not
    /// complete leaves the mode where it stands.
    fn restore_bare(&self)
    {
        let ddtp = self.read64(regs::DDTP);
        if regs::ddtp_mode(ddtp) == DdtMode::Bare as u64
        {
            return;
        }
        if regs::ddtp_mode(ddtp) != DdtMode::Off as u64
            && self.set_ddtp(regs::ddtp_off(ddtp)).is_err()
        {
            return;
        }
        let _ = self.set_ddtp(DdtMode::Bare as u64);
    }
}

/// One attached device: its IOMMU, device ID, context, domain ID, and
/// first-stage tables.
pub struct RiscvDomain
{
    unit: usize,
    device_id: u32,
    /// The device context's leaf page and the index of its first word.
    context: (u64, usize),
    pscid: u32,
    tables: FirstStage,
}

/// Every IOMMU the driver serves and the store of their table pages.
pub struct Riscv
{
    units: Vec<Unit>,
    store: Store,
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

impl Riscv
{
    /// A backend over `units`, building their structures in `store`.
    pub fn new(units: Vec<Unit>, store: Store) -> Self
    {
        Self { units, store }
    }

    /// Store `value` volatile at word `index` of the table page `page`, then
    /// order it before every later store and register write
    /// ([`TableStore::written`]).
    fn write_word(&mut self, page: u64, index: usize, value: u64)
    {
        let t = self.store.table(page);
        // SAFETY: the word lies in the table page `t` borrows exclusively.
        unsafe { core::ptr::write_volatile(&raw mut t[index], value) };
        self.store.written(page, index);
    }

    /// Queue `commands` on unit `unit`'s command queue, the last of them an
    /// `IOFENCE.C`, and wait for the IOMMU to complete them all. A command
    /// error (an illegal command or a memory fault) stops the queue, so it
    /// fails the unit as a timeout does.
    fn submit(&mut self, unit: usize, commands: &[Command]) -> Result<(), BackendError>
    {
        let cq = self.units[unit].cq;
        let mut tail = self.units[unit].cq_tail;
        for command in commands
        {
            // The IOMMU reads no command past the tail, which is written
            // after them.
            let at = tail as usize * COMMAND_WORDS;
            for (i, &word) in command.iter().enumerate()
            {
                self.write_word(cq, at + i, word);
            }
            tail = (tail + 1) % CQ_ENTRIES;
        }
        let u = &mut self.units[unit];
        u.cq_tail = tail;
        u.write32(regs::CQT, tail);
        u.wait(|u| u.read32(regs::CQCSR) & regs::CQCSR_ERRORS != 0 || u.read32(regs::CQH) == tail)?;
        if u.read32(regs::CQCSR) & regs::CQCSR_ERRORS != 0
        {
            return Err(BackendError::Timeout);
        }
        Ok(())
    }

    /// Set unit `unit` up with empty queues and an empty device directory,
    /// then turn translation on.
    fn setup(&mut self, unit: usize) -> Result<(), BackendError>
    {
        let u = &mut self.units[unit];
        u.cap = Capability::decode(u.read64(regs::CAPABILITIES));
        if !u.cap.version_supported()
        {
            return Err(BackendError::Invalid);
        }
        u.mode = u.cap.first_stage().ok_or(BackendError::Invalid)?;
        // The features and the queues change only with the IOMMU Off or
        // Bare and the queues stopped; a mode left translating goes Off
        // first, and a feature to clear needs it Off.
        let ddtp = u.read64(regs::DDTP);
        let fctl = u.read32(regs::FCTL);
        let features = fctl & (regs::FCTL_BE | regs::FCTL_GXL);
        if regs::translating(ddtp) || features != 0
        {
            u.set_ddtp(regs::ddtp_off(ddtp))?;
        }
        u.stop_queue(regs::CQCSR, regs::CQCSR_CQON)?;
        u.stop_queue(regs::FQCSR, regs::FQCSR_FQON)?;
        if features != 0
        {
            u.write32(regs::FCTL, fctl & !features);
            if u.read32(regs::FCTL) & features != 0
            {
                return Err(BackendError::Invalid);
            }
        }
        let cq = self.store.alloc().ok_or(BackendError::OutOfMemory)?;
        let fq = self.store.alloc().ok_or(BackendError::OutOfMemory)?;
        let root = self.store.alloc().ok_or(BackendError::OutOfMemory)?;
        let u = &mut self.units[unit];
        (u.cq, u.fq, u.cq_tail) = (cq, fq, 0);
        u.write64(regs::CQB, regs::queue_base(cq, CQ_ENTRIES));
        u.write32(regs::CQT, 0);
        u.start_queue(regs::CQCSR, regs::CQCSR_CQEN, regs::CQCSR_CQON)?;
        u.write64(regs::FQB, regs::queue_base(fq, FQ_ENTRIES));
        u.write32(regs::FQH, 0);
        u.start_queue(regs::FQCSR, regs::FQCSR_FQEN, regs::FQCSR_FQON)?;
        // Whatever the IOMMU cached under an earlier mode is dropped before
        // the new directory is used.
        self.submit(
            unit,
            &[
                regs::iodir_inval_ddt(Directory::All),
                regs::iotinval_vma(Translations::All),
                regs::iofence_c(Fence::Commands),
            ],
        )?;
        let u = &mut self.units[unit];
        let extended = u.cap.extended_context;
        for mode in regs::directory_modes(extended)
        {
            u.set_ddtp(regs::ddtp(mode, root))?;
            if regs::ddtp_mode(u.read64(regs::DDTP)) == mode as u64
            {
                u.ddt = DeviceDirectory::new(root, mode.levels(), extended);
                return Ok(());
            }
        }
        Err(BackendError::Invalid)
    }
}

impl Backend for Riscv
{
    type Domain = RiscvDomain;

    fn init_unit(&mut self, unit: usize) -> Result<(), BackendError>
    {
        let set_up = self.setup(unit);
        if set_up.is_err()
        {
            self.units[unit].ddt = None;
            self.units[unit].restore_bare();
        }
        set_up
    }

    fn disable_all(&mut self)
    {
        for u in &mut self.units
        {
            if u.ddt.take().is_some()
            {
                u.restore_bare();
            }
        }
    }

    fn attach(&mut self, unit: usize, bdf: u16, did: u32) -> Result<RiscvDomain, BackendError>
    {
        if did >= PSCIDS
        {
            return Err(BackendError::Invalid);
        }
        let device_id = u32::from(bdf);
        let u = &self.units[unit];
        let (ddt, mode) = (u.ddt.ok_or(BackendError::Invalid)?, u.mode);
        let (page, first) = ddt
            .context(&mut self.store, device_id)
            .map_err(table_error)?;
        let tables = FirstStage::new(&mut self.store, mode).ok_or(BackendError::OutOfMemory)?;
        let words = device_context(tables.root(), mode, did);
        // The context's other words are written first, highest first, and
        // `tc`, which holds the valid bit, last, so the IOMMU never reads a
        // valid context beside stale words; each store is volatile and
        // fenced before the next ([`Self::write_word`]).
        for i in (1..ddt.context_words()).rev()
        {
            self.write_word(page, first + i, words.get(i).copied().unwrap_or(0));
        }
        self.write_word(page, first, words[0]);
        self.submit(
            unit,
            &[
                regs::iodir_inval_ddt(Directory::Device(device_id)),
                regs::iofence_c(Fence::Commands),
            ],
        )?;
        Ok(RiscvDomain {
            unit,
            device_id,
            context: (page, first),
            pscid: did,
            tables,
        })
    }

    fn map(
        &mut self,
        domain: &mut RiscvDomain,
        iova: u64,
        phys: u64,
        len: u64,
        write: bool,
    ) -> Result<(), BackendError>
    {
        let access = if write
        {
            Access::ReadWrite
        }
        else
        {
            Access::Read
        };
        let mapped = domain.tables.map(&mut self.store, iova, phys, len, access);
        // A new valid entry needs no invalidation, since the IOMMU caches no
        // invalid one; a map that failed part-way undid the entries it wrote,
        // which the IOMMU may have cached meanwhile.
        if mapped.is_err()
        {
            self.submit(
                domain.unit,
                &[
                    regs::iotinval_vma(Translations::Domain(domain.pscid)),
                    regs::iofence_c(Fence::DeviceAccesses),
                ],
            )?;
        }
        mapped.map_err(table_error)
    }

    fn unmap(&mut self, domain: &mut RiscvDomain, iova: u64, len: u64) -> Result<(), BackendError>
    {
        // A failed unmap cleared the pages before the one it failed on, so
        // the invalidation runs either way.
        let unmapped = domain.tables.unmap(&mut self.store, iova, len);
        let which = if len == PAGE
        {
            Translations::Page {
                pscid: domain.pscid,
                iova,
            }
        }
        else
        {
            Translations::Domain(domain.pscid)
        };
        self.submit(
            domain.unit,
            &[
                regs::iotinval_vma(which),
                regs::iofence_c(Fence::DeviceAccesses),
            ],
        )?;
        unmapped.map_err(table_error)
    }

    fn block(&mut self, domain: &mut RiscvDomain) -> Result<(), BackendError>
    {
        let (page, first) = domain.context;
        // Clearing `tc` clears the valid bit; the other words are then
        // don't-care.
        self.write_word(page, first, 0);
        self.submit(
            domain.unit,
            &[
                regs::iodir_inval_ddt(Directory::Device(domain.device_id)),
                regs::iotinval_vma(Translations::Domain(domain.pscid)),
                regs::iofence_c(Fence::DeviceAccesses),
            ],
        )
    }

    fn query(&self, unit: usize) -> UnitInfo
    {
        UnitInfo {
            width_bits: self.units[unit].mode.width_bits(),
            domain_ids: PSCIDS,
        }
    }

    fn poll_faults(&mut self, record: &mut dyn FnMut(Fault))
    {
        let Self { units, store } = self;
        for (index, u) in units.iter().enumerate()
        {
            if u.ddt.is_none()
            {
                continue;
            }
            let csr = u.read32(regs::FQCSR);
            let tail = u.read32(regs::FQT) % FQ_ENTRIES;
            let mut head = u.read32(regs::FQH) % FQ_ENTRIES;
            // The records are read after the tail that publishes them.
            fence(Ordering::SeqCst);
            while head != tail
            {
                let at = head as usize * FAULT_RECORD_WORDS;
                let page = store.table(u.fq);
                let mut words = [0u64; FAULT_RECORD_WORDS];
                for (i, w) in words.iter_mut().enumerate()
                {
                    // SAFETY: the record lies in the fault-queue page `page`
                    // borrows; the IOMMU wrote it before advancing the tail.
                    *w = unsafe { core::ptr::read_volatile(&raw const page[at + i]) };
                }
                if let Some(f) = regs::decode_fault(words)
                    && let Ok(bdf) = u16::try_from(f.device_id)
                {
                    record(Fault {
                        unit: index,
                        bdf,
                        reason: f.cause,
                        iova: f.iova & !(PAGE - 1),
                    });
                }
                head = (head + 1) % FQ_ENTRIES;
            }
            u.write32(regs::FQH, head);
            // An overflow or a record-store fault stops the queue's
            // recording until it is cleared (write 1), the queue kept on.
            let stopped = csr & (regs::FQCSR_FQOF | regs::FQCSR_FQMF);
            if stopped != 0 && csr & regs::CSR_BUSY == 0
            {
                u.write32(regs::FQCSR, regs::FQCSR_FQEN | stopped);
            }
        }
    }
}
