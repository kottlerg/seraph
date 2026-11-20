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
//! On RISC-V a memory fence orders no device access, so the `mmio` barriers
//! order the two: each register write after every structure store before it
//! (`fence w,o`) and before the next register write (`fence o,o`), the fault
//! records after the tail register that publishes them (`fence i,r`), and
//! the head register write that frees their slots after the record reads
//! (`fence r,o`).
//!
//! Each IOMMU's device directory is rooted at its anchor, the page devmgr
//! keeps for the boot. A driver devmgr restarts adopts the IOMMUs: it
//! requires each translating through a directory rooted at its anchor, in
//! the mode the dead instance chose, waits for the dead instance's commands
//! to complete, replaces both queues with its own, the mode left as it
//! stands, and builds devmgr's replayed devices under a staging root page of
//! the same depth. [`Backend::commit`] copies each staged root entry into
//! the anchor by the [`anchor`] write rule (a non-leaf entry is one word; a
//! one-level directory's entry is a whole device context, rewritten as the
//! rule's fifth case says when more than one of its words changed), then
//! invalidates every cached directory entry and translation, ordering the
//! device accesses before it. Faults the dead instance had not read are
//! dropped with its fault queue.
//!
//! The IOMMU reads the device directory, the page tables, and the queues
//! from memory coherently with the processor caches, as the platform's PCI
//! host declares (`dma-coherent`) and QEMU's `riscv-iommu-pci` does; the
//! specification states no coherence rule, and a platform whose IOMMU reads
//! past the caches would need its table writes cleaned from them, which the
//! store does not do on riscv64.

use std::sync::atomic::{Ordering, fence};
use std::time::{Duration, Instant};

use iommu_core::anchor::{self, Step};
use iommu_core::table::TableStore;
use iommu_core::{Access, Backend, BackendError, Fault, RemapEntry, Start, UnitInfo};
use iommu_riscv::regs::{
    self, COMMAND_WORDS, CQ_ENTRIES, Capability, Command, DdtMode, Directory, FAULT_RECORD_WORDS,
    FQ_ENTRIES, Fence, FirstStageMode, Translations,
};
use iommu_riscv::tables::{DeviceDirectory, FirstStage, PAGE, TableError, device_context};
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
    /// Physical address of the IOMMU's anchor, the device directory's root
    /// page it translates through.
    anchor: u64,
    /// The device directory attaches write, once the IOMMU translates: the
    /// anchor's, or an adopting driver's staging directory until its
    /// commit.
    ddt: Option<DeviceDirectory>,
}

impl Unit
{
    /// An IOMMU whose register page is mapped at `regs`, with its anchor at
    /// the physical address `anchor`, a page of the backend's store.
    pub fn new(regs: u64, anchor: u64) -> Self
    {
        Self {
            regs,
            anchor,
            cap: Capability::decode(0),
            mode: FirstStageMode::Sv39,
            cq: 0,
            cq_tail: 0,
            fq: 0,
            ddt: None,
        }
    }

    /// The address of the register at `off`, one of the `regs` offsets.
    /// Every one lies inside the register page mapped from `regs`, which
    /// ends below `u64::MAX`, so the sum does not saturate.
    fn register(&self, off: usize) -> u64
    {
        self.regs.saturating_add(off as u64)
    }

    fn read32(&self, off: usize) -> u32
    {
        // SAFETY: `off` is one of the `regs` offsets, every one inside the
        // register page mapped from `regs` for the driver's life and reached
        // only through raw volatile accesses; every register is naturally
        // aligned.
        unsafe { core::ptr::read_volatile(self.register(off) as *const u32) }
    }

    /// Write a 32-bit register. A write starts or configures an IOMMU
    /// operation that may read the in-memory structures, so every store the
    /// driver made to them before it is ordered before it, and the register
    /// writes of a sequence (a queue's base, then its index, then its enable)
    /// reach the IOMMU in program order: on RISC-V a memory fence orders no
    /// device access, so the memory-to-device barrier (`fence w,o`) precedes
    /// the write and the device-to-device one (`fence o,o`) follows it.
    fn write32(&self, off: usize, value: u32)
    {
        mmio::dma_to_mmio_barrier();
        // SAFETY: as in `read32`.
        unsafe { core::ptr::write_volatile(self.register(off) as *mut u32, value) };
        mmio::mmio_to_mmio_barrier();
    }

    fn read64(&self, off: usize) -> u64
    {
        // SAFETY: as in `read32`.
        unsafe { core::ptr::read_volatile(self.register(off) as *const u64) }
    }

    /// Write a 64-bit register, ordered as [`Self::write32`] is.
    fn write64(&self, off: usize, value: u64)
    {
        mmio::dma_to_mmio_barrier();
        // SAFETY: as in `read32`.
        unsafe { core::ptr::write_volatile(self.register(off) as *mut u64, value) };
        mmio::mmio_to_mmio_barrier();
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

/// One attached device: its IOMMU, device ID, domain ID, and first-stage
/// tables. Its context is looked up in the directory when it is blocked,
/// since a commit moves a one-level directory's contexts into the anchor.
pub struct RiscvDomain
{
    unit: usize,
    device_id: u32,
    pscid: u32,
    tables: FirstStage,
}

/// Every IOMMU the driver serves and the store of their table pages.
pub struct Riscv
{
    units: Vec<Unit>,
    store: Store,
    /// How the units are set up: a restarted instance adopts them.
    start: Start,
    /// The adopted units translate through this instance's tables alone.
    committed: bool,
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
    /// A backend over `units`, building their structures in `store`,
    /// setting the units up as `start` says.
    pub fn new(units: Vec<Unit>, store: Store, start: Start) -> Self
    {
        Self {
            units,
            store,
            start,
            committed: false,
        }
    }

    /// Store `value` volatile at word `index` of the table page `page`, then
    /// order it before every later store ([`TableStore::written`]); the
    /// register write that follows orders it before itself ([`Unit::write32`]).
    /// Every `index` passed lies in the page (a command-queue slot, or a
    /// device context's word from [`DeviceDirectory::context`]), so the
    /// [`BackendError::Invalid`] is never returned.
    fn write_word(&mut self, page: u64, index: usize, value: u64) -> Result<(), BackendError>
    {
        let word = self
            .store
            .table(page)
            .get_mut(index)
            .ok_or(BackendError::Invalid)?;
        // SAFETY: `word` lies in the table page the store lends exclusively.
        unsafe { core::ptr::write_volatile(&raw mut *word, value) };
        self.store.written(page, index);
        Ok(())
    }

    /// Unit `unit`. [`Service`](iommu_core::Service) passes only a unit the
    /// resource list delivered, so the [`BackendError::Invalid`] is never
    /// returned.
    fn unit(&self, unit: usize) -> Result<&Unit, BackendError>
    {
        self.units.get(unit).ok_or(BackendError::Invalid)
    }

    /// Unit `unit`, as [`Self::unit`].
    fn unit_mut(&mut self, unit: usize) -> Result<&mut Unit, BackendError>
    {
        self.units.get_mut(unit).ok_or(BackendError::Invalid)
    }

    /// Queue `commands` on unit `unit`'s command queue, the last of them an
    /// `IOFENCE.C`, and wait for the IOMMU to complete them all. A command
    /// error (an illegal command or a memory fault) stops the queue, so it
    /// fails the unit as a timeout does.
    fn submit(&mut self, unit: usize, commands: &[Command]) -> Result<(), BackendError>
    {
        let u = self.unit(unit)?;
        let (cq, mut tail) = (u.cq, u.cq_tail);
        for command in commands
        {
            // The IOMMU reads no command past the tail, which is written
            // after them. `tail` stays below `CQ_ENTRIES`, whose slots fill
            // the page, so no step saturates.
            let at = (tail as usize).saturating_mul(COMMAND_WORDS);
            for (i, &word) in command.iter().enumerate()
            {
                self.write_word(cq, at.saturating_add(i), word)?;
            }
            tail = tail.saturating_add(1) % CQ_ENTRIES;
        }
        let u = self.unit_mut(unit)?;
        u.cq_tail = tail;
        u.write32(regs::CQT, tail);
        u.wait(|u| u.read32(regs::CQCSR) & regs::CQCSR_ERRORS != 0 || u.read32(regs::CQH) == tail)?;
        if u.read32(regs::CQCSR) & regs::CQCSR_ERRORS != 0
        {
            return Err(BackendError::Timeout);
        }
        Ok(())
    }

    /// Set unit `unit` up as the backend's `start` says.
    fn setup(&mut self, unit: usize) -> Result<(), BackendError>
    {
        let u = self.unit_mut(unit)?;
        u.cap = Capability::decode(u.read64(regs::CAPABILITIES));
        if !u.cap.version_supported()
        {
            return Err(BackendError::Invalid);
        }
        u.mode = u.cap.first_stage().ok_or(BackendError::Invalid)?;
        let cq = self.store.alloc().ok_or(BackendError::OutOfMemory)?;
        let fq = self.store.alloc().ok_or(BackendError::OutOfMemory)?;
        match self.start
        {
            Start::Reset => self.reset_unit(unit, cq, fq),
            Start::Adopt => self.adopt_unit(unit, cq, fq),
        }
    }

    /// Adopt unit `unit` from a dead instance: require it translating
    /// through a directory rooted at its anchor with the features the
    /// driver needs clear and no command error recorded, wait for the dead
    /// instance's commands to complete, and replace both queues with ones
    /// in the pages `cq` and `fq`, the mode left as it stands. Later
    /// attaches build under a staging root of the same depth until
    /// [`Backend::commit`].
    fn adopt_unit(&mut self, unit: usize, cq: u64, fq: u64) -> Result<(), BackendError>
    {
        let staging = self.store.alloc().ok_or(BackendError::OutOfMemory)?;
        let u = self.unit(unit)?;
        let levels = regs::directory_at(u.read64(regs::DDTP), u.anchor);
        if levels.is_none()
            || u.read32(regs::FCTL) & (regs::FCTL_BE | regs::FCTL_GXL) != 0
            || u.read32(regs::CQCSR) & regs::CQCSR_ERRORS != 0
        {
            return Err(BackendError::Invalid);
        }
        let ddt = levels
            .and_then(|levels| DeviceDirectory::new(staging, levels, u.cap.context_format))
            .ok_or(BackendError::Invalid)?;
        u.wait(|u| {
            u.read32(regs::CQH) == u.read32(regs::CQT)
                || u.read32(regs::CQCSR) & regs::CQCSR_ERRORS != 0
        })?;
        if u.read32(regs::CQCSR) & regs::CQCSR_ERRORS != 0
        {
            return Err(BackendError::Timeout);
        }
        u.stop_queue(regs::CQCSR, regs::CQCSR_CQON)?;
        u.stop_queue(regs::FQCSR, regs::FQCSR_FQON)?;
        // No interrupt-pending bit the dead instance's queues left survives
        // into this instance's queues.
        u.write32(regs::IPSR, u.read32(regs::IPSR));
        let u = self.unit_mut(unit)?;
        u.start_queues(cq, fq)?;
        u.ddt = Some(ddt);
        Ok(())
    }

    /// Bring unit `unit` to a state it may be changed in, start empty
    /// queues in the pages `cq` and `fq`, and turn translation on through
    /// an empty directory rooted at its anchor.
    fn reset_unit(&mut self, unit: usize, cq: u64, fq: u64) -> Result<(), BackendError>
    {
        let u = self.unit_mut(unit)?;
        u.quiesce()?;
        let root = u.anchor;
        u.start_queues(cq, fq)?;
        // The IOMMU is Off or Bare, so it reads no entry of the anchor.
        *self.store.table(root) = [0; iommu_core::table::TABLE_WORDS];
        fence(Ordering::SeqCst);
        self.store.flush(root, 0, PAGE);
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
        self.unit_mut(unit)?.select_directory(root)
    }

    /// Copy unit `unit`'s staged root page into its anchor by the
    /// [`anchor`] write rule, then invalidate every cached directory entry
    /// and translation, ordering the device accesses before it, so it
    /// translates through this instance's tables alone.
    fn commit_unit(&mut self, unit: usize) -> Result<(), BackendError>
    {
        let u = self.unit(unit)?;
        let (anchor, ddt) = (u.anchor, u.ddt.ok_or(BackendError::Invalid)?);
        let staged = self.store.table(ddt.root()).to_vec();
        let width = ddt.root_entry_words();
        for (entry, step) in anchor::table_steps(self.store.table(anchor), &staged, width)
        {
            match step
            {
                Step::Store { word, value } => self.write_word(anchor, word, value)?,
                // Only a device context, a one-level directory's entry, has
                // more than one word, and its index is its device ID.
                Step::Invalidate =>
                {
                    let id = u32::try_from(entry).map_err(|_| BackendError::Invalid)?;
                    self.submit(
                        unit,
                        &[
                            regs::iodir_inval_ddt(Directory::Device(id)),
                            regs::iofence_c(Fence::Commands),
                        ],
                    )?;
                }
            }
        }
        self.submit(
            unit,
            &[
                regs::iodir_inval_ddt(Directory::All),
                regs::iotinval_vma(Translations::All),
                regs::iofence_c(Fence::DeviceAccesses),
            ],
        )?;
        self.unit_mut(unit)?.ddt = Some(ddt.rooted_at(anchor));
        Ok(())
    }
}

impl Unit
{
    /// Bring the IOMMU to a state its features and queues may be changed in:
    /// Off or Bare, with both queues stopped and the features the driver
    /// needs clear. A mode left translating goes Off first, and a feature to
    /// clear needs it Off.
    ///
    /// # Errors
    /// [`BackendError::Timeout`] when a step does not complete;
    /// [`BackendError::Invalid`] when a feature does not clear.
    fn quiesce(&self) -> Result<(), BackendError>
    {
        let ddtp = self.read64(regs::DDTP);
        let fctl = self.read32(regs::FCTL);
        let features = fctl & (regs::FCTL_BE | regs::FCTL_GXL);
        if regs::translating(ddtp) || features != 0
        {
            self.set_ddtp(regs::ddtp_off(ddtp))?;
        }
        self.stop_queue(regs::CQCSR, regs::CQCSR_CQON)?;
        self.stop_queue(regs::FQCSR, regs::FQCSR_FQON)?;
        if features != 0
        {
            self.write32(regs::FCTL, fctl & !features);
            if self.read32(regs::FCTL) & features != 0
            {
                return Err(BackendError::Invalid);
            }
        }
        Ok(())
    }

    /// Program and enable the command queue in the zeroed page `cq` and the
    /// fault queue in the zeroed page `fq`, each empty, its interrupt off.
    ///
    /// # Errors
    /// [`BackendError::Timeout`] when a queue does not come on.
    fn start_queues(&mut self, cq: u64, fq: u64) -> Result<(), BackendError>
    {
        (self.cq, self.fq, self.cq_tail) = (cq, fq, 0);
        self.write64(regs::CQB, regs::queue_base(cq, CQ_ENTRIES));
        self.write32(regs::CQT, 0);
        self.start_queue(regs::CQCSR, regs::CQCSR_CQEN, regs::CQCSR_CQON)?;
        self.write64(regs::FQB, regs::queue_base(fq, FQ_ENTRIES));
        self.write32(regs::FQH, 0);
        self.start_queue(regs::FQCSR, regs::FQCSR_FQEN, regs::FQCSR_FQON)
    }

    /// Point `ddtp` at the empty directory rooted at the zeroed page `root`
    /// in the first mode of [`regs::directory_modes`] the IOMMU retains,
    /// which turns translation on.
    ///
    /// # Errors
    /// [`BackendError::Timeout`] when a write does not complete;
    /// [`BackendError::Invalid`] when the IOMMU retains no directory mode.
    fn select_directory(&mut self, root: u64) -> Result<(), BackendError>
    {
        let format = self.cap.context_format;
        for mode in regs::directory_modes(format)
        {
            self.set_ddtp(regs::ddtp(mode, root))?;
            if regs::ddtp_mode(self.read64(regs::DDTP)) == mode as u64
            {
                self.ddt = DeviceDirectory::new(root, mode.levels(), format);
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
        // An adopted unit keeps translating through the tables it holds.
        if set_up.is_err()
            && self.start == Start::Reset
            && let Ok(u) = self.unit_mut(unit)
        {
            u.ddt = None;
            u.restore_bare();
        }
        set_up
    }

    fn disable_all(&mut self)
    {
        if self.start == Start::Adopt
        {
            return;
        }
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
        let u = self.unit(unit)?;
        let (ddt, mode) = (u.ddt.ok_or(BackendError::Invalid)?, u.mode);
        let (page, first) = ddt
            .context(&mut self.store, device_id)
            .map_err(table_error)?;
        let tables = FirstStage::new(&mut self.store, mode).ok_or(BackendError::OutOfMemory)?;
        let words = device_context(tables.root(), mode, did);
        // The context's other words are written first, highest first, and
        // `tc`, which holds the valid bit, last, so the IOMMU never reads a
        // valid context beside stale words; each store is volatile and
        // fenced before the next ([`Self::write_word`]). The context's words
        // lie in its leaf page, so no index below saturates.
        for i in (1..ddt.context_words()).rev()
        {
            self.write_word(
                page,
                first.saturating_add(i),
                words.get(i).copied().unwrap_or(0),
            )?;
        }
        self.write_word(page, first, words[0])?;
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
            pscid: did,
            tables,
        })
    }

    fn commit(&mut self) -> Result<(), BackendError>
    {
        if self.start != Start::Adopt || self.committed
        {
            return Err(BackendError::Invalid);
        }
        for unit in 0..self.units.len()
        {
            self.commit_unit(unit)?;
        }
        self.committed = true;
        Ok(())
    }

    fn map(
        &mut self,
        domain: &mut RiscvDomain,
        iova: u64,
        phys: u64,
        len: u64,
        access: Access,
    ) -> Result<(), BackendError>
    {
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

    /// The device's MSI write to the IMSIC file is translated as any other
    /// write of it, through its first stage, so the file's page is mapped
    /// there at its own address, read-write, since a first-stage entry
    /// cannot allow writes without reads. `msiptp` stays Off, as the
    /// specification requires while the second stage is Bare (README § MSI
    /// confinement).
    fn map_msi(&mut self, domain: &mut RiscvDomain, file: u64) -> Result<(), BackendError>
    {
        self.map(domain, file, file, PAGE, Access::ReadWrite)
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
        let ddt = self.unit(domain.unit)?.ddt.ok_or(BackendError::Invalid)?;
        // The device's attach linked every directory page on the way, so
        // the lookup takes no page.
        let (page, first) = ddt
            .context(&mut self.store, domain.device_id)
            .map_err(table_error)?;
        // Clearing `tc` clears the valid bit; the other words are then
        // don't-care.
        self.write_word(page, first, 0)?;
        self.submit(
            domain.unit,
            &[
                regs::iodir_inval_ddt(Directory::Device(domain.device_id)),
                regs::iotinval_vma(Translations::Domain(domain.pscid)),
                regs::iofence_c(Fence::DeviceAccesses),
            ],
        )
    }

    /// The unit's address width and domain IDs; zero widths and IDs for a
    /// unit the backend does not hold, which [`Service`](iommu_core::Service)
    /// never asks for.
    fn query(&self, unit: usize) -> UnitInfo
    {
        self.units.get(unit).map_or(
            UnitInfo {
                width_bits: 0,
                domain_ids: 0,
            },
            |u| UnitInfo {
                width_bits: u.mode.width_bits(),
                domain_ids: PSCIDS,
            },
        )
    }

    fn poll_faults(&mut self, record: &mut dyn FnMut(Fault))
    {
        let Self { units, store, .. } = self;
        for (index, u) in units.iter().enumerate()
        {
            if u.ddt.is_none()
            {
                continue;
            }
            let Some(queue) = store.page_ptr(u.fq)
            else
            {
                continue;
            };
            let csr = u.read32(regs::FQCSR);
            let tail = u.read32(regs::FQT) % FQ_ENTRIES;
            let mut head = u.read32(regs::FQH) % FQ_ENTRIES;
            // The records are read after the tail that publishes them.
            mmio::mmio_to_dma_barrier();
            while head != tail
            {
                // `head` stays below `FQ_ENTRIES`, whose records fill the
                // page, so no step saturates.
                let at = (head as usize).saturating_mul(FAULT_RECORD_WORDS);
                let mut words = [0u64; FAULT_RECORD_WORDS];
                for (i, w) in words.iter_mut().enumerate()
                {
                    // SAFETY: `head` is below `FQ_ENTRIES` and `i` below
                    // `FAULT_RECORD_WORDS`, so the record's word lies in the
                    // fault-queue page's 512.
                    let word = unsafe { queue.add(at.saturating_add(i)) };
                    // SAFETY: `queue` is the fault-queue page, mapped for the
                    // driver's life, and `word` lies in it. The IOMMU writes
                    // the page, so it is read through the raw pointer alone,
                    // with no reference to it formed.
                    *w = unsafe { core::ptr::read_volatile(word) };
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
                head = head.saturating_add(1) % FQ_ENTRIES;
            }
            // The records are read before the head hands their slots back.
            mmio::dma_read_to_mmio_barrier();
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

    /// Refused, the table's cap deleted: the RISC-V IOMMU reaches a
    /// device's MSIs through its DMA translation ([`Self::map_msi`]), not
    /// through a remapping table.
    fn remap_enable(
        &mut self,
        _entries: u32,
        _extended: bool,
        table: u64,
    ) -> Result<bool, BackendError>
    {
        let _ = syscall::cap_delete(table);
        Err(BackendError::Invalid)
    }

    /// Nothing to turn off: [`Self::remap_enable`] turns nothing on.
    fn remap_disable(&mut self) {}

    /// Refused, as [`Self::remap_enable`] is.
    fn remap_set(&mut self, _handle: u16, _entry: RemapEntry) -> Result<(), BackendError>
    {
        Err(BackendError::Invalid)
    }

    /// Refused, as [`Self::remap_enable`] is.
    fn remap_clear(&mut self, _handle: u16) -> Result<(), BackendError>
    {
        Err(BackendError::Invalid)
    }
}
