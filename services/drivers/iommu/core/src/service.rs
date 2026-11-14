// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/drivers/iommu/core/src/service.rs

//! The `ipc::iommu_labels` service an IOMMU driver runs for devmgr, and the
//! per-domain record that bounds and checks each request before its
//! [`Backend`] runs.
//!
//! [`Service::handle`] answers one request: it checks the label version,
//! that the unit or domain exists, that the requester ID belongs to the unit,
//! that a mapped cap is a Memory cap with the rights the access needs, and
//! that a range is page-aligned, inside the unit's width, and clear of the
//! domain's other ranges, and only then calls the backend. It keeps each
//! mapped cap while its range is installed and deletes it at the range's
//! `UNMAP`, the domain's `BLOCK`, or at once when it refuses the request. A
//! firmware-reserved range `MAP_RESERVED` installs at its own address, and an
//! interrupt file's page `MAP_MSI` installs at its own, carry no cap and stand
//! until the domain's `BLOCK`. A unit whose backend reports
//! a timeout is treated as failed: every later request on it is refused with
//! `HARDWARE_TIMEOUT`. Interrupt remapping (`REMAP_SETUP`, `REMAP_SET`,
//! `REMAP_CLEAR`) spans every unit: the service checks each entry's handle,
//! destination, vector, and source ID against the table it set up, and a
//! timeout fails the remapping as a whole.
//!
//! [`serve`] receives on the service endpoint for the rest of the driver's
//! life and [`poll_faults`] polls the units' fault records on a thread of the
//! driver's own; both reach the one [`Service`] through a [`Lock`] the
//! driver supplies, held for one request or one poll. Three kinds of IPC
//! can be made under it: a request that needs table pages the backend's
//! store lacks takes them from memmgr; any heap allocation under it (a
//! domain, range, or chunk record, or the run table of the VA arena a new
//! chunk is reserved from) may grow the heap, which calls memmgr too; and a
//! backend failure path may log (a call to the log service). The one other
//! thread the lock serializes against is the fault poll, which then waits
//! those calls out; no call into devmgr is ever made under it.

use alloc::vec::Vec;

use ipc::devmgr_dma_labels::{ACCESS_DEVICE_WRITE, ACCESS_MASK};
use ipc::recv_guard::{RecvFailureStage, RecvGuard};
use ipc::{IpcMessage, iommu_errors, iommu_labels};
use syscall_abi::{PAGE_SIZE, RIGHTS_MEM_MAP, RIGHTS_MEM_WRITE};

use crate::bootstrap::Units;
use crate::faults::{Fault, FaultQueue};
use crate::{Access, Backend, BackendError, RemapEntry};

/// Domains one driver holds at once, over all its units: one per PCI
/// function devmgr attaches, which it does once per function per boot.
/// `docs/limits.md` classifies the bound.
pub const MAX_DOMAINS: usize = 256;
/// Ranges one domain holds at once. devmgr bounds a device's mappings below
/// it (`devmgr_firmware::dma::MAX_MAPPINGS_PER_DEVICE`); the driver's own
/// bound keeps a caller that does not from growing its record without end.
pub const MAX_RANGES_PER_DOMAIN: usize = 64;
/// Interrupt files one domain reaches at once (`MAP_MSI`), apart from its
/// ranges: one per message-signalled vector at most, and a device has at
/// most 64 (`driver_binding::decl::MAX_MSI_VECTORS`). `docs/limits.md`
/// classifies the bound.
pub const MAX_MSI_FILES_PER_DOMAIN: usize = 64;
/// How often, in milliseconds, [`poll_faults`] reads the units' fault
/// records. A tuning value that bounds no capacity: a unit that records
/// faults faster than this drains them overflows its few records, and the
/// unit then drops faults until the next poll.
pub const FAULT_POLL_MS: u64 = 100;
/// Entries one interrupt remapping table holds at most
/// (`iommu_labels::MAX_REMAP_ENTRIES`).
#[expect(
    clippy::cast_possible_truncation,
    reason = "the label's bound is 2^16, which fits"
)]
pub const MAX_REMAP_ENTRIES: u32 = iommu_labels::MAX_REMAP_ENTRIES as u32;
/// The lowest vector a remapping entry may deliver: vectors below 16 are
/// reserved for exceptions on x86-64 and invalid for a fixed interrupt.
const MIN_REMAP_VECTOR: u64 = 16;

/// A Memory cap's frames and rights, as the kernel reports them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryCap
{
    /// Physical address of the first byte.
    pub phys: u64,
    /// Bytes the cap covers.
    pub len: u64,
    /// The cap's rights (`RIGHTS_MEM_*`).
    pub rights: u64,
}

/// The kernel operations the service makes on the caps a request carries.
pub trait CapOps
{
    /// The frames and rights of `cap`; `None` when it is not a Memory cap.
    fn memory(&self, cap: u64) -> Option<MemoryCap>;
    /// Delete `cap` from the driver's `CSpace`.
    fn delete(&self, cap: u64);
}

/// [`CapOps`] through the kernel's `SYS_CAP_INFO` and `SYS_CAP_DELETE`.
///
/// The frames a `MAP` request carries are a driver's, whose caps lack
/// `RIGHTS_MEM_PHYS`, so their physical bases are read presenting
/// `credential`, a Memory cap of the IOMMU driver's own that carries it: the
/// driver is phys-class, so memmgr's grants to it keep the right
/// (core/kernel/docs/cross-boundary-disclosure.md § Physical-address
/// surfaces).
pub struct KernelCaps
{
    credential: u64,
}

impl KernelCaps
{
    /// Take a one-page grant from memmgr on `memmgr_ep` as the credential,
    /// held for the driver's life and never mapped. `None` when memmgr
    /// refuses it; a reply of any other shape is deleted.
    ///
    /// # Safety
    /// `ipc_buf` MUST be the calling thread's registered IPC buffer.
    #[must_use]
    pub unsafe fn new(memmgr_ep: u64, ipc_buf: *mut u64) -> Option<Self>
    {
        let req = IpcMessage::builder(ipc::memmgr_labels::REQUEST_MEMORY_CAPS)
            .word(0, 1)
            .build();
        // SAFETY: the caller's contract makes `ipc_buf` this thread's
        // registered IPC buffer.
        let reply = unsafe { ipc::ipc_call(memmgr_ep, &req, ipc_buf) }.ok()?;
        let caps = reply.caps();
        if reply.label == ipc::memmgr_errors::SUCCESS
            && let [credential] = *caps
        {
            return Some(Self { credential });
        }
        for &c in caps
        {
            let _ = syscall::cap_delete(c);
        }
        None
    }
}

impl CapOps for KernelCaps
{
    fn memory(&self, cap: u64) -> Option<MemoryCap>
    {
        let tag_rights = syscall::cap_info(cap, syscall::CAP_INFO_TAG_RIGHTS).ok()?;
        // CAP_INFO_TAG_RIGHTS packs the tag above bit 32 and the rights below.
        if tag_rights >> 32 != u64::from(syscall::CAP_TAG_MEMORY)
        {
            return None;
        }
        Some(MemoryCap {
            phys: syscall::cap_info_phys_base(cap, self.credential).ok()?,
            len: syscall::cap_info(cap, syscall::CAP_INFO_MEMORY_SIZE).ok()?,
            rights: tag_rights & 0xFFFF_FFFF,
        })
    }

    fn delete(&self, cap: u64)
    {
        let _ = syscall::cap_delete(cap);
    }
}

/// Exclusive access to a value shared between threads: the driver's
/// [`Service`], shared by [`serve`] and [`poll_faults`].
pub trait Lock<T>
{
    /// Run `f` on the value with no other thread inside it.
    fn with<R>(&self, f: impl FnOnce(&mut T) -> R) -> R;
}

/// What an installed range of a domain is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind
{
    /// A `MAP` range, and the cap over its frames the driver keeps while it
    /// stands.
    Mapped(u64),
    /// A firmware-reserved range (`MAP_RESERVED`), which no cap covers and
    /// no `UNMAP` withdraws.
    Reserved,
    /// An interrupt file's page (`MAP_MSI`), which no cap covers and no
    /// `UNMAP` withdraws.
    MsiFile,
}

/// One installed range of a domain.
struct Range
{
    iova: u64,
    len: u64,
    kind: Kind,
}

impl Range
{
    /// Whether the range shares a byte with `iova..end`. [`Service::install`]
    /// refuses a range whose end passes `u64`, so neither end saturates.
    fn overlaps(&self, iova: u64, end: u64) -> bool
    {
        self.iova < end && iova < self.iova.saturating_add(self.len)
    }

    /// The cap the driver keeps for the range: a `MAP` range's only.
    fn cap(&self) -> Option<u64>
    {
        match self.kind
        {
            Kind::Mapped(cap) => Some(cap),
            Kind::Reserved | Kind::MsiFile => None,
        }
    }
}

/// One attached function: its domain handle, unit, requester, domain ID,
/// the backend's state for it, and the ranges installed in it.
struct DomainRecord<D>
{
    handle: u64,
    unit: usize,
    bdf: u16,
    did: u32,
    domain: D,
    ranges: Vec<Range>,
}

/// The interrupt remapping table `REMAP_SETUP` set up.
#[derive(Clone, Copy)]
struct Remap
{
    entries: u32,
    /// 32-bit destinations; 8-bit when false.
    extended: bool,
}

/// The driver's state: its backend, its units' scopes, every attached
/// domain, the interrupt remapping, and the faults polled and not yet taken.
pub struct Service<B: Backend, C: CapOps>
{
    backend: B,
    caps: C,
    units: Units,
    failed: Vec<bool>,
    domains: Vec<DomainRecord<B::Domain>>,
    next_handle: u64,
    remap: Option<Remap>,
    /// A unit timed out on a remapping command: every later remapping
    /// request is refused with `HARDWARE_TIMEOUT`.
    remap_failed: bool,
    faults: FaultQueue,
}

/// An `iommu_errors` code for a backend failure.
fn backend_code(e: BackendError) -> u64
{
    match e
    {
        BackendError::Invalid => iommu_errors::INVALID_REQUEST,
        BackendError::OutOfMemory => iommu_errors::OUT_OF_RESOURCES,
        BackendError::Timeout => iommu_errors::HARDWARE_TIMEOUT,
    }
}

impl<B: Backend, C: CapOps> Service<B, C>
{
    /// A service over `backend` for `units`, with no domain. `None` when its
    /// records cannot be reserved.
    #[must_use]
    pub fn new(backend: B, caps: C, units: Units) -> Option<Self>
    {
        let mut failed = Vec::new();
        failed.try_reserve_exact(units.0.len()).ok()?;
        failed.resize(units.0.len(), false);
        Some(Self {
            backend,
            caps,
            units,
            failed,
            domains: Vec::new(),
            next_handle: 1,
            remap: None,
            remap_failed: false,
            faults: FaultQueue::new()?,
        })
    }

    /// Program every unit empty and turn its translation on
    /// ([`Backend::init_unit`]). On a unit's failure every unit enabled
    /// before it is turned off again ([`Backend::disable_all`]), so a driver
    /// whose setup fails leaves no device blocked.
    ///
    /// # Errors
    /// The index of the unit that failed and why.
    pub fn init(&mut self) -> Result<(), (usize, BackendError)>
    {
        for unit in 0..self.units.0.len()
        {
            if let Err(e) = self.backend.init_unit(unit)
            {
                self.backend.disable_all();
                return Err((unit, e));
            }
        }
        Ok(())
    }

    /// Turn translation off on every unit ([`Backend::disable_all`]): the
    /// driver could not report ready, so devmgr runs every device
    /// unconfined.
    pub fn disable(&mut self)
    {
        self.backend.disable_all();
    }

    /// Poll the units' fault records into the queue. Returns the faults the
    /// queue dropped since the last poll for want of room.
    pub fn poll(&mut self) -> u64
    {
        let faults = &mut self.faults;
        self.backend.poll_faults(&mut |f| faults.push(f));
        self.faults.take_dropped()
    }

    /// Answer one request, taking ownership of the caps it carries: a
    /// mapped cap is kept while its range stands, and every other cap is
    /// deleted. Returns the reply.
    pub fn handle(&mut self, msg: &IpcMessage) -> IpcMessage
    {
        let caps = msg.caps();
        let kept = if msg.label == iommu_labels::MAP
        {
            caps.first().copied()
        }
        else
        {
            None
        };
        for &c in caps.iter().skip(usize::from(kept.is_some()))
        {
            self.caps.delete(c);
        }
        if msg.word(0) != u64::from(ipc::IOMMU_LABELS_VERSION)
        {
            if let Some(c) = kept
            {
                self.caps.delete(c);
            }
            return IpcMessage::new(iommu_errors::LABEL_VERSION_MISMATCH);
        }
        let code = match msg.label
        {
            iommu_labels::ATTACH => match self.attach(msg.word(1), msg.word(2))
            {
                Ok(handle) =>
                {
                    return IpcMessage::builder(iommu_errors::SUCCESS)
                        .word(0, handle)
                        .build();
                }
                Err(code) => code,
            },
            iommu_labels::MAP =>
            {
                let Some(cap) = kept
                else
                {
                    return IpcMessage::new(iommu_errors::INVALID_REQUEST);
                };
                let result = self.map(msg.word(1), msg.word(2), msg.word(3), cap);
                if result.is_err()
                {
                    self.caps.delete(cap);
                }
                result.err().unwrap_or(iommu_errors::SUCCESS)
            }
            iommu_labels::MAP_RESERVED => self
                .map_reserved(msg.word(1), msg.word(2), msg.word(3))
                .err()
                .unwrap_or(iommu_errors::SUCCESS),
            iommu_labels::MAP_MSI => self
                .map_msi(msg.word(1), msg.word(2))
                .err()
                .unwrap_or(iommu_errors::SUCCESS),
            iommu_labels::UNMAP => self.unmap(msg.word(1), msg.word(2)),
            iommu_labels::BLOCK => self.block(msg.word(1)),
            iommu_labels::QUERY_UNIT => match self.query(msg.word(1))
            {
                Some(width) =>
                {
                    return IpcMessage::builder(iommu_errors::SUCCESS)
                        .word(0, u64::from(width))
                        .build();
                }
                None => iommu_errors::INVALID_REQUEST,
            },
            iommu_labels::TAKE_FAULTS => return self.take_faults(),
            iommu_labels::REMAP_SETUP => match self.remap_setup(msg.word(1), msg.word(2))
            {
                Ok(extended) =>
                {
                    return IpcMessage::builder(iommu_errors::SUCCESS)
                        .word(0, u64::from(extended))
                        .build();
                }
                Err(code) => code,
            },
            iommu_labels::REMAP_SET =>
            {
                let w = |i| msg.word(i);
                self.remap_set(w(1), [w(2), w(3), w(4), w(5)])
                    .err()
                    .unwrap_or(iommu_errors::SUCCESS)
            }
            iommu_labels::REMAP_CLEAR => self
                .remap_clear(msg.word(1))
                .err()
                .unwrap_or(iommu_errors::SUCCESS),
            _ => iommu_errors::UNKNOWN_OPCODE,
        };
        IpcMessage::new(code)
    }

    /// The `iommu_errors` code for a backend failure on `unit`, marking the
    /// unit failed on a timeout.
    fn backend_failure(&mut self, unit: usize, e: BackendError) -> u64
    {
        if e == BackendError::Timeout
            && let Some(failed) = self.failed.get_mut(unit)
        {
            *failed = true;
        }
        backend_code(e)
    }

    /// `Ok` for a delivered unit that has not timed out. Every caller passes
    /// a unit it checked delivered or a domain's unit, so the
    /// `INVALID_REQUEST` of an undelivered one is never returned.
    fn unit_ok(&self, unit: usize) -> Result<(), u64>
    {
        match self.failed.get(unit)
        {
            Some(false) => Ok(()),
            Some(true) => Err(iommu_errors::HARDWARE_TIMEOUT),
            None => Err(iommu_errors::INVALID_REQUEST),
        }
    }

    fn domain_index(&self, handle: u64) -> Result<usize, u64>
    {
        self.domains
            .iter()
            .position(|d| d.handle == handle)
            .ok_or(iommu_errors::INVALID_REQUEST)
    }

    /// The lowest domain ID of `unit` no domain holds, from 1: domain ID 0
    /// stays unused, since a unit in caching mode reserves it.
    fn free_did(&self, unit: usize) -> Option<u32>
    {
        let ids = self.backend.query(unit).domain_ids;
        (1..ids).find(|&did| !self.domains.iter().any(|d| d.unit == unit && d.did == did))
    }

    fn attach(&mut self, unit_word: u64, rid: u64) -> Result<u64, u64>
    {
        let invalid = iommu_errors::INVALID_REQUEST;
        let unit = usize::try_from(unit_word).map_err(|_| invalid)?;
        let segment = u16::try_from(rid >> 16).map_err(|_| invalid)?;
        let bdf = u16::try_from(rid & 0xffff).map_err(|_| invalid)?;
        if unit >= self.units.0.len() || self.units.unit_for(segment, bdf) != Some(unit)
        {
            return Err(invalid);
        }
        self.unit_ok(unit)?;
        if let Some(d) = self.domains.iter().find(|d| d.unit == unit && d.bdf == bdf)
        {
            return Ok(d.handle);
        }
        let exhausted = iommu_errors::OUT_OF_RESOURCES;
        if self.domains.len() >= MAX_DOMAINS
        {
            return Err(exhausted);
        }
        let did = self.free_did(unit).ok_or(exhausted)?;
        // Handles are never reused, so a driver that has handed out every
        // one attaches no further domain.
        let handle = self.next_handle;
        let next_handle = handle.checked_add(1).ok_or(exhausted)?;
        self.domains.try_reserve(1).map_err(|_| exhausted)?;
        let domain = self
            .backend
            .attach(unit, bdf, did)
            .map_err(|e| self.backend_failure(unit, e))?;
        self.next_handle = next_handle;
        self.domains.push(DomainRecord {
            handle,
            unit,
            bdf,
            did,
            domain,
            ranges: Vec::new(),
        });
        Ok(handle)
    }

    fn map(&mut self, handle: u64, iova: u64, access: u64, cap: u64) -> Result<(), u64>
    {
        let invalid = iommu_errors::INVALID_REQUEST;
        let index = self.domain_index(handle)?;
        if access == 0 || access & !ACCESS_MASK != 0
        {
            return Err(invalid);
        }
        let access = if access & ACCESS_DEVICE_WRITE != 0
        {
            Access::ReadWrite
        }
        else
        {
            Access::Read
        };
        let mem = self.caps.memory(cap).ok_or(invalid)?;
        let needed = match access
        {
            Access::ReadWrite => RIGHTS_MEM_MAP | RIGHTS_MEM_WRITE,
            Access::Read => RIGHTS_MEM_MAP,
        };
        if mem.rights & needed != needed || mem.phys & (PAGE_SIZE - 1) != 0
        {
            return Err(invalid);
        }
        self.install(index, iova, mem.len, Kind::Mapped(cap), (mem.phys, access))
    }

    /// Install the firmware-reserved range of `len` bytes at `base` in the
    /// domain `handle` at its own address, read-write, with no cap.
    fn map_reserved(&mut self, handle: u64, base: u64, len: u64) -> Result<(), u64>
    {
        let index = self.domain_index(handle)?;
        self.install(index, base, len, Kind::Reserved, (base, Access::ReadWrite))
    }

    /// Install the interrupt file's page at `file` in the domain `handle` at
    /// its own address, with no cap ([`Backend::map_msi`]).
    fn map_msi(&mut self, handle: u64, file: u64) -> Result<(), u64>
    {
        let index = self.domain_index(handle)?;
        self.install(
            index,
            file,
            PAGE_SIZE,
            Kind::MsiFile,
            (file, Access::ReadWrite),
        )
    }

    /// Install `len` bytes at `iova` in the domain at `index`, once the range
    /// is checked page-aligned, nonempty, within the unit's width, clear of
    /// the domain's other ranges, and within the domain's bound for its
    /// `kind`, recording it as `kind`. A [`Kind::MsiFile`] page is installed
    /// by [`Backend::map_msi`]; any other range from the physical address and
    /// with the access of `frames` by [`Backend::map`].
    fn install(
        &mut self,
        index: usize,
        iova: u64,
        len: u64,
        kind: Kind,
        frames: (u64, Access),
    ) -> Result<(), u64>
    {
        let invalid = iommu_errors::INVALID_REQUEST;
        let record = self.domains.get(index).ok_or(invalid)?;
        let unit = record.unit;
        let width = self.backend.query(unit).width_bits;
        let end = iova.checked_add(len).ok_or(invalid)?;
        if len == 0
            || (iova | len) & (PAGE_SIZE - 1) != 0
            || u32::from(width) < 64 && end > 1u64 << width
        {
            return Err(invalid);
        }
        if record.ranges.iter().any(|r| r.overlaps(iova, end))
        {
            return Err(iommu_errors::ADDRESS_IN_USE);
        }
        let is_file = |r: &Range| r.kind == Kind::MsiFile;
        let (held, bound) = if kind == Kind::MsiFile
        {
            (
                record.ranges.iter().filter(|r| is_file(r)).count(),
                MAX_MSI_FILES_PER_DOMAIN,
            )
        }
        else
        {
            (
                record.ranges.iter().filter(|r| !is_file(r)).count(),
                MAX_RANGES_PER_DOMAIN,
            )
        };
        if held >= bound
        {
            return Err(iommu_errors::OUT_OF_RESOURCES);
        }
        self.unit_ok(unit)?;
        let record = self.domains.get_mut(index).ok_or(invalid)?;
        record
            .ranges
            .try_reserve(1)
            .map_err(|_| iommu_errors::OUT_OF_RESOURCES)?;
        let installed = if kind == Kind::MsiFile
        {
            self.backend.map_msi(&mut record.domain, iova)
        }
        else
        {
            self.backend
                .map(&mut record.domain, iova, frames.0, len, frames.1)
        };
        if let Err(e) = installed
        {
            return Err(self.backend_failure(unit, e));
        }
        record.ranges.push(Range { iova, len, kind });
        Ok(())
    }

    fn unmap(&mut self, handle: u64, iova: u64) -> u64
    {
        let invalid = iommu_errors::INVALID_REQUEST;
        let index = match self.domain_index(handle)
        {
            Ok(i) => i,
            Err(code) => return code,
        };
        let Some(record) = self.domains.get(index)
        else
        {
            return invalid;
        };
        let unit = record.unit;
        let Some((at, range)) = record
            .ranges
            .iter()
            .enumerate()
            .find(|(_, r)| r.iova == iova)
        else
        {
            return iommu_errors::NO_MAPPING;
        };
        if range.cap().is_none()
        {
            return invalid;
        }
        let len = range.len;
        if let Err(code) = self.unit_ok(unit)
        {
            return code;
        }
        let Some(record) = self.domains.get_mut(index)
        else
        {
            return invalid;
        };
        if let Err(e) = self.backend.unmap(&mut record.domain, iova, len)
        {
            return self.backend_failure(unit, e);
        }
        let range = record.ranges.swap_remove(at);
        if let Some(cap) = range.cap()
        {
            self.caps.delete(cap);
        }
        iommu_errors::SUCCESS
    }

    fn block(&mut self, handle: u64) -> u64
    {
        let index = match self.domain_index(handle)
        {
            Ok(i) => i,
            Err(code) => return code,
        };
        let Some(unit) = self.domains.get(index).map(|d| d.unit)
        else
        {
            return iommu_errors::INVALID_REQUEST;
        };
        if let Err(code) = self.unit_ok(unit)
        {
            return code;
        }
        let Some(record) = self.domains.get_mut(index)
        else
        {
            return iommu_errors::INVALID_REQUEST;
        };
        if let Err(e) = self.backend.block(&mut record.domain)
        {
            return self.backend_failure(unit, e);
        }
        let record = self.domains.swap_remove(index);
        for cap in record.ranges.iter().filter_map(Range::cap)
        {
            self.caps.delete(cap);
        }
        iommu_errors::SUCCESS
    }

    fn query(&self, unit_word: u64) -> Option<u8>
    {
        let unit = usize::try_from(unit_word).ok()?;
        (unit < self.units.0.len()).then(|| self.backend.query(unit).width_bits)
    }

    /// The `iommu_errors` code for a backend failure of a remapping command,
    /// failing the remapping on a timeout.
    fn remap_failure(&mut self, e: BackendError) -> u64
    {
        if e == BackendError::Timeout
        {
            self.remap_failed = true;
        }
        backend_code(e)
    }

    /// Set up interrupt remapping with a table of `entries` entries, or turn
    /// it off for 0 (`REMAP_SETUP`); whether its destinations are 32-bit.
    /// Refused while the units translate more than one PCI segment: the one
    /// table they share names an entry's requester by a source ID with no
    /// segment, so a function on one segment would pass the entries written
    /// for the same-numbered function on another.
    fn remap_setup(&mut self, entries: u64, extended: u64) -> Result<bool, u64>
    {
        let invalid = iommu_errors::INVALID_REQUEST;
        if extended > 1
        {
            return Err(invalid);
        }
        if entries == 0
        {
            self.backend.remap_disable();
            self.remap = None;
            return Ok(false);
        }
        let entries = u32::try_from(entries).map_err(|_| invalid)?;
        let segments_differ = self
            .units
            .0
            .first()
            .is_some_and(|first| self.units.0.iter().any(|u| u.segment != first.segment));
        if self.remap.is_some()
            || !entries.is_power_of_two()
            || !(2..=MAX_REMAP_ENTRIES).contains(&entries)
            || segments_differ
        {
            return Err(invalid);
        }
        if self.remap_failed
        {
            return Err(iommu_errors::HARDWARE_TIMEOUT);
        }
        let extended = self
            .backend
            .remap_enable(entries, extended == 1)
            .map_err(|e| self.remap_failure(e))?;
        self.remap = Some(Remap { entries, extended });
        Ok(extended)
    }

    /// The handle `word` names in the remapping set up, once it is checked
    /// below the table's entries and the remapping has not failed.
    fn remap_handle(&self, word: u64) -> Result<(u16, Remap), u64>
    {
        let invalid = iommu_errors::INVALID_REQUEST;
        let remap = self.remap.ok_or(invalid)?;
        if word >= u64::from(remap.entries)
        {
            return Err(invalid);
        }
        if self.remap_failed
        {
            return Err(iommu_errors::HARDWARE_TIMEOUT);
        }
        Ok((u16::try_from(word).map_err(|_| invalid)?, remap))
    }

    /// Make entry `handle` deliver as `[destination, vector, level, source
    /// ID]` says (`REMAP_SET`), once each field is checked within its bound.
    fn remap_set(&mut self, handle: u64, fields: [u64; 4]) -> Result<(), u64>
    {
        let invalid = iommu_errors::INVALID_REQUEST;
        let (handle, remap) = self.remap_handle(handle)?;
        let [destination, vector, level, source_id] = fields;
        let widest = if remap.extended
        {
            u64::from(u32::MAX)
        }
        else
        {
            u64::from(u8::MAX)
        };
        if destination > widest || !(MIN_REMAP_VECTOR..=255).contains(&vector) || level > 1
        {
            return Err(invalid);
        }
        let entry = RemapEntry {
            destination: u32::try_from(destination).map_err(|_| invalid)?,
            vector: u8::try_from(vector).map_err(|_| invalid)?,
            level: level == 1,
            source_id: u16::try_from(source_id).map_err(|_| invalid)?,
        };
        self.backend
            .remap_set(handle, entry)
            .map_err(|e| self.remap_failure(e))
    }

    /// Make entry `handle` not present (`REMAP_CLEAR`).
    fn remap_clear(&mut self, handle: u64) -> Result<(), u64>
    {
        let (handle, _) = self.remap_handle(handle)?;
        self.backend
            .remap_clear(handle)
            .map_err(|e| self.remap_failure(e))
    }

    /// Poll the units, so the reply holds every fault recorded so far, and
    /// take the oldest queued faults into the reply.
    fn take_faults(&mut self) -> IpcMessage
    {
        self.poll();
        let mut pairs = [[0u64; 2]; iommu_labels::MAX_FAULTS_PER_REPLY];
        let mut slots = pairs.iter_mut();
        let units = &self.units;
        let n = self
            .faults
            .take(iommu_labels::MAX_FAULTS_PER_REPLY, |f: Fault| {
                let segment = units.0.get(f.unit).map_or(0, |u| u.segment);
                let [bus, devfn] = f.bdf.to_be_bytes();
                let rid = iommu_labels::requester_id(segment, bus, devfn >> 3, devfn & 7);
                // `take` passes at most as many faults as there are slots.
                if let Some(slot) = slots.next()
                {
                    *slot = [rid | (u64::from(f.reason) << 32), f.iova];
                }
            });
        let taken = pairs.get(..n).unwrap_or_default();
        IpcMessage::builder(iommu_errors::SUCCESS)
            .word(0, n as u64)
            .words(1, taken.as_flattened())
            .build()
    }
}

/// Receive on `service_ep` for the rest of the driver's life and answer each
/// request through `service` ([`Service::handle`]).
///
/// # Safety
/// `ipc_buf` must point to the calling thread's registered IPC buffer page.
pub unsafe fn serve<B, C, L>(
    service_ep: u64,
    ipc_buf: *mut u64,
    service: &L,
    diag: fn(RecvFailureStage, i64),
) -> !
where
    B: Backend,
    C: CapOps,
    L: Lock<Service<B, C>>,
{
    let mut guard = RecvGuard::new(diag);
    loop
    {
        // SAFETY: the caller guarantees `ipc_buf` is the registered IPC buffer.
        let msg = match unsafe { ipc::ipc_recv(service_ep, ipc_buf) }
        {
            Ok(msg) => msg,
            Err(e) =>
            {
                guard.on_failure(e);
                continue;
            }
        };
        guard.on_success();
        let reply = service.with(|s| s.handle(&msg));
        // SAFETY: as above. A reply the caller cannot take needs nothing
        // further: it moves no cap.
        let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
    }
}

/// Poll the units' fault records every [`FAULT_POLL_MS`] for the rest of the
/// driver's life ([`Service::poll`]), calling `on_dropped` with the count of
/// faults the queue had no room for.
pub fn poll_faults<B, C, L>(service: &L, on_dropped: fn(u64)) -> !
where
    B: Backend,
    C: CapOps,
    L: Lock<Service<B, C>>,
{
    loop
    {
        let _ = syscall::thread_sleep(FAULT_POLL_MS);
        let dropped = service.with(Service::poll);
        if dropped != 0
        {
            on_dropped(dropped);
        }
    }
}

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::UnitInfo;
    use crate::bootstrap::{Scope, UnitScope};
    use core::cell::RefCell;
    use ipc::devmgr_dma_labels::ACCESS_DEVICE_READ;

    const RW: u64 = ACCESS_DEVICE_READ | ACCESS_DEVICE_WRITE;

    /// A backend that records what it is asked, fails on demand, and keeps
    /// each domain's installed ranges.
    #[derive(Default)]
    struct Fake
    {
        enabled: Vec<usize>,
        fail_unit: Option<(usize, BackendError)>,
        fail_next: Option<BackendError>,
        /// Refuse every `map_msi`, as a family whose MSIs its DMA
        /// translation does not reach does.
        refuse_msi: bool,
        attached: Vec<(usize, u16, u32)>,
        blocked: Vec<u32>,
        pending: Vec<Fault>,
        /// Refuse interrupt remapping, as a family that does not remap
        /// interrupts does.
        no_remap: bool,
        /// Every unit offers 32-bit destinations.
        offers_extended: bool,
        /// The remapping table's entries while remapping is on.
        remapping: Option<u32>,
        /// Every remapping entry set, in order.
        set: Vec<(u16, RemapEntry)>,
        /// Every remapping entry cleared, in order.
        cleared: Vec<u16>,
    }

    struct FakeDomain
    {
        did: u32,
        ranges: Vec<(u64, u64, u64, Access)>,
        files: Vec<u64>,
    }

    impl Fake
    {
        fn fail(&mut self) -> Result<(), BackendError>
        {
            self.fail_next.take().map_or(Ok(()), Err)
        }
    }

    impl Backend for Fake
    {
        type Domain = FakeDomain;

        fn init_unit(&mut self, unit: usize) -> Result<(), BackendError>
        {
            if let Some((u, e)) = self.fail_unit
                && u == unit
            {
                return Err(e);
            }
            self.enabled.push(unit);
            Ok(())
        }

        fn disable_all(&mut self)
        {
            self.enabled.clear();
        }

        fn attach(&mut self, unit: usize, bdf: u16, did: u32) -> Result<FakeDomain, BackendError>
        {
            self.fail()?;
            self.attached.push((unit, bdf, did));
            Ok(FakeDomain {
                did,
                ranges: Vec::new(),
                files: Vec::new(),
            })
        }

        fn map(
            &mut self,
            domain: &mut FakeDomain,
            iova: u64,
            phys: u64,
            len: u64,
            access: Access,
        ) -> Result<(), BackendError>
        {
            self.fail()?;
            domain.ranges.push((iova, phys, len, access));
            Ok(())
        }

        fn map_msi(&mut self, domain: &mut FakeDomain, file: u64) -> Result<(), BackendError>
        {
            self.fail()?;
            if self.refuse_msi
            {
                return Err(BackendError::Invalid);
            }
            domain.files.push(file);
            Ok(())
        }

        fn unmap(
            &mut self,
            domain: &mut FakeDomain,
            iova: u64,
            _len: u64,
        ) -> Result<(), BackendError>
        {
            self.fail()?;
            domain.ranges.retain(|r| r.0 != iova);
            Ok(())
        }

        fn block(&mut self, domain: &mut FakeDomain) -> Result<(), BackendError>
        {
            self.fail()?;
            self.blocked.push(domain.did);
            domain.ranges.clear();
            domain.files.clear();
            Ok(())
        }

        fn query(&self, _unit: usize) -> UnitInfo
        {
            UnitInfo {
                width_bits: 39,
                domain_ids: 4,
            }
        }

        fn poll_faults(&mut self, record: &mut dyn FnMut(Fault))
        {
            for f in self.pending.drain(..)
            {
                record(f);
            }
        }

        fn remap_enable(&mut self, entries: u32, extended: bool) -> Result<bool, BackendError>
        {
            self.fail()?;
            if self.no_remap
            {
                return Err(BackendError::Invalid);
            }
            self.remapping = Some(entries);
            Ok(extended && self.offers_extended)
        }

        fn remap_disable(&mut self)
        {
            self.remapping = None;
        }

        fn remap_set(&mut self, handle: u16, entry: RemapEntry) -> Result<(), BackendError>
        {
            self.fail()?;
            self.set.push((handle, entry));
            Ok(())
        }

        fn remap_clear(&mut self, handle: u16) -> Result<(), BackendError>
        {
            self.fail()?;
            self.cleared.push(handle);
            Ok(())
        }
    }

    /// Memory caps by slot (`phys = slot << 20`, 2 pages, read-write) except
    /// slot 9 (read-only) and slot 13 (not a Memory cap); records deletes.
    #[derive(Default)]
    struct FakeCaps
    {
        deleted: RefCell<Vec<u64>>,
    }

    impl CapOps for FakeCaps
    {
        fn memory(&self, cap: u64) -> Option<MemoryCap>
        {
            (cap != 13).then_some(MemoryCap {
                phys: cap << 20,
                len: 2 * PAGE_SIZE,
                rights: if cap == 9
                {
                    RIGHTS_MEM_MAP
                }
                else
                {
                    RIGHTS_MEM_MAP | RIGHTS_MEM_WRITE
                },
            })
        }

        fn delete(&self, cap: u64)
        {
            self.deleted.borrow_mut().push(cap);
        }
    }

    fn service() -> Service<Fake, FakeCaps>
    {
        let units = Units(vec![
            UnitScope {
                segment: 0,
                include_pci_all: true,
                scopes: vec![],
            },
            UnitScope {
                segment: 0,
                include_pci_all: false,
                scopes: vec![Scope::Function(0x0020)],
            },
        ]);
        Service::new(Fake::default(), FakeCaps::default(), units).unwrap()
    }

    fn req(label: u64, words: &[u64], caps: &[u64]) -> IpcMessage
    {
        let mut b = IpcMessage::builder(label)
            .word(0, u64::from(ipc::IOMMU_LABELS_VERSION))
            .words(1, words);
        for &c in caps
        {
            b = b.cap(c);
        }
        b.build()
    }

    fn attach(s: &mut Service<Fake, FakeCaps>, unit: u64, bdf: u64) -> IpcMessage
    {
        s.handle(&req(iommu_labels::ATTACH, &[unit, bdf], &[]))
    }

    fn domain(s: &mut Service<Fake, FakeCaps>) -> u64
    {
        let r = attach(s, 0, 0x0018);
        assert_eq!(r.label, iommu_errors::SUCCESS);
        r.word(0)
    }

    fn map(s: &mut Service<Fake, FakeCaps>, d: u64, iova: u64, access: u64, cap: u64) -> u64
    {
        s.handle(&req(iommu_labels::MAP, &[d, iova, access], &[cap]))
            .label
    }

    fn deleted(s: &Service<Fake, FakeCaps>) -> Vec<u64>
    {
        s.caps.deleted.borrow().clone()
    }

    #[test]
    fn a_unit_that_fails_its_setup_turns_every_enabled_unit_off_again()
    {
        let mut s = service();
        s.backend.fail_unit = Some((1, BackendError::Timeout));
        assert_eq!(s.init(), Err((1, BackendError::Timeout)));
        assert_eq!(s.backend.enabled, [] as [usize; 0]);
        s.backend.fail_unit = None;
        assert_eq!(s.init(), Ok(()));
        assert_eq!(s.backend.enabled, [0, 1]);
    }

    #[test]
    fn a_request_of_another_label_version_is_refused_and_its_caps_deleted()
    {
        let mut s = service();
        let stale = IpcMessage::builder(iommu_labels::MAP)
            .word(0, 0)
            .cap(5)
            .build();
        assert_eq!(s.handle(&stale).label, iommu_errors::LABEL_VERSION_MISMATCH);
        assert_eq!(deleted(&s), [5]);
    }

    #[test]
    fn a_function_attached_twice_keeps_its_first_domain()
    {
        let mut s = service();
        let d = domain(&mut s);
        assert_eq!(attach(&mut s, 0, 0x0018).word(0), d);
        assert_eq!(s.backend.attached, [(0, 0x0018, 1)]);
    }

    #[test]
    fn a_function_outside_the_named_unit_is_refused()
    {
        let mut s = service();
        // 0x20 is named by unit 1, so the catch-all unit 0 does not take it;
        // 0x18 is named by no scope, so only the catch-all does.
        assert_eq!(
            attach(&mut s, 0, 0x0020).label,
            iommu_errors::INVALID_REQUEST
        );
        assert_eq!(
            attach(&mut s, 1, 0x0018).label,
            iommu_errors::INVALID_REQUEST
        );
        assert_eq!(
            attach(&mut s, 2, 0x0018).label,
            iommu_errors::INVALID_REQUEST
        );
        assert_eq!(
            attach(&mut s, 0, 1 << 16).label,
            iommu_errors::INVALID_REQUEST
        );
        assert_eq!(attach(&mut s, 1, 0x0020).label, iommu_errors::SUCCESS);
    }

    #[test]
    fn attaching_past_the_units_domain_ids_is_refused()
    {
        let mut s = service();
        // The fake unit has 4 domain IDs; 0 is never given, so three attach.
        for bdf in 1..=3
        {
            assert_eq!(attach(&mut s, 0, bdf).label, iommu_errors::SUCCESS);
        }
        assert_eq!(attach(&mut s, 0, 4).label, iommu_errors::OUT_OF_RESOURCES);
    }

    #[test]
    fn attaching_once_every_handle_is_spent_is_refused_before_the_backend()
    {
        let mut s = service();
        s.next_handle = u64::MAX - 1;
        assert_eq!(attach(&mut s, 0, 1).word(0), u64::MAX - 1);
        assert_eq!(attach(&mut s, 0, 2).label, iommu_errors::OUT_OF_RESOURCES);
        assert_eq!(s.backend.attached, [(0, 1, 1)]);
    }

    #[test]
    fn a_mapping_is_installed_with_the_caps_frames_and_kept_until_its_unmap()
    {
        let mut s = service();
        let d = domain(&mut s);
        assert_eq!(map(&mut s, d, 0x10_0000, RW, 3), iommu_errors::SUCCESS);
        assert_eq!(
            s.domains[0].domain.ranges,
            [(0x10_0000, 3 << 20, 2 * PAGE_SIZE, Access::ReadWrite)]
        );
        assert_eq!(deleted(&s), [] as [u64; 0]);
        let unmap = req(iommu_labels::UNMAP, &[d, 0x10_0000], &[]);
        assert_eq!(s.handle(&unmap).label, iommu_errors::SUCCESS);
        assert_eq!(
            s.domains[0].domain.ranges,
            [] as [(u64, u64, u64, Access); 0]
        );
        assert_eq!(deleted(&s), [3]);
        assert_eq!(s.handle(&unmap).label, iommu_errors::NO_MAPPING);
    }

    #[test]
    fn an_overlapping_range_is_refused_and_an_adjacent_one_accepted()
    {
        let mut s = service();
        let d = domain(&mut s);
        assert_eq!(map(&mut s, d, 0x10_0000, RW, 3), iommu_errors::SUCCESS);
        assert_eq!(
            map(&mut s, d, 0x10_1000, RW, 4),
            iommu_errors::ADDRESS_IN_USE
        );
        assert_eq!(map(&mut s, d, 0x10_2000, RW, 5), iommu_errors::SUCCESS);
        assert_eq!(deleted(&s), [4]);
    }

    #[test]
    fn a_misused_map_is_refused_before_the_backend_and_its_cap_deleted()
    {
        let mut s = service();
        let d = domain(&mut s);
        let width_end = 1u64 << 39;
        for (domain, iova, access, cap) in [
            (d + 1, 0x10_0000, RW, 3),              // no such domain
            (d, 0x10_0800, RW, 3),                  // unaligned IOVA
            (d, width_end - PAGE_SIZE, RW, 3),      // past the unit's width
            (d, 0x10_0000, 0, 3),                   // no access
            (d, 0x10_0000, 1 << 2, 3),              // unknown access bit
            (d, 0x10_0000, ACCESS_DEVICE_WRITE, 9), // write to a read-only cap
            (d, 0x10_0000, ACCESS_DEVICE_READ, 13), // not a Memory cap
        ]
        {
            assert_eq!(
                map(&mut s, domain, iova, access, cap),
                iommu_errors::INVALID_REQUEST
            );
        }
        assert_eq!(
            s.domains[0].domain.ranges,
            [] as [(u64, u64, u64, Access); 0]
        );
        assert_eq!(deleted(&s), [3, 3, 3, 3, 3, 9, 13]);
        assert_eq!(map(&mut s, d, 0x10_0000, ACCESS_DEVICE_READ, 9), 0);
    }

    #[test]
    fn a_read_only_map_reaches_the_backend_read_only()
    {
        let mut s = service();
        let d = domain(&mut s);
        assert_eq!(
            map(&mut s, d, 0x10_0000, ACCESS_DEVICE_READ, 3),
            iommu_errors::SUCCESS
        );
        assert_eq!(
            s.domains[0].domain.ranges,
            [(0x10_0000, 3 << 20, 2 * PAGE_SIZE, Access::Read)]
        );
    }

    #[test]
    fn a_map_without_a_cap_is_refused()
    {
        let mut s = service();
        let d = domain(&mut s);
        assert_eq!(
            s.handle(&req(iommu_labels::MAP, &[d, 0x10_0000, RW], &[]))
                .label,
            iommu_errors::INVALID_REQUEST
        );
    }

    #[test]
    fn blocking_a_domain_withdraws_every_range_and_the_domain()
    {
        let mut s = service();
        let d = domain(&mut s);
        map(&mut s, d, 0x10_0000, RW, 3);
        map(&mut s, d, 0x20_0000, RW, 4);
        let block = req(iommu_labels::BLOCK, &[d], &[]);
        assert_eq!(s.handle(&block).label, iommu_errors::SUCCESS);
        assert_eq!(s.backend.blocked, [1]);
        assert_eq!(deleted(&s), [3, 4]);
        assert_eq!(
            map(&mut s, d, 0x10_0000, RW, 5),
            iommu_errors::INVALID_REQUEST
        );
        assert_eq!(s.handle(&block).label, iommu_errors::INVALID_REQUEST);
    }

    #[test]
    fn a_unit_that_times_out_refuses_every_later_request()
    {
        let mut s = service();
        let d = domain(&mut s);
        s.backend.fail_next = Some(BackendError::Timeout);
        assert_eq!(
            map(&mut s, d, 0x10_0000, RW, 3),
            iommu_errors::HARDWARE_TIMEOUT
        );
        assert_eq!(
            map(&mut s, d, 0x10_0000, RW, 4),
            iommu_errors::HARDWARE_TIMEOUT
        );
        assert_eq!(
            s.handle(&req(iommu_labels::BLOCK, &[d], &[])).label,
            iommu_errors::HARDWARE_TIMEOUT
        );
        assert_eq!(
            attach(&mut s, 0, 0x30).label,
            iommu_errors::HARDWARE_TIMEOUT
        );
        // The other unit is unaffected.
        assert_eq!(attach(&mut s, 1, 0x20).label, iommu_errors::SUCCESS);
    }

    #[test]
    fn a_backend_out_of_memory_refuses_the_map_and_keeps_the_unit()
    {
        let mut s = service();
        let d = domain(&mut s);
        s.backend.fail_next = Some(BackendError::OutOfMemory);
        assert_eq!(
            map(&mut s, d, 0x10_0000, RW, 3),
            iommu_errors::OUT_OF_RESOURCES
        );
        assert_eq!(map(&mut s, d, 0x10_0000, RW, 4), iommu_errors::SUCCESS);
        assert_eq!(deleted(&s), [3]);
    }

    #[test]
    fn a_domain_holds_at_most_its_bound_of_ranges()
    {
        let mut s = service();
        let d = domain(&mut s);
        for i in 0..MAX_RANGES_PER_DOMAIN as u64
        {
            assert_eq!(map(&mut s, d, 0x10_0000 + i * 0x2000, RW, 3), 0);
        }
        let next = 0x10_0000 + MAX_RANGES_PER_DOMAIN as u64 * 0x2000;
        assert_eq!(map(&mut s, d, next, RW, 3), iommu_errors::OUT_OF_RESOURCES);
    }

    #[test]
    fn a_failed_unmap_leaves_the_range_and_its_cap_installed()
    {
        let mut s = service();
        let d = domain(&mut s);
        assert_eq!(map(&mut s, d, 0x10_0000, RW, 3), iommu_errors::SUCCESS);
        s.backend.fail_next = Some(BackendError::OutOfMemory);
        let unmap = req(iommu_labels::UNMAP, &[d, 0x10_0000], &[]);
        assert_eq!(s.handle(&unmap).label, iommu_errors::OUT_OF_RESOURCES);
        assert_eq!(s.domains[0].ranges.len(), 1);
        assert_eq!(deleted(&s), [] as [u64; 0]);
        assert_eq!(s.handle(&unmap).label, iommu_errors::SUCCESS);
        assert_eq!(deleted(&s), [3]);
    }

    #[test]
    fn query_unit_reports_the_width_of_a_delivered_unit_only()
    {
        let mut s = service();
        let r = s.handle(&req(iommu_labels::QUERY_UNIT, &[1], &[]));
        assert_eq!((r.label, r.word(0)), (iommu_errors::SUCCESS, 39));
        let r = s.handle(&req(iommu_labels::QUERY_UNIT, &[2], &[]));
        assert_eq!(r.label, iommu_errors::INVALID_REQUEST);
    }

    #[test]
    fn take_faults_reports_each_polled_fault_with_its_requester_id_once()
    {
        let mut s = service();
        s.backend.pending.push(Fault {
            unit: 0,
            bdf: 0x0018,
            // A RISC-V IOMMU cause wider than 8 bits keeps all its bits.
            reason: 259,
            iova: 0x10_0000,
        });
        let take = req(iommu_labels::TAKE_FAULTS, &[], &[]);
        let r = s.handle(&take);
        assert_eq!(r.label, iommu_errors::SUCCESS);
        assert_eq!(r.words(), [1, 0x0018 | (259 << 32), 0x10_0000]);
        assert_eq!(s.handle(&take).words(), [0]);
    }

    #[test]
    fn a_take_carries_at_most_its_bound_and_leaves_the_rest()
    {
        let mut s = service();
        for i in 0..=iommu_labels::MAX_FAULTS_PER_REPLY as u64
        {
            s.backend.pending.push(Fault {
                unit: 0,
                bdf: 1,
                reason: 1,
                iova: i << 12,
            });
        }
        let take = req(iommu_labels::TAKE_FAULTS, &[], &[]);
        let first = s.handle(&take);
        assert_eq!(first.word(0), iommu_labels::MAX_FAULTS_PER_REPLY as u64);
        assert_eq!(s.handle(&take).words()[..1], [1]);
    }

    fn map_reserved(s: &mut Service<Fake, FakeCaps>, d: u64, base: u64, len: u64) -> u64
    {
        s.handle(&req(iommu_labels::MAP_RESERVED, &[d, base, len], &[]))
            .label
    }

    #[test]
    fn a_reserved_range_is_installed_read_write_at_its_own_address_with_no_cap()
    {
        let mut s = service();
        let d = domain(&mut s);
        assert_eq!(
            map_reserved(&mut s, d, 0x7c00_0000, 3 * PAGE_SIZE),
            iommu_errors::SUCCESS
        );
        assert_eq!(
            s.domains[0].domain.ranges,
            [(0x7c00_0000, 0x7c00_0000, 3 * PAGE_SIZE, Access::ReadWrite)]
        );
        // A cap sent with it is not kept.
        let with_cap = req(
            iommu_labels::MAP_RESERVED,
            &[d, 0x7d00_0000, PAGE_SIZE],
            &[6],
        );
        assert_eq!(s.handle(&with_cap).label, iommu_errors::SUCCESS);
        assert_eq!(deleted(&s), [6]);
    }

    #[test]
    fn a_misused_reserved_range_is_refused_before_the_backend()
    {
        let mut s = service();
        let d = domain(&mut s);
        let width_end = 1u64 << 39;
        for (domain, base, len) in [
            (d + 1, 0x7c00_0000, PAGE_SIZE),    // no such domain
            (d, 0x7c00_0800, PAGE_SIZE),        // unaligned base
            (d, 0x7c00_0000, PAGE_SIZE + 1),    // unaligned length
            (d, 0x7c00_0000, 0),                // empty
            (d, width_end - PAGE_SIZE, 0x2000), // past the unit's width
            (d, u64::MAX - 0xfff, PAGE_SIZE),   // wraps
        ]
        {
            assert_eq!(
                map_reserved(&mut s, domain, base, len),
                iommu_errors::INVALID_REQUEST
            );
        }
        assert_eq!(
            s.domains[0].domain.ranges,
            [] as [(u64, u64, u64, Access); 0]
        );
    }

    #[test]
    fn a_reserved_range_and_a_mapping_may_not_overlap()
    {
        let mut s = service();
        let d = domain(&mut s);
        assert_eq!(map(&mut s, d, 0x10_0000, RW, 3), iommu_errors::SUCCESS);
        assert_eq!(
            map_reserved(&mut s, d, 0x10_1000, PAGE_SIZE),
            iommu_errors::ADDRESS_IN_USE
        );
        assert_eq!(
            map_reserved(&mut s, d, 0x20_0000, PAGE_SIZE),
            iommu_errors::SUCCESS
        );
        assert_eq!(
            map(&mut s, d, 0x1f_f000, RW, 4),
            iommu_errors::ADDRESS_IN_USE
        );
        assert_eq!(deleted(&s), [4]);
    }

    #[test]
    fn a_reserved_range_is_not_unmapped_and_goes_with_the_domains_block()
    {
        let mut s = service();
        let d = domain(&mut s);
        assert_eq!(map_reserved(&mut s, d, 0x7c00_0000, PAGE_SIZE), 0);
        assert_eq!(map(&mut s, d, 0x10_0000, RW, 3), iommu_errors::SUCCESS);
        let unmap = req(iommu_labels::UNMAP, &[d, 0x7c00_0000], &[]);
        assert_eq!(s.handle(&unmap).label, iommu_errors::INVALID_REQUEST);
        assert_eq!(s.domains[0].domain.ranges.len(), 2);
        let block = req(iommu_labels::BLOCK, &[d], &[]);
        assert_eq!(s.handle(&block).label, iommu_errors::SUCCESS);
        // Only the mapped cap is deleted: the reserved range carried none.
        assert_eq!(deleted(&s), [3]);
    }

    fn map_msi(s: &mut Service<Fake, FakeCaps>, d: u64, file: u64) -> u64
    {
        s.handle(&req(iommu_labels::MAP_MSI, &[d, file], &[])).label
    }

    /// The supervisor-level IMSIC file of hart 3 on QEMU `virt`.
    const FILE: u64 = 0x2800_3000;

    #[test]
    fn an_interrupt_file_is_installed_at_its_own_address_with_no_cap()
    {
        let mut s = service();
        let d = domain(&mut s);
        assert_eq!(map_msi(&mut s, d, FILE), iommu_errors::SUCCESS);
        assert_eq!(s.domains[0].domain.files, [FILE]);
        assert_eq!(
            s.domains[0].domain.ranges,
            [] as [(u64, u64, u64, Access); 0]
        );
        let r = &s.domains[0].ranges[0];
        assert_eq!((r.iova, r.len, r.kind), (FILE, PAGE_SIZE, Kind::MsiFile));
        // A cap sent with it is not kept.
        let with_cap = req(iommu_labels::MAP_MSI, &[d, FILE + PAGE_SIZE], &[6]);
        assert_eq!(s.handle(&with_cap).label, iommu_errors::SUCCESS);
        assert_eq!(deleted(&s), [6]);
    }

    #[test]
    fn a_misused_interrupt_file_is_refused_before_the_backend()
    {
        let mut s = service();
        let d = domain(&mut s);
        let width_end = 1u64 << 39;
        for (domain, file) in [
            (d + 1, FILE),  // no such domain
            (d, FILE + 4),  // unaligned
            (d, width_end), // past the unit's width
            (d, !0xfff),    // wraps
        ]
        {
            assert_eq!(map_msi(&mut s, domain, file), iommu_errors::INVALID_REQUEST);
        }
        assert_eq!(s.domains[0].domain.files, [] as [u64; 0]);
        assert!(s.domains[0].ranges.is_empty());
    }

    #[test]
    fn an_interrupt_file_and_a_range_may_not_overlap()
    {
        let mut s = service();
        let d = domain(&mut s);
        assert_eq!(
            map(&mut s, d, FILE - PAGE_SIZE, RW, 3),
            iommu_errors::SUCCESS
        );
        assert_eq!(map_msi(&mut s, d, FILE), iommu_errors::ADDRESS_IN_USE);
        assert_eq!(map_msi(&mut s, d, FILE + PAGE_SIZE), iommu_errors::SUCCESS);
        assert_eq!(
            map_msi(&mut s, d, FILE + PAGE_SIZE),
            iommu_errors::ADDRESS_IN_USE
        );
        assert_eq!(
            map_reserved(&mut s, d, FILE + PAGE_SIZE, PAGE_SIZE),
            iommu_errors::ADDRESS_IN_USE
        );
        assert_eq!(s.domains[0].domain.files, [FILE + PAGE_SIZE]);
    }

    #[test]
    fn an_interrupt_file_is_not_unmapped_and_goes_with_the_domains_block()
    {
        let mut s = service();
        let d = domain(&mut s);
        assert_eq!(map_msi(&mut s, d, FILE), iommu_errors::SUCCESS);
        assert_eq!(map(&mut s, d, 0x10_0000, RW, 3), iommu_errors::SUCCESS);
        let unmap = req(iommu_labels::UNMAP, &[d, FILE], &[]);
        assert_eq!(s.handle(&unmap).label, iommu_errors::INVALID_REQUEST);
        assert_eq!(s.domains[0].domain.files, [FILE]);
        let block = req(iommu_labels::BLOCK, &[d], &[]);
        assert_eq!(s.handle(&block).label, iommu_errors::SUCCESS);
        assert_eq!(s.backend.blocked, [1]);
        // Only the mapped cap is deleted: the file carried none.
        assert_eq!(deleted(&s), [3]);
        assert_eq!(map_msi(&mut s, d, FILE), iommu_errors::INVALID_REQUEST);
    }

    #[test]
    fn a_family_that_does_not_take_interrupt_files_refuses_them_and_records_none()
    {
        let mut s = service();
        let d = domain(&mut s);
        s.backend.refuse_msi = true;
        assert_eq!(map_msi(&mut s, d, FILE), iommu_errors::INVALID_REQUEST);
        assert!(s.domains[0].ranges.is_empty());
        // The unit is not failed: the refusal is not a timeout.
        assert_eq!(map(&mut s, d, FILE, RW, 3), iommu_errors::SUCCESS);
    }

    #[test]
    fn a_unit_that_times_out_on_an_interrupt_file_refuses_every_later_request()
    {
        let mut s = service();
        let d = domain(&mut s);
        s.backend.fail_next = Some(BackendError::Timeout);
        assert_eq!(map_msi(&mut s, d, FILE), iommu_errors::HARDWARE_TIMEOUT);
        assert!(s.domains[0].ranges.is_empty());
        assert_eq!(map_msi(&mut s, d, FILE), iommu_errors::HARDWARE_TIMEOUT);
    }

    #[test]
    fn interrupt_files_have_a_bound_of_their_own_beside_the_ranges()
    {
        let mut s = service();
        let d = domain(&mut s);
        for i in 0..MAX_MSI_FILES_PER_DOMAIN as u64
        {
            assert_eq!(map_msi(&mut s, d, FILE + i * PAGE_SIZE), 0);
        }
        let next = FILE + MAX_MSI_FILES_PER_DOMAIN as u64 * PAGE_SIZE;
        assert_eq!(map_msi(&mut s, d, next), iommu_errors::OUT_OF_RESOURCES);
        // The files take nothing from the ranges' bound.
        for i in 0..MAX_RANGES_PER_DOMAIN as u64
        {
            assert_eq!(map(&mut s, d, 0x10_0000 + i * 0x2000, RW, 3), 0);
        }
        let next = 0x10_0000 + MAX_RANGES_PER_DOMAIN as u64 * 0x2000;
        assert_eq!(map(&mut s, d, next, RW, 3), iommu_errors::OUT_OF_RESOURCES);
    }

    fn remap_setup(s: &mut Service<Fake, FakeCaps>, entries: u64, extended: u64) -> IpcMessage
    {
        s.handle(&req(iommu_labels::REMAP_SETUP, &[entries, extended], &[]))
    }

    fn remap_set(s: &mut Service<Fake, FakeCaps>, fields: [u64; 5]) -> u64
    {
        s.handle(&req(iommu_labels::REMAP_SET, &fields, &[])).label
    }

    /// Entry 7 delivering vector 0x41 to CPU 3, edge-triggered, from the
    /// requester 00:1f.0.
    const SET: [u64; 5] = [7, 3, 0x41, 0, 0x00f8];

    #[test]
    fn remapping_is_set_up_once_and_reports_the_destination_width()
    {
        let mut s = service();
        let r = remap_setup(&mut s, 1024, 1);
        assert_eq!((r.label, r.word(0)), (iommu_errors::SUCCESS, 0));
        assert_eq!(s.backend.remapping, Some(1024));
        assert_eq!(
            remap_setup(&mut s, 1024, 1).label,
            iommu_errors::INVALID_REQUEST
        );
        // Turned off, it may be set up again.
        assert_eq!(remap_setup(&mut s, 0, 0).label, iommu_errors::SUCCESS);
        assert_eq!(s.backend.remapping, None);
        s.backend.offers_extended = true;
        let r = remap_setup(&mut s, 2, 1);
        assert_eq!((r.label, r.word(0)), (iommu_errors::SUCCESS, 1));
    }

    #[test]
    fn a_table_size_outside_the_bound_is_refused_before_the_backend()
    {
        let mut s = service();
        for (entries, extended) in [
            (1, 0),
            (1000, 0),
            (iommu_labels::MAX_REMAP_ENTRIES * 2, 0),
            (1 << 40, 0),
            (1024, 2),
        ]
        {
            assert_eq!(
                remap_setup(&mut s, entries, extended).label,
                iommu_errors::INVALID_REQUEST
            );
        }
        assert_eq!(s.backend.remapping, None);
        let r = remap_setup(&mut s, iommu_labels::MAX_REMAP_ENTRIES, 0);
        assert_eq!(r.label, iommu_errors::SUCCESS);
    }

    /// Defect caught: one shared table, whose entries name a requester with
    /// no segment, was set up for units on two segments.
    #[test]
    fn units_on_two_segments_refuse_the_setup()
    {
        let units = Units(vec![
            UnitScope {
                segment: 0,
                include_pci_all: true,
                scopes: vec![],
            },
            UnitScope {
                segment: 1,
                include_pci_all: true,
                scopes: vec![],
            },
        ]);
        let mut s = Service::new(Fake::default(), FakeCaps::default(), units).unwrap();
        assert_eq!(
            remap_setup(&mut s, 1024, 0).label,
            iommu_errors::INVALID_REQUEST
        );
        assert_eq!(s.backend.remapping, None);
    }

    #[test]
    fn a_family_that_does_not_remap_interrupts_refuses_the_setup()
    {
        let mut s = service();
        s.backend.no_remap = true;
        assert_eq!(
            remap_setup(&mut s, 1024, 0).label,
            iommu_errors::INVALID_REQUEST
        );
        assert_eq!(remap_set(&mut s, SET), iommu_errors::INVALID_REQUEST);
    }

    #[test]
    fn an_entry_is_set_and_cleared_within_the_table()
    {
        let mut s = service();
        assert_eq!(remap_set(&mut s, SET), iommu_errors::INVALID_REQUEST);
        remap_setup(&mut s, 1024, 0);
        assert_eq!(remap_set(&mut s, SET), iommu_errors::SUCCESS);
        let level = [1023, 0xff, 0xff, 1, 0xffff];
        assert_eq!(remap_set(&mut s, level), iommu_errors::SUCCESS);
        assert_eq!(
            s.backend.set,
            [
                (
                    7,
                    RemapEntry {
                        destination: 3,
                        vector: 0x41,
                        level: false,
                        source_id: 0xf8,
                    }
                ),
                (
                    1023,
                    RemapEntry {
                        destination: 0xff,
                        vector: 0xff,
                        level: true,
                        source_id: 0xffff,
                    }
                ),
            ]
        );
        let clear = req(iommu_labels::REMAP_CLEAR, &[7], &[]);
        assert_eq!(s.handle(&clear).label, iommu_errors::SUCCESS);
        let past = req(iommu_labels::REMAP_CLEAR, &[1024], &[]);
        assert_eq!(s.handle(&past).label, iommu_errors::INVALID_REQUEST);
        assert_eq!(s.backend.cleared, [7]);
    }

    #[test]
    fn an_entry_outside_its_fields_bounds_is_refused_before_the_backend()
    {
        let mut s = service();
        remap_setup(&mut s, 1024, 0);
        for fields in [
            [1024, 3, 0x41, 0, 0xf8],  // past the table
            [7, 0x100, 0x41, 0, 0xf8], // wider than 8-bit destinations
            [7, 3, 15, 0, 0xf8],       // an exception vector
            [7, 3, 0x100, 0, 0xf8],    // not a vector
            [7, 3, 0x41, 2, 0xf8],     // neither edge nor level
            [7, 3, 0x41, 0, 0x1_0000], // not a source ID
        ]
        {
            assert_eq!(remap_set(&mut s, fields), iommu_errors::INVALID_REQUEST);
        }
        assert_eq!(s.backend.set, [] as [(u16, RemapEntry); 0]);
    }

    #[test]
    fn extended_destinations_take_a_32_bit_id()
    {
        let mut s = service();
        s.backend.offers_extended = true;
        remap_setup(&mut s, 1024, 1);
        assert_eq!(
            remap_set(&mut s, [7, 0x1_0000, 0x41, 0, 0xf8]),
            iommu_errors::SUCCESS
        );
        assert_eq!(
            remap_set(&mut s, [7, 1 << 32, 0x41, 0, 0xf8]),
            iommu_errors::INVALID_REQUEST
        );
    }

    #[test]
    fn a_remapping_timeout_refuses_every_later_remapping_request()
    {
        let mut s = service();
        remap_setup(&mut s, 1024, 0);
        s.backend.fail_next = Some(BackendError::Timeout);
        assert_eq!(remap_set(&mut s, SET), iommu_errors::HARDWARE_TIMEOUT);
        assert_eq!(remap_set(&mut s, SET), iommu_errors::HARDWARE_TIMEOUT);
        let clear = req(iommu_labels::REMAP_CLEAR, &[7], &[]);
        assert_eq!(s.handle(&clear).label, iommu_errors::HARDWARE_TIMEOUT);
        // Translation requests are unaffected.
        assert_eq!(attach(&mut s, 0, 0x0018).label, iommu_errors::SUCCESS);
    }

    #[test]
    fn an_unknown_label_is_refused_and_its_caps_deleted()
    {
        let mut s = service();
        assert_eq!(
            s.handle(&req(99, &[], &[7, 8])).label,
            iommu_errors::UNKNOWN_OPCODE
        );
        assert_eq!(deleted(&s), [7, 8]);
    }
}
