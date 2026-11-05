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
//! unit whose backend reports a timeout is treated as failed: every later
//! request on it is refused with `HARDWARE_TIMEOUT`.
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
use crate::{Backend, BackendError};

/// Domains one driver holds at once, over all its units: one per PCI
/// function devmgr attaches, which it does once per function per boot.
/// `docs/limits.md` classifies the bound.
pub const MAX_DOMAINS: usize = 256;
/// Ranges one domain holds at once. devmgr bounds a device's mappings below
/// it (`devmgr_firmware::dma::MAX_MAPPINGS_PER_DEVICE`); the driver's own
/// bound keeps a caller that does not from growing its record without end.
pub const MAX_RANGES_PER_DOMAIN: usize = 64;
/// How often, in milliseconds, [`poll_faults`] reads the units' fault
/// records. A tuning value that bounds no capacity: a unit that records
/// faults faster than this drains them overflows its few records, and the
/// unit then drops faults until the next poll.
pub const FAULT_POLL_MS: u64 = 100;

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
pub struct KernelCaps;

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
            phys: syscall::cap_info(cap, syscall::CAP_INFO_MEMORY_PHYS_BASE).ok()?,
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

/// One installed range of a domain, and the cap over its frames the driver
/// keeps while it stands.
struct Range
{
    iova: u64,
    len: u64,
    cap: u64,
}

impl Range
{
    fn overlaps(&self, iova: u64, len: u64) -> bool
    {
        self.iova < iova + len && iova < self.iova + self.len
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

/// The driver's state: its backend, its units' scopes, every attached
/// domain, and the faults polled and not yet taken.
pub struct Service<B: Backend, C: CapOps>
{
    backend: B,
    caps: C,
    units: Units,
    failed: Vec<bool>,
    domains: Vec<DomainRecord<B::Domain>>,
    next_handle: u64,
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
            _ => iommu_errors::UNKNOWN_OPCODE,
        };
        IpcMessage::new(code)
    }

    /// The `iommu_errors` code for a backend failure on `unit`, marking the
    /// unit failed on a timeout.
    fn backend_failure(&mut self, unit: usize, e: BackendError) -> u64
    {
        if e == BackendError::Timeout
        {
            self.failed[unit] = true;
        }
        backend_code(e)
    }

    fn unit_ok(&self, unit: usize) -> Result<(), u64>
    {
        if self.failed[unit]
        {
            Err(iommu_errors::HARDWARE_TIMEOUT)
        }
        else
        {
            Ok(())
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
        self.domains.try_reserve(1).map_err(|_| exhausted)?;
        let domain = self
            .backend
            .attach(unit, bdf, did)
            .map_err(|e| self.backend_failure(unit, e))?;
        let handle = self.next_handle;
        self.next_handle += 1;
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
        let write = access & ACCESS_DEVICE_WRITE != 0;
        let mem = self.caps.memory(cap).ok_or(invalid)?;
        let needed = if write
        {
            RIGHTS_MEM_MAP | RIGHTS_MEM_WRITE
        }
        else
        {
            RIGHTS_MEM_MAP
        };
        let unit = self.domains[index].unit;
        let width = self.backend.query(unit).width_bits;
        let end = iova.checked_add(mem.len).ok_or(invalid)?;
        if mem.rights & needed != needed
            || mem.len == 0
            || (iova | mem.len | mem.phys) & (PAGE_SIZE - 1) != 0
            || u32::from(width) < 64 && end > 1u64 << width
        {
            return Err(invalid);
        }
        let record = &self.domains[index];
        if record.ranges.iter().any(|r| r.overlaps(iova, mem.len))
        {
            return Err(iommu_errors::ADDRESS_IN_USE);
        }
        if record.ranges.len() >= MAX_RANGES_PER_DOMAIN
        {
            return Err(iommu_errors::OUT_OF_RESOURCES);
        }
        self.unit_ok(unit)?;
        self.domains[index]
            .ranges
            .try_reserve(1)
            .map_err(|_| iommu_errors::OUT_OF_RESOURCES)?;
        let mapped = self.backend.map(
            &mut self.domains[index].domain,
            iova,
            mem.phys,
            mem.len,
            write,
        );
        mapped.map_err(|e| self.backend_failure(unit, e))?;
        self.domains[index].ranges.push(Range {
            iova,
            len: mem.len,
            cap,
        });
        Ok(())
    }

    fn unmap(&mut self, handle: u64, iova: u64) -> u64
    {
        let index = match self.domain_index(handle)
        {
            Ok(i) => i,
            Err(code) => return code,
        };
        let unit = self.domains[index].unit;
        let Some(at) = self.domains[index]
            .ranges
            .iter()
            .position(|r| r.iova == iova)
        else
        {
            return iommu_errors::NO_MAPPING;
        };
        if let Err(code) = self.unit_ok(unit)
        {
            return code;
        }
        let len = self.domains[index].ranges[at].len;
        if let Err(e) = self
            .backend
            .unmap(&mut self.domains[index].domain, iova, len)
        {
            return self.backend_failure(unit, e);
        }
        let range = self.domains[index].ranges.swap_remove(at);
        self.caps.delete(range.cap);
        iommu_errors::SUCCESS
    }

    fn block(&mut self, handle: u64) -> u64
    {
        let index = match self.domain_index(handle)
        {
            Ok(i) => i,
            Err(code) => return code,
        };
        let unit = self.domains[index].unit;
        if let Err(code) = self.unit_ok(unit)
        {
            return code;
        }
        if let Err(e) = self.backend.block(&mut self.domains[index].domain)
        {
            return self.backend_failure(unit, e);
        }
        let record = self.domains.swap_remove(index);
        for r in record.ranges
        {
            self.caps.delete(r.cap);
        }
        iommu_errors::SUCCESS
    }

    fn query(&self, unit_word: u64) -> Option<u8>
    {
        let unit = usize::try_from(unit_word).ok()?;
        (unit < self.units.0.len()).then(|| self.backend.query(unit).width_bits)
    }

    /// Poll the units, so the reply holds every fault recorded so far, and
    /// take the oldest queued faults into the reply.
    fn take_faults(&mut self) -> IpcMessage
    {
        self.poll();
        let mut words = [0u64; 1 + 2 * iommu_labels::MAX_FAULTS_PER_REPLY];
        let mut n = 0usize;
        let units = &self.units;
        self.faults
            .take(iommu_labels::MAX_FAULTS_PER_REPLY, |f: Fault| {
                let segment = units.0.get(f.unit).map_or(0, |u| u.segment);
                let [bus, devfn] = f.bdf.to_be_bytes();
                let rid = iommu_labels::requester_id(segment, bus, devfn >> 3, devfn & 7);
                words[1 + 2 * n] = rid | (u64::from(f.reason) << 32);
                words[2 + 2 * n] = f.iova;
                n += 1;
            });
        words[0] = n as u64;
        IpcMessage::builder(iommu_errors::SUCCESS)
            .words(0, &words[..=2 * n])
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
        attached: Vec<(usize, u16, u32)>,
        blocked: Vec<u32>,
        pending: Vec<Fault>,
    }

    struct FakeDomain
    {
        did: u32,
        ranges: Vec<(u64, u64, u64, bool)>,
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
            })
        }

        fn map(
            &mut self,
            d: &mut FakeDomain,
            iova: u64,
            phys: u64,
            len: u64,
            write: bool,
        ) -> Result<(), BackendError>
        {
            self.fail()?;
            d.ranges.push((iova, phys, len, write));
            Ok(())
        }

        fn unmap(&mut self, d: &mut FakeDomain, iova: u64, _len: u64) -> Result<(), BackendError>
        {
            self.fail()?;
            d.ranges.retain(|r| r.0 != iova);
            Ok(())
        }

        fn block(&mut self, d: &mut FakeDomain) -> Result<(), BackendError>
        {
            self.fail()?;
            self.blocked.push(d.did);
            d.ranges.clear();
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
            (cap != 13).then(|| MemoryCap {
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
        assert!(s.backend.enabled.is_empty());
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
    fn a_mapping_is_installed_with_the_caps_frames_and_kept_until_its_unmap()
    {
        let mut s = service();
        let d = domain(&mut s);
        assert_eq!(map(&mut s, d, 0x10_0000, RW, 3), iommu_errors::SUCCESS);
        assert_eq!(
            s.domains[0].domain.ranges,
            [(0x10_0000, 3 << 20, 2 * PAGE_SIZE, true)]
        );
        assert!(deleted(&s).is_empty());
        let unmap = req(iommu_labels::UNMAP, &[d, 0x10_0000], &[]);
        assert_eq!(s.handle(&unmap).label, iommu_errors::SUCCESS);
        assert!(s.domains[0].domain.ranges.is_empty());
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
        assert!(s.domains[0].domain.ranges.is_empty());
        assert_eq!(deleted(&s), [3, 3, 3, 3, 3, 9, 13]);
        assert_eq!(map(&mut s, d, 0x10_0000, ACCESS_DEVICE_READ, 9), 0);
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
        assert!(deleted(&s).is_empty());
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
