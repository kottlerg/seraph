// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/devmgr/src/iommu.rs

//! devmgr's side of the IOMMU: discovering the remapping units, spawning the
//! IOMMU driver that programs them, deciding each DMA-capable device's
//! confinement, calling the driver over `ipc::iommu_labels`, and restarting
//! it when it dies.
//!
//! At boot, before the boot batch, [`bring_up`] reads the firmware table of
//! the architecture's IOMMU family (`arch::current::IOMMU_FAMILY`): on
//! x86-64 the ACPI DMAR, whose VT-d units' register `Mmio` caps it carves
//! from the apertures; on riscv64 the ACPI RIMT, whose RISC-V IOMMUs are PCI
//! functions, each unit's register cap being its BAR 0, carved before devmgr
//! turns on the function's memory decode and bus mastering, the last step of
//! the unit's hand-over, so a unit not handed over is left as the firmware
//! left it and one turned on is always handed over. For each unit it also
//! allocates the unit's anchor ([`kept_pages`]), the page the unit's root
//! structure lives in, which devmgr keeps for the boot. It spawns, in a
//! settle batch of its own, the boot-module driver whose declaration matches
//! the family's record key ([`Family::key`]: `dmar` binds `iommu-vtd`,
//! `rimt` binds `iommu-riscv`), and delivers it every unit in its resource
//! list (`driver_binding::resources`: each unit's segment, scope and anchor,
//! then its register range). devmgr keeps its register caps, its anchors and
//! a copy of the driver's image ([`copy_image`]) for a restart. Once the
//! driver reports ready every function a unit translates is blocked until
//! devmgr attaches it, so [`Iommu::confine`] attaches each DMA-capable device
//! before its DMA grant and maps, at their own addresses, the regions the
//! firmware reserves for it (each DMAR RMRR that names it; the RIMT describes
//! none). It refuses a device whose reserved regions overlap memory memmgr
//! pools, pass its unit's width, or number past
//! `MAX_RESERVED_RANGES_PER_DEVICE`, one the RIMT gives a device ID other
//! than its requester ID, one whose unit it could not hand over, and one
//! whose `ATTACH` or reserved mapping fails. When no unit is found, no driver
//! module was delivered, or the driver does not report ready within the
//! settle bound, devmgr logs once that DMA runs unconfined and every device
//! runs so; a driver that fails its own setup turns translation off again
//! first, but one that dies or hangs before its ready report after it turned
//! a unit's translation on leaves that unit blocking the devices behind it,
//! and devmgr logs as such.
//!
//! On riscv64 a confined device's message-signaled interrupts are writes its
//! domain translates, so before devmgr enables them it has the driver map the
//! page of each interrupt file they target in the device's domain
//! (`MAP_MSI`, `crate::dma::DmaGrant::reach_interrupt_file`). VT-d does
//! not translate them: its interrupt remapping governs them, which devmgr
//! turns on and programs through the same driver ([`crate::intremap`];
//! `docs/device-management.md` § Interrupt Delivery).
//!
//! The [`IommuClient`] is shared by devmgr's control thread (`ATTACH`,
//! `MAP_MSI`, `BLOCK`, `REMAP_SETUP`, `REMAP_SET`, `REMAP_CLEAR`), its
//! DMA thread (`MAP`, `UNMAP`), and its fault-log thread (`TAKE_FAULTS`),
//! each call made with no devmgr lock held. It records each domain's handle
//! and domain ID and, on VT-d, the remapping table and entries
//! (`firmware::iommu_restart`). When the driver dies after it reported
//! ready, the hardware goes on translating through the dead instance's
//! tables, so devmgr cannot fall back to unconfined DMA. A death watch thread
//! per instance sees the death at once, independent of the control thread,
//! which may itself be blocked in a call to the dead instance: it marks the
//! client restarting, so the DMA thread's calls wait for the restart, and
//! answers every call queued on the dead instance's endpoint with an error.
//! The control thread then restarts the driver ([`Iommu::restart`]): a new
//! instance adopts the units translating from their anchors, devmgr replays
//! its records into it, and the instance commits its tables into the anchors,
//! after which devmgr releases every dead instance's DMA hold. A death by
//! the driver's own exit, a spent restart budget or a failed restart fails
//! the client closed ([`IommuClient::fail`]): every later call fails at once,
//! and devmgr withdraws every confined device's driver. See
//! `docs/device-management.md` § IOMMU Discovery and Programming and
//! § IOMMU Driver Restart.

use std::os::seraph::thread::BuilderExt;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::Duration;

use driver_binding::decl::DriverDecl;
use driver_binding::resources::{
    IommuUnit, MAX_IOMMU_UNITS, MAX_UNIT_REGISTER_PAGES, MAX_UNIT_SCOPES, Resource, Scope,
};
use firmware::binding::{Choice, MatchTable, RecordKeys, Source};
use firmware::dma::{
    Confinement, DeviceReplay, ReservedError, ReservedRange, has_iova_space, iova_limit,
    reserved_ranges,
};
use firmware::dmar::{self, Bdf, Resolved};
use firmware::iommu_restart::{
    self, Domain, Domains, Holds, Refusal, RemapEntry, RemapTable, Remaps,
};
use firmware::rimt;
use ipc::{IpcMessage, iommu_errors, iommu_labels, memmgr_errors, memmgr_labels};
use restart_budget::RestartBudget;
use syscall_abi::{PAGE_SIZE, SyscallError};

use crate::decls::Binary;
use crate::spawn::HeldChild;
use crate::{DeviceCatalog, Registry, ServedDriver, Serves, SpawnedDriver};
use crate::{arch, caps, pci, settle, spawn};

/// The IOMMU family an architecture's platforms carry, which decides the
/// firmware table devmgr discovers the units in and the driver module it
/// spawns over them (`arch::current::IOMMU_FAMILY`).
#[cfg_attr(
    target_arch = "riscv64",
    expect(
        dead_code,
        reason = "the riscv64 build never constructs `Vtd`, its family being `Riscv` \
                  (`arch::current::IOMMU_FAMILY`); the variant stays, since devmgr's discovery \
                  handles each family on either build"
    )
)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family
{
    /// Intel VT-d, described by the ACPI DMAR (`iommu-vtd`).
    Vtd,
    /// The RISC-V IOMMU as a PCI function, described by the ACPI RIMT
    /// (`iommu-riscv`).
    Riscv,
}

impl Family
{
    /// The units' name in devmgr's log lines.
    fn units(self) -> &'static str
    {
        match self
        {
            Self::Vtd => "VT-d units",
            Self::Riscv => "RISC-V IOMMUs",
        }
    }

    /// What the address word `address` of a fault of reason `reason` the
    /// family's driver recorded names: a VT-d interrupt-remapping fault names
    /// a remapping table handle (`dmar::fault_site`), every other fault an
    /// IOVA.
    fn fault_site(self, reason: u16, address: u64) -> dmar::FaultSite
    {
        match self
        {
            Self::Vtd => dmar::fault_site(reason, address),
            Self::Riscv => dmar::FaultSite::Iova(address),
        }
    }

    /// The family's IOMMU family key, which its record carries and its
    /// driver's declaration names (docs/driver-binding.md § Device Records).
    fn key(self) -> &'static [u8]
    {
        match self
        {
            Self::Vtd => b"dmar",
            Self::Riscv => b"rimt",
        }
    }
}

/// How often, in milliseconds, devmgr's fault-log thread takes the IOMMU
/// driver's recorded faults and logs them. A tuning value that bounds no
/// capacity: the driver queues faults between takes (its own bound,
/// `iommu_core::faults::FAULT_QUEUE_CAPACITY`, decides what overflows).
const FAULT_LOG_MS: u64 = 1000;

/// The bus, device, and function of a PCI function in the IOMMU driver's
/// encoding (bus in bits 8..16, device in bits 3..8, function below).
fn bdf_word(bus: u8, device: u8, function: u8) -> u16
{
    u16::from_be_bytes([bus, ((device & 0x1f) << 3) | (function & 7)])
}

/// How long a DMA-thread call waits for a restart of the IOMMU driver to
/// end: the control thread may first finish a settle batch it is in, then
/// settles the restarted instance, then replays devmgr's records into it,
/// each within the settle bound. A call still waiting then fails as it
/// would against a failed driver.
const RESTART_WAIT: Duration = settle::SETTLE_TIMEOUT.saturating_mul(3);

/// The calls a DMA-thread request makes at most ([`crate::dma`]): each
/// repeat follows the death of the instance the previous one reached, and
/// devmgr restarts the driver at most [`restart_budget::RESTART_BURST`]
/// times in a window.
pub const CALL_ATTEMPTS: u32 = restart_budget::RESTART_BURST + 1;

/// Where the IOMMU driver devmgr calls stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase
{
    /// Spawned at boot, not yet reported ready.
    Starting,
    /// Serving: devmgr calls it.
    Ready,
    /// The serving instance died and devmgr is restarting the driver: the
    /// units go on translating through the dead instance's tables.
    Restarting,
    /// Not served: every call is refused from now on.
    Failed,
}

/// The instance devmgr calls: its endpoint, its device badge, and where it
/// stands.
struct Link
{
    /// The instance's service endpoint, which devmgr created; the driver
    /// receives on a copy. A dead instance's is deleted once a later one
    /// has committed ([`Instance::release`]).
    ep: u64,
    /// The instance's device badge, which its death posts carry; 0 until the
    /// boot instance reports ready.
    badge: u64,
    phase: Phase,
}

/// The IOMMU driver as devmgr calls it: the instance it calls, the units'
/// translation widths, and the records a restart rebuilds the driver's state
/// from (`docs/device-management.md` § IOMMU Driver Restart).
///
/// Every lock is a leaf: none is held while another of the client's is
/// taken, or across an IPC. The DMA thread takes the link's inside the DMA
/// table's ([`Self::serves`]).
pub struct IommuClient
{
    link: Mutex<Link>,
    /// Signalled whenever the link's phase leaves [`Phase::Restarting`].
    phase_changed: Condvar,
    /// Each unit's IOVA width (`QUERY_UNIT`), by unit index; set once the
    /// boot instance is ready. A restarted instance must report the same.
    widths: OnceLock<Vec<u8>>,
    /// Every domain the driver holds, by handle.
    domains: Mutex<Domains>,
    /// The interrupt remapping table and the entries written to it.
    remaps: Mutex<Remaps>,
}

impl IommuClient
{
    /// A client of the boot instance, whose endpoint is `ep`, starting.
    fn new(ep: u64) -> Self
    {
        Self {
            link: Mutex::new(Link {
                ep,
                badge: 0,
                phase: Phase::Starting,
            }),
            phase_changed: Condvar::new(),
            widths: OnceLock::new(),
            domains: Mutex::new(Domains::new()),
            remaps: Mutex::new(Remaps::new()),
        }
    }

    fn link(&self) -> MutexGuard<'_, Link>
    {
        self.link.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn domains(&self) -> MutexGuard<'_, Domains>
    {
        self.domains.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn remaps(&self) -> MutexGuard<'_, Remaps>
    {
        self.remaps.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Whether the driver has failed: every call is refused from then on.
    pub fn failed(&self) -> bool
    {
        self.link().phase == Phase::Failed
    }

    /// Record that the boot instance, of device badge `badge`, reported
    /// ready; `false` when it has died meanwhile, the driver then failed.
    fn mark_ready(&self, badge: u64) -> bool
    {
        let mut link = self.link();
        if link.phase != Phase::Starting
        {
            return false;
        }
        link.phase = Phase::Ready;
        link.badge = badge;
        true
    }

    /// The endpoint of the instance serving now; `None` while none is.
    fn serving(&self) -> Option<u64>
    {
        let link = self.link();
        (link.phase == Phase::Ready).then_some(link.ep)
    }

    /// The endpoint of the instance serving, waiting up to [`RESTART_WAIT`]
    /// while a restart runs; `None` when none serves by then.
    pub fn await_serving(&self) -> Option<u64>
    {
        let deadline = std::time::Instant::now().checked_add(RESTART_WAIT);
        let mut link = self.link();
        while link.phase == Phase::Restarting
        {
            let left = deadline?.saturating_duration_since(std::time::Instant::now());
            if left.is_zero()
            {
                return None;
            }
            link = self
                .phase_changed
                .wait_timeout(link, left)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
        (link.phase == Phase::Ready).then_some(link.ep)
    }

    /// Whether the instance whose endpoint is `ep` serves now. A DMA-thread
    /// call made on `ep` records its outcome in the DMA table only when it
    /// does, deciding under the table's lock: once a death has moved the
    /// link on, the restart's replay, which reads the table under the same
    /// lock, decides what the next instance holds, and the call is made
    /// again on it ([`crate::dma`]).
    pub fn serves(&self, ep: u64) -> bool
    {
        let link = self.link();
        link.ep == ep && link.phase == Phase::Ready
    }

    /// Call the driver with `msg` on the instance serving now. `Err` with
    /// the driver's error label, or `HARDWARE_TIMEOUT` when none serves or
    /// the call itself fails (the instance died with it in flight). For the
    /// control thread and the fault-log thread: a restart runs on the control
    /// thread, so a fault-log call made while it runs fails at once.
    fn call(&self, msg: &IpcMessage) -> Result<IpcMessage, u64>
    {
        let ep = self.serving().ok_or(iommu_errors::HARDWARE_TIMEOUT)?;
        call_on(ep, msg)
    }

    /// Attach the function `rid` (`iommu_labels::requester_id`) of unit
    /// `unit` to a domain of its own; its domain handle, recorded with its
    /// domain ID for a restart.
    ///
    /// # Errors
    /// The driver's error label, or `OUT_OF_RESOURCES` when the record
    /// cannot grow, the function then blocked again.
    pub fn attach(&self, unit: usize, rid: u64) -> Result<u64, u64>
    {
        let reply = self.call(&attach_msg(unit, rid, 0, 0))?;
        let domain = Domain {
            handle: reply.word(0),
            unit,
            rid,
            did: reply.word(1),
        };
        if self.domains().record(domain).is_err()
        {
            self.block(domain.handle);
            return Err(iommu_errors::OUT_OF_RESOURCES);
        }
        Ok(domain.handle)
    }

    /// Install a derivation of `source`, devmgr's Memory cap, at `iova` in
    /// the domain `handle` with `access` (`MAP`), on the instance whose
    /// endpoint is `ep`.
    ///
    /// # Errors
    /// The driver's error label, the derivation deleted;
    /// `OUT_OF_RESOURCES` when no derivation can be made; `HARDWARE_TIMEOUT`
    /// when the call fails.
    pub fn map_on(ep: u64, handle: u64, iova: u64, access: u64, source: u64) -> Result<(), u64>
    {
        let msg = map_msg(handle, iova, access, source).ok_or(iommu_errors::OUT_OF_RESOURCES)?;
        call_on(ep, &msg).map(|_| ())
    }

    /// Install the firmware-reserved range of `len` bytes at `base` in the
    /// domain `handle` at its own address (`MAP_RESERVED`).
    ///
    /// # Errors
    /// The driver's error label; nothing is installed.
    pub fn map_reserved(&self, handle: u64, base: u64, len: u64) -> Result<(), u64>
    {
        self.call(&map_reserved_msg(handle, base, len)).map(|_| ())
    }

    /// Install the page of the interrupt file at `file` in the domain
    /// `handle` at its own address (`MAP_MSI`), so the domain's function
    /// reaches that file with its message-signaled interrupts.
    ///
    /// # Errors
    /// The driver's error label (`INVALID_REQUEST` from a family whose
    /// messages its DMA translation does not carry); nothing is installed.
    pub fn map_msi(&self, handle: u64, file: u64) -> Result<(), u64>
    {
        self.call(&map_msi_msg(handle, file)).map(|_| ())
    }

    /// Remove the range at `iova` of the domain `handle` (`UNMAP`), on the
    /// instance whose endpoint is `ep`.
    ///
    /// # Errors
    /// The driver's error label, the range standing; `HARDWARE_TIMEOUT`
    /// when the call fails.
    pub fn unmap_on(ep: u64, handle: u64, iova: u64) -> Result<(), u64>
    {
        let msg = request(iommu_labels::UNMAP)
            .word(1, handle)
            .word(2, iova)
            .build();
        call_on(ep, &msg).map(|_| ())
    }

    /// Block the domain `handle`'s function at its device's withdrawal;
    /// whether the block is in place. A domain the ledger no longer holds was
    /// left out of a restarted instance's tables, its replay having failed,
    /// so its function is blocked already: a domain is recorded at its
    /// `ATTACH` and forgotten only at its block or at that failure.
    pub fn block_withdrawn(&self, handle: u64) -> bool
    {
        if self.domains().get(handle).is_none()
        {
            return true;
        }
        self.block(handle)
    }

    /// Block the domain `handle`'s function, forgetting the domain; whether
    /// the block is in place.
    pub fn block(&self, handle: u64) -> bool
    {
        self.domains().forget(handle);
        let msg = request(iommu_labels::BLOCK).word(1, handle).build();
        self.call(&msg).is_ok()
    }

    /// Set up the interrupt remapping table every unit shares, of `entries`
    /// entries in `table`, devmgr's Memory cap on its pages, asking for
    /// 32-bit destinations when `extended` is set (`REMAP_SETUP`); whether
    /// the destinations are 32-bit. On success devmgr keeps `table` for the
    /// boot, for a restart, which sets the table up again as this call left
    /// it.
    ///
    /// # Errors
    /// The driver's error label, or `OUT_OF_RESOURCES` when `table` cannot
    /// be derived; remapping stays off, and the caller keeps `table`.
    #[expect(
        clippy::fn_params_excessive_bools,
        reason = "`extended` is a word of the `REMAP_SETUP` message"
    )]
    pub fn remap_setup(&self, entries: u64, extended: bool, table: u64) -> Result<bool, u64>
    {
        let msg =
            remap_setup_msg(entries, extended, table).ok_or(iommu_errors::OUT_OF_RESOURCES)?;
        let granted = self.call(&msg)?.word(0) == 1;
        self.remaps().set_table(RemapTable {
            cap: table,
            entries,
            extended: granted,
        });
        Ok(granted)
    }

    /// Turn interrupt remapping off again (`REMAP_SETUP` of no entries),
    /// deleting the table's cap devmgr kept. The kernel refused to switch to
    /// the remappable formats, so no entry is in use.
    pub fn remap_off(&self)
    {
        let _ = self.call(&request(iommu_labels::REMAP_SETUP).build());
        let table = self.remaps().take_table();
        if let Some(cap) = table
        {
            let _ = syscall::cap_delete(cap);
        }
    }

    /// Make remapping entry `handle` deliver `vector` to the CPU whose
    /// interrupt controller ID is `apic_id`, level-triggered when `level` is
    /// set, for requests from `source` alone (`REMAP_SET`), recorded for a
    /// restart.
    ///
    /// # Errors
    /// The driver's error label, the entry as it was; `OUT_OF_RESOURCES`
    /// when the record cannot grow, the entry then cleared.
    #[expect(
        clippy::fn_params_excessive_bools,
        reason = "`level` is a word of the `REMAP_SET` message"
    )]
    pub fn remap_set(
        &self,
        handle: u16,
        apic_id: u32,
        vector: u8,
        level: bool,
        source: u16,
    ) -> Result<(), u64>
    {
        let entry = RemapEntry {
            handle,
            apic_id,
            vector,
            level,
            source,
        };
        self.call(&remap_set_msg(&entry))?;
        if self.remaps().set(entry).is_err()
        {
            let _ = self.remap_clear(handle);
            return Err(iommu_errors::OUT_OF_RESOURCES);
        }
        Ok(())
    }

    /// Make remapping entry `handle` not present (`REMAP_CLEAR`), forgetting
    /// it.
    ///
    /// # Errors
    /// The driver's error label.
    pub fn remap_clear(&self, handle: u16) -> Result<(), u64>
    {
        self.remaps().clear(handle);
        let msg = request(iommu_labels::REMAP_CLEAR)
            .word(1, u64::from(handle))
            .build();
        self.call(&msg).map(|_| ())
    }

    /// The IOVA width of unit `unit`; 0 when unknown.
    fn width(&self, unit: usize) -> u8
    {
        self.widths
            .get()
            .and_then(|w| w.get(unit))
            .copied()
            .unwrap_or(0)
    }

    /// Take the faults the driver recorded since the last take, passing each
    /// as (requester ID, reason, IOVA) to `each`; `false` when the driver
    /// refused or none serves.
    pub fn take_faults(&self, mut each: impl FnMut(u64, u16, u64)) -> bool
    {
        loop
        {
            let Ok(reply) = self.call(&request(iommu_labels::TAKE_FAULTS).build())
            else
            {
                return false;
            };
            let count = usize::try_from(reply.word(0))
                .unwrap_or(0)
                .min(iommu_labels::MAX_FAULTS_PER_REPLY);
            for i in 0..count
            {
                let at = i.saturating_mul(2);
                let word = reply.word(at.saturating_add(1));
                let reason = u16::try_from((word >> 32) & 0xffff).unwrap_or(0);
                each(word & 0xFFFF_FFFF, reason, reply.word(at.saturating_add(2)));
            }
            if count < iommu_labels::MAX_FAULTS_PER_REPLY
            {
                return true;
            }
        }
    }

    /// The instance whose endpoint is `ep` has died, as its death watch saw
    /// ([`watch_instance`]): when it was serving, a restart is due
    /// ([`Phase::Restarting`]), and when it was the boot instance not yet
    /// ready, the driver fails. A restart candidate's death changes nothing
    /// here: the restart that spawned it sees its calls fail.
    fn died(&self, ep: u64)
    {
        let mut link = self.link();
        if link.ep != ep
        {
            return;
        }
        match link.phase
        {
            Phase::Starting => link.phase = Phase::Failed,
            Phase::Ready => link.phase = Phase::Restarting,
            Phase::Restarting | Phase::Failed =>
            {}
        }
    }

    /// The instance of device badge `badge` has died, as devmgr's death watch
    /// saw: whether it is the instance devmgr serves, a restart then being
    /// due ([`Phase::Restarting`], set here when its own death watch has not
    /// yet). `false` for a restart candidate's death, which the restart that
    /// spawned it handles, and once the driver has failed.
    pub fn begin_restart(&self, badge: u64) -> bool
    {
        let mut link = self.link();
        if link.badge != badge
        {
            return false;
        }
        match link.phase
        {
            Phase::Ready =>
            {
                link.phase = Phase::Restarting;
                true
            }
            Phase::Restarting => true,
            Phase::Starting | Phase::Failed => false,
        }
    }

    /// Whether `badge` is the device badge of the instance devmgr serves or
    /// last served.
    pub fn is_instance(&self, badge: u64) -> bool
    {
        self.link().badge == badge
    }

    /// The driver is not served any more: refuse every later call, wake every
    /// call waiting for a restart, and log the fail-closed state once.
    /// Returns whether this call was the first.
    pub fn fail(&self) -> bool
    {
        let mut link = self.link();
        let before = link.phase;
        link.phase = Phase::Failed;
        drop(link);
        self.phase_changed.notify_all();
        if before != Phase::Failed
        {
            std::os::seraph::log!(
                warn: "IOMMU driver not served with translation on: every later DMA_MAP refused, \
                       confined devices withdrawn"
            );
        }
        before != Phase::Failed
    }

    /// The restarted instance whose endpoint is `ep` and device badge
    /// `badge` has committed its tables: it serves from now on, and every
    /// call waiting for the restart is made on it.
    fn serve_restarted(&self, ep: u64, badge: u64)
    {
        let mut link = self.link();
        link.ep = ep;
        link.badge = badge;
        link.phase = Phase::Ready;
        drop(link);
        self.phase_changed.notify_all();
    }
}

/// Call the instance whose endpoint is `ep` with `msg` from the calling
/// thread. `Err` with the driver's error label, the reply's caps deleted, or
/// `HARDWARE_TIMEOUT` when the call itself fails.
fn call_on(ep: u64, msg: &IpcMessage) -> Result<IpcMessage, u64>
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    // SAFETY: `ipc_buf` is the calling thread's registered IPC buffer.
    match unsafe { ipc::ipc_call(ep, msg, ipc_buf) }
    {
        Ok(reply) if reply.label == iommu_errors::SUCCESS => Ok(reply),
        Ok(reply) =>
        {
            for &c in reply.caps()
            {
                let _ = syscall::cap_delete(c);
            }
            Err(reply.label)
        }
        Err(_) => Err(iommu_errors::HARDWARE_TIMEOUT),
    }
}

/// [`call_on`] for a request whose reply carries nothing devmgr reads.
fn send(ep: u64, msg: &IpcMessage) -> Result<(), u64>
{
    call_on(ep, msg).map(|_| ())
}

/// A request of `label`, carrying the protocol version.
fn request(label: u64) -> ipc::IpcMessageBuilder
{
    IpcMessage::builder(label).word(0, u64::from(ipc::IOMMU_LABELS_VERSION))
}

/// `ATTACH` of the function `rid` of unit `unit`, taking the domain handle
/// `handle` and domain ID `did`, each 0 for one the driver chooses.
fn attach_msg(unit: usize, rid: u64, handle: u64, did: u64) -> IpcMessage
{
    request(iommu_labels::ATTACH)
        .word(1, unit as u64)
        .word(2, rid)
        .word(3, handle)
        .word(4, did)
        .build()
}

/// `MAP` of a derivation of `source` at `iova` in the domain `handle`;
/// `None` when the derivation fails.
fn map_msg(handle: u64, iova: u64, access: u64, source: u64) -> Option<IpcMessage>
{
    let copy = syscall::cap_derive(source, syscall::RIGHTS_ALL).ok()?;
    Some(
        request(iommu_labels::MAP)
            .word(1, handle)
            .word(2, iova)
            .word(3, access)
            .cap(copy)
            .build(),
    )
}

/// `MAP_RESERVED` of `len` bytes at `base` in the domain `handle`.
fn map_reserved_msg(handle: u64, base: u64, len: u64) -> IpcMessage
{
    request(iommu_labels::MAP_RESERVED)
        .word(1, handle)
        .word(2, base)
        .word(3, len)
        .build()
}

/// `MAP_MSI` of the interrupt file at `file` in the domain `handle`.
fn map_msi_msg(handle: u64, file: u64) -> IpcMessage
{
    request(iommu_labels::MAP_MSI)
        .word(1, handle)
        .word(2, file)
        .build()
}

/// `REMAP_SETUP` of `entries` entries on a derivation of `table`; `None`
/// when the derivation fails.
#[expect(
    clippy::fn_params_excessive_bools,
    reason = "`extended` is a word of the `REMAP_SETUP` message"
)]
fn remap_setup_msg(entries: u64, extended: bool, table: u64) -> Option<IpcMessage>
{
    let copy = syscall::cap_derive(table, syscall::RIGHTS_ALL).ok()?;
    Some(
        request(iommu_labels::REMAP_SETUP)
            .word(1, entries)
            .word(2, u64::from(extended))
            .cap(copy)
            .build(),
    )
}

/// `REMAP_SET` of `entry`.
fn remap_set_msg(entry: &RemapEntry) -> IpcMessage
{
    request(iommu_labels::REMAP_SET)
        .word(1, u64::from(entry.handle))
        .word(2, u64::from(entry.apic_id))
        .word(3, u64::from(entry.vector))
        .word(4, u64::from(entry.level))
        .word(5, u64::from(entry.source))
        .build()
}

/// Answer every call queued on the dead instance's endpoint `ep` with
/// `HARDWARE_TIMEOUT`, deleting the caps it carries, until devmgr deletes
/// the endpoint ([`Instance::release`]), so no devmgr thread waits on an
/// instance that will never receive.
fn drain(ep: u64)
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let reply = IpcMessage::new(iommu_errors::HARDWARE_TIMEOUT);
    loop
    {
        // SAFETY: `ipc_buf` is this thread's registered IPC buffer.
        let msg = match unsafe { ipc::ipc_recv(ep, ipc_buf) }
        {
            Ok(msg) => msg,
            Err(e) if e == SyscallError::InvalidCapability as i64 => return,
            Err(_) =>
            {
                let _ = syscall::thread_yield();
                continue;
            }
        };
        for &c in msg.caps()
        {
            let _ = syscall::cap_delete(c);
        }
        // SAFETY: as above.
        let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
    }
}

/// The firmware's description of the units devmgr discovered, against which
/// it places each device.
enum Topology
{
    /// VT-d units, from the DMAR.
    Dmar
    {
        /// The DMAR's bytes, for the unit and RMRR lookups of each device.
        dmar: Vec<u8>,
        /// For each DRHD in table order, its unit index in the driver;
        /// `None` for a unit devmgr could not hand over.
        unit_index: Vec<Option<usize>>,
        /// Every PCI-to-PCI bridge: its segment, function, and bus range.
        bridges: Vec<(u16, Bdf, (u8, u8))>,
    },
    /// RISC-V IOMMUs, from the RIMT.
    Rimt
    {
        /// The RIMT's bytes, for the ID-mapping lookup of each device.
        rimt: Vec<u8>,
        /// For each PCI IOMMU node in table order, its node offset and its
        /// unit index in the driver; `None` for a unit devmgr could not
        /// hand over.
        unit_index: Vec<(u32, Option<usize>)>,
    },
}

/// The bus range of the bridge `b` of `segment` among `bridges`.
fn bridge_range(bridges: &[(u16, Bdf, (u8, u8))], segment: u16, b: Bdf) -> Option<(u8, u8)>
{
    bridges
        .iter()
        .find(|(s, f, _)| *s == segment && *f == b)
        .map(|e| e.2)
}

impl Topology
{
    /// Where the function `target` of `segment` stands against the units.
    fn placement(&self, segment: u16, target: Bdf) -> Placement
    {
        match self
        {
            Self::Dmar {
                dmar,
                unit_index,
                bridges,
            } =>
            {
                let range = |b| bridge_range(bridges, segment, b);
                let secondary = |b| range(b).map(|r: (u8, u8)| r.0);
                let Some(drhd) = dmar::unit_for(dmar, segment, target, secondary, range)
                else
                {
                    return Placement::Untranslated;
                };
                unit_index
                    .get(drhd)
                    .copied()
                    .flatten()
                    .map_or(Placement::NotProgrammed, Placement::Unit)
            }
            Self::Rimt { rimt, unit_index } =>
            {
                let Some(mapping) = rimt::mapping_for(rimt, segment, target)
                else
                {
                    return Placement::Untranslated;
                };
                if !mapping.is_identity()
                {
                    return Placement::Renamed;
                }
                unit_index
                    .iter()
                    .find(|(node, _)| *node == mapping.iommu)
                    .and_then(|(_, unit)| *unit)
                    .map_or(Placement::NotProgrammed, Placement::Unit)
            }
        }
    }

    /// The `(first, last)` byte of each region the firmware reserves for the
    /// function `target` of `segment`: every DMAR RMRR that names it; none
    /// from the RIMT, which describes no reserved region. `None` when the
    /// list cannot grow.
    fn reserved_regions(&self, segment: u16, target: Bdf) -> Option<Vec<(u64, u64)>>
    {
        let mut regions = Vec::new();
        let mut complete = true;
        if let Self::Dmar { dmar, bridges, .. } = self
        {
            let range = |b| bridge_range(bridges, segment, b);
            let secondary = |b| range(b).map(|r: (u8, u8)| r.0);
            dmar::reserved_regions(dmar, segment, target, secondary, range, |first, last| {
                if regions.try_reserve(1).is_ok()
                {
                    regions.push((first, last));
                }
                else
                {
                    complete = false;
                }
            });
        }
        complete.then_some(regions)
    }
}

/// The units devmgr discovered and handed to the IOMMU driver, the firmware
/// description they came from, the client devmgr calls the driver through,
/// the extents of memory memmgr pools, which no device's reserved region may
/// overlap, and what a restart of the driver needs.
pub struct Iommu
{
    client: Arc<IommuClient>,
    topology: Topology,
    faults: Arc<Mutex<firmware::dma::FaultCounts>>,
    /// The `(base, size)` of every extent of memory memmgr pools, as init
    /// reports it; `None` when the set is not known in full.
    pooled: Option<Vec<(u64, u64)>>,
    /// Taken only by the control thread, which runs every restart.
    kit: Mutex<Kit>,
}

/// What devmgr keeps for the boot to restart the IOMMU driver
/// (`docs/device-management.md` § IOMMU Driver Restart): the driver's
/// declaration and image, the units as the boot instance was given them
/// (devmgr's register caps and anchors), the driver's restart budget, the
/// serving instance, and the instances retired since the last commit.
struct Kit
{
    decl: DriverDecl,
    grants: firmware::binding::Grants,
    /// devmgr's copy of the driver's boot module, in pages of its own
    /// ([`copy_image`]); `None` when it could not be made, which refuses
    /// every restart.
    image: Option<Binary>,
    /// The units, each marked to be adopted ([`IommuUnit::adopt`]).
    handed: Handed,
    budget: RestartBudget,
    /// The serving instance.
    serving: Option<Instance>,
    /// The instances devmgr no longer serves, dead or destroyed, since the
    /// last commit, released at the next ([`Instance::release`]).
    retired: Holds<Instance>,
}

impl Kit
{
    /// Keep `instance` until the next commit. When the record cannot grow
    /// its hold is kept for the boot, its token deleted, and its endpoint
    /// and death watch are left as they are.
    fn retire(&mut self, instance: Instance, ipc_buf: *mut u64)
    {
        if let Err(instance) = self.retired.keep(instance)
            && let Some(hold) = instance.hold
        {
            spawn::destroy_held(hold, ipc_buf);
        }
    }
}

/// One instance of the IOMMU driver devmgr started: its DMA hold, its
/// service endpoint, and the event queue of its death watch
/// ([`watch_instance`]).
struct Instance
{
    /// Its process handle and release token; `None` for one never started.
    hold: Option<HeldChild>,
    ep: u64,
    eq: u64,
}

impl Instance
{
    /// Release a retired instance once a later one has committed: destroy
    /// it and release its hold, since no unit walks its pages any more, and
    /// delete its endpoint and event queue, which ends its death watch's
    /// thread. A thread that still holds the endpoint fails its call: a
    /// deleted cap's handle is refused even once its slot is reused
    /// (`docs/capability-model.md`). Whether a hold was released.
    fn release(self, ipc_buf: *mut u64) -> bool
    {
        let released = self
            .hold
            .is_some_and(|hold| spawn::destroy_and_release(hold, ipc_buf));
        let _ = syscall::cap_delete(self.ep);
        let _ = syscall::cap_delete(self.eq);
        released
    }
}

/// What a restart of the IOMMU driver rebuilt in the restarted instance.
pub struct Replayed
{
    /// The domains attached again.
    pub domains: usize,
    /// The mappings installed again.
    pub mappings: usize,
    /// The device badges of the confined devices whose replay failed: their
    /// domains are absent from the restarted instance's tables, so the units
    /// block them, and the caller withdraws their drivers.
    pub failed: Vec<u64>,
}

/// Why a device is not given DMA.
pub struct Refused;

/// Where a device stands against the remapping units.
enum Placement
{
    /// The unit with this driver index translates it.
    Unit(usize),
    /// No unit translates it.
    Untranslated,
    /// The RIMT gives it a device ID other than its requester ID, which the
    /// driver's units are not told.
    Renamed,
    /// The unit that translates it was not handed over.
    NotProgrammed,
}

impl Iommu
{
    /// The client devmgr calls the driver through.
    pub fn client(&self) -> &Arc<IommuClient>
    {
        &self.client
    }

    /// Where `pci_dev` stands against the units, without IPC.
    fn placement(&self, pci_dev: &pci::PciDevice) -> Placement
    {
        let target = Bdf {
            bus: pci_dev.bus,
            device: pci_dev.dev,
            function: pci_dev.func,
        };
        self.topology.placement(pci_dev.segment, target)
    }

    /// The driver's unit index for `pci_dev`: `Ok(None)` when no unit
    /// translates it, so it runs unconfined; `Err` when it must be refused
    /// (the RIMT renames its device ID, or its unit was not handed over),
    /// logged.
    fn unit_of(&self, name: &str, pci_dev: &pci::PciDevice) -> Result<Option<usize>, Refused>
    {
        match self.placement(pci_dev)
        {
            Placement::Unit(unit) => Ok(Some(unit)),
            Placement::Untranslated =>
            {
                std::os::seraph::log!(
                    warn: "{}: no remapping unit translates the device; unconfined",
                    name
                );
                Ok(None)
            }
            Placement::Renamed =>
            {
                std::os::seraph::log!(
                    warn: "{}: the firmware gives the device another IOMMU device ID; refused",
                    name
                );
                Err(Refused)
            }
            Placement::NotProgrammed =>
            {
                std::os::seraph::log!(
                    warn: "{}: its remapping unit is not programmed; refused",
                    name
                );
                Err(Refused)
            }
        }
    }

    /// Whether `pci_dev` would be confined: a programmed unit translates it
    /// by its own requester ID and the driver has not failed. No IPC;
    /// [`Self::confine`] decides, and also refuses a device whose reserved
    /// regions cannot be mapped.
    pub fn would_confine(&self, pci_dev: &pci::PciDevice) -> bool
    {
        matches!(self.placement(pci_dev), Placement::Unit(_)) && !self.client.failed()
    }

    /// Attach `pci_dev` to a domain of its own before its DMA grant, so its
    /// driver's mappings are confined to it, and map there, at their own
    /// addresses, the regions the firmware reserves for it: its confinement,
    /// whose IOVA limit is the smaller of the unit's width and `dma_width`
    /// (the device's DMA address width its driver declares; `None` for no
    /// limit of its own) and which, behind a VT-d unit, keeps the interrupt
    /// address range out of its IOVAs (`firmware::dma::INTERRUPT_RANGE`),
    /// and those ranges, unconfined with none when no unit translates it.
    /// Logged `Err` when it is refused: the RIMT renames its device ID, its
    /// unit is not programmed, the driver has failed, its reserved regions
    /// overlap pooled memory, pass the unit's width, or are too many, its IOVA
    /// limit leaves no IOVA above `IOVA_BASE` (a declared DMA width of 20 bits
    /// or less, `firmware::dma::has_iova_space`), or the `ATTACH` or a
    /// reserved mapping fails; a device attached by then is blocked again.
    pub fn confine(
        &self,
        name: &str,
        pci_dev: &pci::PciDevice,
        dma_width: Option<u8>,
    ) -> Result<(Confinement, Vec<ReservedRange>), Refused>
    {
        let Some(unit) = self.unit_of(name, pci_dev)?
        else
        {
            return Ok((Confinement::Unconfined, Vec::new()));
        };
        let limit = iova_limit(self.client.width(unit), dma_width);
        if !has_iova_space(limit)
        {
            std::os::seraph::log!(
                warn: "{}: DMA address width leaves no IOVA above {:#x}; refused",
                name,
                firmware::dma::IOVA_BASE
            );
            return Err(Refused);
        }
        let reserved = self.reserved_ranges(name, pci_dev, unit)?;
        let rid =
            iommu_labels::requester_id(pci_dev.segment, pci_dev.bus, pci_dev.dev, pci_dev.func);
        let handle = match self.client.attach(unit, rid)
        {
            Ok(handle) => handle,
            Err(code) =>
            {
                std::os::seraph::log!(
                    warn: "{}: IOMMU ATTACH refused ({}); not spawned",
                    name,
                    code
                );
                return Err(Refused);
            }
        };
        for r in &reserved
        {
            if let Err(code) = self.client.map_reserved(handle, r.base, r.len)
            {
                std::os::seraph::log!(
                    warn: "{}: firmware-reserved range {:#x}..{:#x} not mapped ({}); refused",
                    name,
                    r.base,
                    r.base.saturating_add(r.len),
                    code
                );
                self.client.block(handle);
                return Err(Refused);
            }
            std::os::seraph::log!(
                "{}: firmware-reserved range {:#x}..{:#x} identity-mapped",
                name,
                r.base,
                r.base.saturating_add(r.len)
            );
        }
        let interrupt_range = matches!(self.topology, Topology::Dmar { .. });
        Ok((
            Confinement::Domain {
                handle,
                limit,
                interrupt_range,
            },
            reserved,
        ))
    }

    /// The ranges the domain of `pci_dev`, which unit `unit` translates,
    /// maps at their own addresses ([`reserved_ranges`]); logged `Err` when
    /// they cannot be mapped, so the device is refused.
    fn reserved_ranges(
        &self,
        name: &str,
        pci_dev: &pci::PciDevice,
        unit: usize,
    ) -> Result<Vec<ReservedRange>, Refused>
    {
        let target = Bdf {
            bus: pci_dev.bus,
            device: pci_dev.dev,
            function: pci_dev.func,
        };
        let Some(regions) = self.topology.reserved_regions(pci_dev.segment, target)
        else
        {
            std::os::seraph::log!(warn: "{}: reserved regions not read (no memory); refused", name);
            return Err(Refused);
        };
        if regions.is_empty()
        {
            return Ok(Vec::new());
        }
        let Some(pooled) = self.pooled.as_deref()
        else
        {
            std::os::seraph::log!(
                warn: "{}: firmware-reserved regions not checked \
                       (pooled memory not known); refused",
                name
            );
            return Err(Refused);
        };
        reserved_ranges(&regions, pooled, self.client.width(unit)).map_err(|e| {
            match e
            {
                ReservedError::Pooled(r) => std::os::seraph::log!(
                    warn: "{}: firmware-reserved range {:#x}..{:#x} overlaps pooled memory; \
                     refused (platform error)",
                    name,
                    r.base,
                    r.base.saturating_add(r.len)
                ),
                ReservedError::PastWidth { base, last } => std::os::seraph::log!(
                    warn: "{}: firmware-reserved region {:#x}..={:#x} \
                           past the unit's width; refused",
                    name,
                    base,
                    last
                ),
                ReservedError::TooMany => std::os::seraph::log!(
                    warn: "{}: more than {} firmware-reserved ranges; refused",
                    name,
                    firmware::dma::MAX_RESERVED_RANGES_PER_DEVICE as u64
                ),
                ReservedError::OutOfMemory => std::os::seraph::log!(
                    warn: "{}: reserved ranges not built (no memory); refused",
                    name
                ),
            }
            Refused
        })
    }

    /// What keeps interrupt remapping off on this platform
    /// (`dmar::remap_obstacle`): a VT-d unit not handed to the driver, or
    /// units on more than one PCI segment. `None` for an IOMMU family other
    /// than VT-d, which [`Self::io_apic_sources`] turns away first.
    pub fn remap_obstacle(&self) -> Option<dmar::RemapObstacle>
    {
        let Topology::Dmar {
            dmar, unit_index, ..
        } = &self.topology
        else
        {
            return None;
        };
        dmar::remap_obstacle(dmar, unit_index.iter().map(Option::is_some))
    }

    /// The DMAR's flags and the source ID of each I/O APIC its units name,
    /// by I/O APIC ID (`crate::intremap::enable`); `None` for an IOMMU
    /// family other than VT-d. An I/O APIC whose path does not resolve is
    /// left out.
    pub fn io_apic_sources(&self) -> Option<(dmar::DmarFlags, Vec<(u8, u16)>)>
    {
        let Topology::Dmar { dmar, bridges, .. } = &self.topology
        else
        {
            return None;
        };
        let flags = dmar::flags(dmar)?;
        let mut sources = Vec::new();
        for scope in dmar::io_apic_scopes(dmar)
        {
            let secondary = |b| bridge_range(bridges, scope.segment, b).map(|r| r.0);
            if let Some(source) = scope.source_id(secondary)
                && sources.try_reserve(1).is_ok()
            {
                sources.push((scope.id, source));
            }
        }
        Some((flags, sources))
    }

    /// Take the driver's recorded faults and log each against its device;
    /// returns the faults taken for the device given DMA under requester ID
    /// `rid` since its grant ([`Self::track_faults`]) and the IOVA of the
    /// latest.
    pub fn log_faults(&self, rid: u64) -> (u64, u64)
    {
        take_and_log(&self.client, &self.faults);
        self.faults
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .count(rid)
    }

    /// Count the faults of requester ID `rid` from zero, a device having been
    /// given DMA under it: first take the faults the driver recorded, so one
    /// raised by an earlier device at the same address, whose slot is powered
    /// off before the new device can arrive, is logged and not counted
    /// (`firmware::dma::FaultCounts`). Logged when the table cannot grow; the
    /// device's faults are then logged only.
    pub fn track_faults(&self, rid: u64)
    {
        take_and_log(&self.client, &self.faults);
        let tracked = self
            .faults
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .track(rid);
        if tracked.is_err()
        {
            std::os::seraph::log!(
                warn: "IOMMU: no memory to count the faults of requester {:#x}; logged only",
                rid
            );
        }
    }

    /// Stop counting the faults of requester ID `rid`: its device's DMA was
    /// withdrawn, and a fault it raises from now on is logged only.
    pub fn untrack_faults(&self, rid: u64)
    {
        self.faults
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .untrack(rid);
    }
}

/// Take `client`'s recorded faults and log each, counting a DMA translation
/// fault in `counts` when a live device's grant tracks its requester ID
/// (`firmware::dma::FaultCounts`); a VT-d interrupt-remapping fault names a
/// remapping table handle, not an IOVA ([`Family::fault_site`]), and is
/// logged only.
///
/// `counts` stays locked from before the take until every fault taken is
/// recorded, so a caller that reads `counts` after its own take sees every
/// fault another thread's take has handed devmgr (the DMA thread's
/// `DMA_FAULTS` reads it beside the fault-log thread), and a requester ID
/// tracked after a take ([`Iommu::track_faults`]) is charged no fault taken
/// before. The lock is held across the `TAKE_FAULTS` IPC, which
/// `docs/coding-standards.md` § Concurrency advises against: only the
/// fault-log thread, the DMA thread serving `DMA_FAULTS`, and the control
/// thread at a confined device's grant take it, so a waiter waits no longer
/// than the holders' calls to the driver, each no longer than its own would,
/// and a dead driver's calls are answered (`IommuClient::fail`), so the
/// holder does not block for good.
fn take_and_log(client: &IommuClient, counts: &Mutex<firmware::dma::FaultCounts>)
{
    let mut counts = counts.lock().unwrap_or_else(PoisonError::into_inner);
    let mut taken = Vec::new();
    let _ = client.take_faults(|rid, reason, iova| {
        if taken.try_reserve(1).is_ok()
        {
            taken.push((rid, reason, iova));
        }
    });
    let family = arch::current::IOMMU_FAMILY;
    let mut counted = Vec::new();
    let _ = counted.try_reserve_exact(taken.len());
    for &(rid, reason, address) in &taken
    {
        let charged = match family.fault_site(reason, address)
        {
            dmar::FaultSite::Iova(iova) => counts.record(rid, iova),
            dmar::FaultSite::InterruptHandle(_) => true,
        };
        if counted.len() < counted.capacity()
        {
            counted.push(charged);
        }
    }
    drop(counts);
    for (i, (rid, reason, address)) in taken.into_iter().enumerate()
    {
        let (what, value) = match family.fault_site(reason, address)
        {
            dmar::FaultSite::Iova(iova) => ("IOVA", iova),
            dmar::FaultSite::InterruptHandle(handle) => ("interrupt remapping handle", handle),
        };
        let uncounted = if counted.get(i).copied().unwrap_or(true)
        {
            ""
        }
        else
        {
            "; no live DMA grant, not counted"
        };
        std::os::seraph::log!(
            warn: "IOMMU fault: device {}:{}:{}.{} reason {:#x} {} {:#x}{}",
            rid >> 16,
            (rid >> 8) & 0xff,
            (rid >> 3) & 0x1f,
            rid & 7,
            reason,
            what,
            value,
            uncounted
        );
    }
}

/// Copy the ACPI table of signature `sig` out of the firmware tables; `None`
/// when there is none.
fn read_acpi(caps: &caps::DevmgrCaps, sig: [u8; 4]) -> Option<Vec<u8>>
{
    let phys = crate::tables::locate_table_by_sig(&caps.firmware, sig)?;
    crate::tables::with_acpi_table(&caps.firmware, phys, |t| {
        let mut v = Vec::new();
        v.try_reserve(t.len()).ok()?;
        v.extend_from_slice(t);
        Some(v)
    })
}

/// The firmware table that describes `family`'s units: the DMAR for VT-d,
/// the RIMT for the RISC-V IOMMU. `None` when there is none.
fn read_units_table(caps: &caps::DevmgrCaps, family: Family) -> Option<Vec<u8>>
{
    match family
    {
        Family::Vtd => read_acpi(caps, *b"DMAR"),
        Family::Riscv => read_acpi(caps, *b"RIMT"),
    }
}

/// A resolved scope entry in the IOMMU driver's encoding.
fn scope_word(r: Resolved) -> Scope
{
    match r
    {
        Resolved::Function(f) => Scope::Function(bdf_word(f.bus, f.device, f.function)),
        Resolved::Buses(first, last) => Scope::Buses { first, last },
    }
}

/// The remapping units devmgr hands the IOMMU driver, in unit-index order:
/// each unit's register `Mmio` range, carrying devmgr's cap for it, and each
/// unit with the index of its range in `registers`, which opens its group of
/// the driver's resource list ([`spawn::BoundSpawnConfig::units`]).
#[derive(Default)]
struct Handed
{
    registers: Vec<Resource>,
    units: Vec<(usize, IommuUnit)>,
    /// The PCI function (segment, bus, device, function) of each unit that
    /// is one, the RISC-V IOMMUs: devmgr has enabled it for the driver, so
    /// its record is bound ([`bring_up`]).
    functions: Vec<(u16, u8, u8, u8)>,
}

impl Handed
{
    /// Room for one more unit; false when none can be allocated.
    fn reserve(&mut self) -> bool
    {
        self.registers.try_reserve(1).is_ok()
            && self.units.try_reserve(1).is_ok()
            && self.functions.try_reserve(1).is_ok()
    }

    /// Whether a unit whose register range spans `pages` pages and whose
    /// scope is `scopes` can be handed over: one more unit within
    /// [`MAX_IOMMU_UNITS`], its scope within what its unit round carries, and
    /// its span within [`MAX_UNIT_REGISTER_PAGES`].
    fn fits(&self, pages: u64, scopes: &[Scope]) -> bool
    {
        self.units.len() < MAX_IOMMU_UNITS
            && scopes.len() <= MAX_UNIT_SCOPES
            && (1..=MAX_UNIT_REGISTER_PAGES).contains(&pages)
    }

    /// Hand over `unit` with its register range `registers`; the unit's
    /// index.
    fn push(&mut self, registers: Resource, unit: IommuUnit) -> usize
    {
        let index = self.units.len();
        self.units.push((self.registers.len(), unit));
        self.registers.push(registers);
        index
    }

    /// Delete devmgr's register caps and anchors: no driver was started
    /// over them.
    fn release(&self)
    {
        self.release_registers();
        for (_, unit) in &self.units
        {
            let _ = syscall::cap_delete(unit.anchor);
        }
    }

    /// Delete devmgr's register caps, keeping the anchors for the boot: a
    /// driver that may have turned a unit's translation on was not served,
    /// so the unit may walk its anchor for the rest of the boot.
    fn release_registers(&self)
    {
        for r in &self.registers
        {
            let _ = syscall::cap_delete(r.cap());
        }
    }

    /// Mark every unit to be adopted by the next instance, a restart.
    fn adopt(&mut self)
    {
        for (_, unit) in &mut self.units
        {
            unit.adopt = true;
        }
    }
}

/// `pages` physically contiguous pages from memmgr, which read zero
/// (`services/memmgr/docs/memory-pool.md` § Frame contents): devmgr's
/// Memory cap on them, kept for the boot, or `None`, logged.
pub fn kept_pages(pages: u64, what: &str) -> Option<u64>
{
    let arg = pages | (u64::from(memmgr_labels::REQUIRE_CONTIGUOUS) << 32);
    let request = IpcMessage::builder(memmgr_labels::REQUEST_MEMORY_CAPS)
        .word(0, arg)
        .build();
    let ipc_buf = std::os::seraph::current_ipc_buf();
    // SAFETY: `ipc_buf` is the calling thread's registered IPC buffer.
    let reply = unsafe {
        ipc::ipc_call(
            std::os::seraph::startup_info().memmgr_endpoint,
            &request,
            ipc_buf,
        )
    };
    if let Ok(reply) = &reply
    {
        if reply.label == memmgr_errors::SUCCESS
            && let &[cap] = reply.caps()
        {
            return Some(cap);
        }
        // A reply of any other shape is deleted; its run stays charged to
        // devmgr, which never exits.
        for &c in reply.caps()
        {
            let _ = syscall::cap_delete(c);
        }
    }
    std::os::seraph::log!(warn: "{}: {} pages not granted", what, pages);
    None
}

/// Carve each DRHD's register cap, allocate its anchor ([`kept_pages`]) and
/// resolve its scope: the units handed over, and the DMAR topology devmgr
/// places devices against. A DRHD whose register range no aperture covers,
/// whose anchor is not granted, whose scope or register span exceeds what
/// its unit's group carries, or past the driver's unit bound is not handed
/// over and its functions are refused.
fn vtd_units(
    caps: &mut caps::DevmgrCaps,
    dmar_bytes: Vec<u8>,
    devices: &[pci::PciDevice],
) -> (Handed, Topology)
{
    let bridges = bridges(devices);
    let mut handed = Handed::default();
    let mut unit_index = Vec::new();
    for unit in dmar::drhd_units(&dmar_bytes)
    {
        if unit_index.try_reserve(1).is_err() || !handed.reserve()
        {
            break;
        }
        let seg = unit.segment;
        let mut scopes = Vec::new();
        let range = |b: Bdf| bridge_range(&bridges, seg, b);
        unit.resolve_scopes(
            &dmar_bytes,
            |b| range(b).map(|r| r.0),
            range,
            |r| {
                if scopes.try_reserve(1).is_ok()
                {
                    scopes.push(scope_word(r));
                }
            },
        );
        let bytes = unit
            .register_pages
            .checked_mul(PAGE_SIZE)
            .filter(|_| handed.fits(unit.register_pages, &scopes));
        let cap = bytes.and_then(|bytes| crate::carve_subrange(caps, unit.register_base, bytes));
        let anchor = cap.and_then(|_| kept_pages(1, "VT-d unit anchor"));
        if let (Some(bytes), Some(cap), Some(anchor)) = (bytes, cap, anchor)
        {
            let registers = Resource::Mmio {
                cap,
                bar: None,
                phys: unit.register_base,
                bytes,
                offset: 0,
            };
            let handed_unit = IommuUnit {
                segment: seg,
                include_pci_all: unit.include_pci_all,
                scopes,
                anchor,
                adopt: false,
            };
            unit_index.push(Some(handed.push(registers, handed_unit)));
        }
        else
        {
            if let Some(cap) = cap
            {
                // Deleted, the range leaves the apertures for the boot: it
                // holds only the unit's registers.
                let _ = syscall::cap_delete(cap);
            }
            std::os::seraph::log!(
                warn: "VT-d unit at {:#x} not handed over; its devices are refused",
                unit.register_base
            );
            unit_index.push(None);
        }
    }
    let topology = Topology::Dmar {
        dmar: dmar_bytes,
        unit_index,
        bridges,
    };
    (handed, topology)
}

/// Resolve each RIMT PCI IOMMU's scope and carve its register cap: the
/// units handed over, and the RIMT topology devmgr places devices against.
/// An IOMMU the PCI scan did not find, without a memory BAR 0 of at least a
/// page, whose scope exceeds what its unit's group carries, whose BAR no
/// aperture covers, whose memory decode and bus mastering devmgr cannot turn
/// on, or past the driver's unit bound is not handed over, left as the
/// firmware left it, and its functions are refused.
fn riscv_units(
    caps: &mut caps::DevmgrCaps,
    rimt_bytes: Vec<u8>,
    devices: &[pci::PciDevice],
) -> (Handed, Topology)
{
    let mut handed = Handed::default();
    let mut unit_index = Vec::new();
    for iommu in rimt::pci_iommus(&rimt_bytes)
    {
        if unit_index.try_reserve(1).is_err() || !handed.reserve()
        {
            break;
        }
        if let Some((registers, unit)) = riscv_unit(caps, &handed, &rimt_bytes, iommu, devices)
        {
            unit_index.push((iommu.node, Some(handed.push(registers, unit))));
            let f = iommu.function;
            handed
                .functions
                .push((iommu.segment, f.bus, f.device, f.function));
        }
        else
        {
            let f = iommu.function;
            std::os::seraph::log!(
                warn: "RISC-V IOMMU {}:{}:{}.{} not handed over; its devices are refused",
                iommu.segment,
                f.bus,
                f.device,
                f.function
            );
            unit_index.push((iommu.node, None));
        }
    }
    let topology = Topology::Rimt {
        rimt: rimt_bytes,
        unit_index,
    };
    (handed, topology)
}

/// The PCI IOMMU `iommu` as a unit `handed` can take: its scope resolved
/// against the scanned `devices`, its BAR 0's first page, which holds every
/// register, carved, and its anchor allocated ([`kept_pages`]), before
/// devmgr turns on the function's memory decode (for the registers) and bus
/// mastering (the IOMMU reads its tables and queues by DMA); `None`, logged
/// where the step logs, when any step
/// fails or the unit does not fit. Turning the function on is the last step,
/// taken only once every other has succeeded, so a function devmgr turns on
/// is always handed over and its record marked bound ([`mark_units_bound`]),
/// and one that is not handed over is left as the firmware left it.
fn riscv_unit(
    caps: &mut caps::DevmgrCaps,
    handed: &Handed,
    rimt_bytes: &[u8],
    iommu: rimt::PciIommu,
    devices: &[pci::PciDevice],
) -> Option<(Resource, IommuUnit)>
{
    let f = iommu.function;
    let dev = devices.iter().find(|d| {
        (d.segment, d.bus, d.dev, d.func) == (iommu.segment, f.bus, f.device, f.function)
    })?;
    let bar = (0..dev.bar_count).find(|&b| {
        dev.bar_pci_idx.get(b) == Some(&0)
            && dev.bar_is_mmio.get(b) == Some(&true)
            && dev.bar_size.get(b).is_some_and(|&size| size >= PAGE_SIZE)
    })?;
    let mut scopes = Vec::new();
    let functions = devices
        .iter()
        .filter(|d| d.segment == iommu.segment)
        .map(|d| Bdf {
            bus: d.bus,
            device: d.dev,
            function: d.func,
        });
    rimt::resolve_scope(rimt_bytes, iommu.node, iommu.segment, &functions, |r| {
        if scopes.try_reserve(1).is_ok()
        {
            scopes.push(scope_word(r));
        }
    });
    if !handed.fits(1, &scopes)
    {
        return None;
    }
    let phys = *dev.bar_phys.get(bar)?;
    let cap = crate::carve_subrange(caps, phys, PAGE_SIZE)?;
    let Some(anchor) = kept_pages(1, "RISC-V IOMMU anchor")
    else
    {
        let _ = syscall::cap_delete(cap);
        return None;
    };
    let enabled =
        crate::bind::carve_function_config("RISC-V IOMMU", dev, caps).is_some_and(|config| {
            let enabled = config.enable_memory_and_bus_master();
            // devmgr needs the function's configuration no further.
            let _ = syscall::cap_delete(config.cap);
            enabled
        });
    if !enabled
    {
        // Deleted, the page leaves the apertures for the boot: it holds
        // only the unit's registers, which nothing but its driver maps.
        // The anchor's page stays charged to devmgr.
        let _ = syscall::cap_delete(cap);
        let _ = syscall::cap_delete(anchor);
        return None;
    }
    let registers = Resource::Mmio {
        cap,
        bar: Some(0),
        phys,
        bytes: PAGE_SIZE,
        offset: 0,
    };
    let unit = IommuUnit {
        segment: iommu.segment,
        include_pci_all: false,
        scopes,
        anchor,
        adopt: false,
    };
    Some((registers, unit))
}

/// Mark bound the record of each unit that is a PCI function, at
/// `functions`. Such a unit is devmgr's from its discovery, whether or not
/// the driver starts: it has its memory decoding and bus mastering enabled
/// for the driver. Marked bound, no pass binds it and acpid is refused every
/// configuration write to it (`firmware::acpid::config_access`).
fn mark_units_bound(
    records: &mut firmware::pci_records::PciRecords,
    functions: &[firmware::acpid::Address],
)
{
    for &address in functions
    {
        let index = records
            .devices()
            .iter()
            .position(|d| firmware::acpid::address(d) == address);
        if let Some(index) = index
        {
            records.mark_bound(index);
        }
    }
}

/// Discover the remapping units, spawn the IOMMU driver over them, and
/// settle it; the [`Iommu`] once the driver reports ready, else `None`,
/// logged once, and every device then runs unconfined, except, when the
/// driver was started but did not report ready, those behind a unit it
/// turned translation on for before it failed, which that unit blocks.
/// The units are placed among the PCI `records`, and the record of each
/// unit that is a PCI function is marked bound.
/// `pooled` holds the `(base, size)` of every extent of memory memmgr
/// pools, from init's bootstrap, against which each device's reserved regions
/// are checked; `None` when the set is not known in full, which refuses every
/// device with a reserved region. What a restart needs is kept from here on
/// ([`Kit`]): devmgr's register caps and anchors, and a copy of the module
/// ([`copy_image`]); the module's own cap is released.
#[expect(
    clippy::too_many_arguments,
    reason = "the IOMMU pass takes the boot modules, the pooled extents, and every table a settle \
              batch records into"
)]
pub fn bring_up(
    records: &mut firmware::pci_records::PciRecords,
    modules: &mut Vec<(DriverDecl, Binary)>,
    pooled: Option<Vec<(u64, u64)>>,
    caps: &mut caps::DevmgrCaps,
    watch: &mut settle::DriverWatch,
    catalog: &mut DeviceCatalog,
    registry: &Registry,
    ipc_buf: *mut u64,
) -> Option<Iommu>
{
    let unconfined = |why: &str| {
        std::os::seraph::log!(warn: "{}: DMA-capable devices run unconfined", why);
    };
    let family = arch::current::IOMMU_FAMILY;
    let Some(table) = read_units_table(caps, family)
    else
    {
        unconfined("no IOMMU found");
        return None;
    };
    let Some((decl, module)) = take_family_driver(family, modules)
    else
    {
        unconfined("no IOMMU driver module");
        return None;
    };
    // Released on every exit: a retained module cap pins init's donated pool
    // run. A restart starts the driver from devmgr's copy.
    let module_guard = spawn::ModuleCapGuard::new(module.cap());
    let grants = firmware::binding::grants(&decl, Source::BootModule, true);
    if !decl.dma || !grants.phys_access
    {
        std::os::seraph::log!(
            warn: "{}: declares no DMA or no physical access, \
                   which the IOMMU driver needs; not bound",
            decl.name.as_str()
        );
        unconfined("IOMMU driver not started");
        return None;
    }
    let (handed, topology) = match family
    {
        Family::Vtd => vtd_units(caps, table, records.devices()),
        Family::Riscv => riscv_units(caps, table, records.devices()),
    };
    mark_units_bound(records, &handed.functions);
    if handed.units.is_empty()
    {
        unconfined("no IOMMU unit can be programmed");
        return None;
    }
    launch(
        Launch {
            decl,
            grants,
            module,
            module_guard,
            handed,
            topology,
            pooled,
        },
        caps,
        watch,
        catalog,
        registry,
        ipc_buf,
    )
}

/// What [`bring_up`] found for the IOMMU driver's start.
struct Launch
{
    decl: DriverDecl,
    grants: firmware::binding::Grants,
    /// The driver's boot module, whose cap `module_guard` releases.
    module: Binary,
    module_guard: spawn::ModuleCapGuard,
    /// The units handed over, none of them empty.
    handed: Handed,
    topology: Topology,
    pooled: Option<Vec<(u64, u64)>>,
}

/// Start the IOMMU driver over what [`bring_up`] found, `found`: create its
/// endpoint and death watch, copy its image, spawn and settle it, and once
/// it reports ready build the [`Iommu`] it serves; `None`, logged, as
/// [`bring_up`] says.
#[expect(
    clippy::too_many_lines,
    reason = "the driver's start in order: the endpoint and death watch, the image copy, the \
              spawn and settle, and each outcome's release of what devmgr allocated for it"
)]
fn launch(
    found: Launch,
    caps: &mut caps::DevmgrCaps,
    watch: &mut settle::DriverWatch,
    catalog: &mut DeviceCatalog,
    registry: &Registry,
    ipc_buf: *mut u64,
) -> Option<Iommu>
{
    let unconfined = |why: &str| {
        std::os::seraph::log!(warn: "{}: DMA-capable devices run unconfined", why);
    };
    let Launch {
        decl,
        grants,
        module,
        module_guard,
        mut handed,
        topology,
        pooled,
    } = found;
    let started = crate::create_service_endpoint().and_then(|ep| {
        let client = Arc::new(IommuClient::new(ep));
        let eq = watch_instance(&client, ep);
        if eq.is_none()
        {
            let _ = syscall::cap_delete(ep);
        }
        eq.map(|eq| (client, ep, eq))
    });
    let Some((client, ep, death_eq)) = started
    else
    {
        handed.release();
        unconfined("no IOMMU driver endpoint or death watch");
        return None;
    };
    let Some(source) = module.source_copy()
    else
    {
        // Wake the death watch, whose observer was never bound, so it exits.
        let _ = syscall::event_post(death_eq, 0);
        handed.release();
        unconfined("IOMMU driver module cap not derived");
        return None;
    };
    let image = copy_image(caps, &module);
    drop(module_guard);
    let settled = spawn_and_settle(
        caps,
        &decl,
        &grants,
        source,
        &handed,
        (ep, death_eq),
        watch,
        catalog,
        registry,
        ipc_buf,
    );
    let (serving, badge) = match settled
    {
        Settled::Ready { held, badge } => (held, badge),
        Settled::NotStarted =>
        {
            let _ = syscall::event_post(death_eq, 0);
            handed.release();
            if let Some(image) = image
            {
                image.release();
            }
            unconfined("IOMMU driver not started");
            return None;
        }
        Settled::NotReady(held) =>
        {
            // Wake the death watch: a spawn that failed before its observer
            // bind leaves it no death to post. A queued death post, received
            // first, ends it all the same.
            let _ = syscall::event_post(death_eq, 0);
            if let Some(held) = held
            {
                spawn::destroy_held(held, ipc_buf);
            }
            handed.release_registers();
            if let Some(image) = image
            {
                image.release();
            }
            std::os::seraph::log!(
                warn: "IOMMU driver not ready after its bootstrap: DMA-capable devices run \
                 unconfined, except those behind a unit it turned translation on for \
                 before it failed, which that unit blocks"
            );
            return None;
        }
    };
    if !client.mark_ready(badge)
    {
        std::os::seraph::log!(
            warn: "IOMMU driver died before devmgr took its ready report: every DMA_MAP of a \
                   device it confines is refused, and no restart is made"
        );
    }
    let units = handed.units.len();
    let _ = client.widths.set(query_widths(ep, units));
    registry.set_iommu(Arc::clone(&client));
    let faults = Arc::new(Mutex::new(firmware::dma::FaultCounts::new()));
    start_fault_log(&client, &faults);
    std::os::seraph::log!(
        "IOMMU: {} {} translating",
        units as u64,
        arch::current::IOMMU_FAMILY.units()
    );
    handed.adopt();
    Some(Iommu {
        client,
        topology,
        faults,
        pooled,
        kit: Mutex::new(Kit {
            decl,
            grants,
            image,
            handed,
            budget: RestartBudget::new(),
            serving: Some(Instance {
                hold: Some(serving),
                ep,
                eq: death_eq,
            }),
            retired: Holds::default(),
        }),
    })
}

/// Copy the IOMMU driver's boot module `module` into pages devmgr allocates
/// and keeps for the boot ([`kept_pages`]): the image every restart starts the
/// driver from. devmgr cannot keep the module's own cap, a derivation of
/// init's donated pool run, which a retained derivation pins unsplittable
/// (`spawn::ModuleCapGuard`), nor read the binary from the drivers directory
/// at a restart, which needs a `DMA_MAP` the IOMMU driver serves. The copy
/// carries the module's name and size, under which procmgr verifies its
/// signature. `None`, logged, when the pages cannot be had or written: the
/// driver is then not restarted.
fn copy_image(caps: &caps::DevmgrCaps, module: &Binary) -> Option<Binary>
{
    let Binary::Module { cap, size, name } = module
    else
    {
        return None;
    };
    let pages = size.div_ceil(PAGE_SIZE);
    let copy = kept_pages(pages, "IOMMU driver image")?;
    let written = crate::decls::with_module(caps, *cap, *size, |bytes| {
        write_pages(caps.self_aspace, copy, pages, bytes)
    });
    let name = name.clone();
    if written != Some(true)
    {
        std::os::seraph::log!(warn: "IOMMU driver image not copied; the driver is not restarted");
        let _ = syscall::cap_delete(copy);
        return None;
    }
    Some(Binary::Module {
        cap: copy,
        size: *size,
        name,
    })
}

/// Write `bytes` at the start of the `pages` pages of the Memory cap `cap`,
/// mapped writable into `aspace` for the call; whether they were written.
fn write_pages(aspace: u64, cap: u64, pages: u64, bytes: &[u8]) -> bool
{
    let Ok(range) = std::os::seraph::reserve_pages(pages)
    else
    {
        return false;
    };
    let va = range.va_start();
    // SAFETY: `range` is a fresh reservation of `pages` pages from the
    // per-process arena, owned here: VA no Rust object or IPC page occupies.
    let mapped = unsafe {
        std::os::seraph::mem_map_funded(
            cap,
            aspace,
            va,
            0,
            pages,
            syscall_abi::MAP_READ | syscall_abi::MAP_WRITABLE,
        )
    };
    let written = mapped.is_ok() && {
        let span = usize::try_from(pages.saturating_mul(PAGE_SIZE)).unwrap_or(0);
        // SAFETY: `span` bytes are mapped writable from `va` above, and
        // nothing else reaches the pages: devmgr allocated them for this copy.
        let dst = unsafe { core::slice::from_raw_parts_mut(va as *mut u8, span) };
        dst.get_mut(..bytes.len())
            .map(|d| d.copy_from_slice(bytes))
            .is_some()
    };
    // SAFETY: the span is this call's own reservation, and `dst`, the only
    // reference into it, is not used past the block above.
    unsafe { crate::unmap_window(aspace, range) };
    written
}

/// The IOMMU pass's match: take out of `modules` every boot-module
/// declaration that matches the family record of `family` (its IOMMU family
/// key, docs/driver-binding.md § Matching) and choose one through a match
/// table of its own. The chosen declaration and module, or `None`, logged
/// when two match equally; every other taken module is released.
fn take_family_driver(
    family: Family,
    modules: &mut Vec<(DriverDecl, Binary)>,
) -> Option<(DriverDecl, Binary)>
{
    let record = RecordKeys {
        iommu_family: Some(family.key()),
        ..RecordKeys::default()
    };
    let mut table: MatchTable<Binary> = MatchTable::new();
    let mut i = 0;
    while i < modules.len()
    {
        let Some(module) = modules.get(i)
        else
        {
            break;
        };
        if firmware::binding::decl_rank(&module.0, Source::BootModule, &record).is_none()
        {
            i = i.saturating_add(1);
            continue;
        }
        let (decl, binary) = modules.remove(i);
        let cap = binary.cap();
        // The IOMMU pass is the boot's first: no driver is bound yet.
        if table.add(decl, Source::BootModule, binary, 0).is_err()
        {
            std::os::seraph::log!(
                warn: "{}: no memory to consider the driver; not bound",
                decl.name.as_str()
            );
            let _ = syscall::cap_delete(cap);
        }
    }
    let chosen = match table.choose(&record)
    {
        Choice::Bind(index) => Some(index),
        Choice::Conflict(first, second) =>
        {
            let candidates = table.candidates();
            std::os::seraph::log!(
                warn: "IOMMU record: {} and {} match it equally; neither bound",
                candidates.get(first).map_or("", |c| c.decl.name.as_str()),
                candidates.get(second).map_or("", |c| c.decl.name.as_str())
            );
            None
        }
        Choice::Unmatched => None,
    };
    let decl = chosen.and_then(|index| table.candidates().get(index).map(|c| c.decl));
    let mut module = None;
    for (index, binary) in table.drain_binaries().enumerate()
    {
        if Some(index) == chosen
        {
            module = Some(binary);
        }
        else
        {
            binary.release();
        }
    }
    decl.zip(module)
}

/// Every PCI-to-PCI bridge of `devices`: its segment, function, and bus
/// range, against which the DMAR's scopes resolve.
fn bridges(devices: &[pci::PciDevice]) -> Vec<(u16, Bdf, (u8, u8))>
{
    let mut out = Vec::new();
    for d in devices
    {
        if let Some(range) = d.bridge_buses
            && out.try_reserve(1).is_ok()
        {
            let f = Bdf {
                bus: d.bus,
                device: d.dev,
                function: d.func,
            };
            out.push((d.segment, f, range));
        }
    }
    out
}

/// The IOVA width of each of the `units` units of the instance whose
/// endpoint is `ep` (`QUERY_UNIT`); 0 for one it does not report, which
/// then takes no mapping.
fn query_widths(ep: u64, units: usize) -> Vec<u8>
{
    let mut widths = Vec::new();
    if widths.try_reserve(units).is_err()
    {
        return widths;
    }
    for unit in 0..units
    {
        let msg = request(iommu_labels::QUERY_UNIT)
            .word(1, unit as u64)
            .build();
        let width = call_on(ep, &msg).map_or(0, |r| u8::try_from(r.word(0)).unwrap_or(0));
        widths.push(width);
    }
    widths
}

/// Start the thread that watches the IOMMU driver instance whose service
/// endpoint is `ep` for its death: it waits on an event queue of its own,
/// to which the instance's spawn binds its second pair of death observers
/// (`settle::OBSERVERS_PER_DRIVER`; the queue holds their two posts and the
/// ending post). On the first death post it tells `client`
/// ([`IommuClient::died`]), at once and independent of devmgr's control
/// thread, which may itself be blocked in a call to the dead instance
/// (directly, or through a read whose buffer the DMA thread is mapping), and
/// then answers every call queued on `ep` with an error until devmgr
/// deletes it ([`drain`]). A post with tag 0, which no death post carries
/// (the correlator is a nonzero device badge), or the deletion of the queue,
/// only ends the thread. The queue,
/// or `None` when it or the thread cannot be created.
fn watch_instance(client: &Arc<IommuClient>, ep: u64) -> Option<u64>
{
    // Two death posts and the ending post; one node per observer.
    const OBSERVERS: u32 = crate::settle::OBSERVERS_PER_DRIVER;
    let eq = std::os::seraph::object_slab_retype(
        std::os::seraph::event_queue_retype_bytes(u64::from(OBSERVERS + 1), u64::from(OBSERVERS)),
        |slab| syscall::event_queue_create_observed(slab, OBSERVERS + 1, OBSERVERS).ok(),
    )?;
    let watched = Arc::clone(client);
    let started = std::thread::Builder::new()
        .name("iommu-watch".into())
        .spawn(move || {
            loop
            {
                match syscall::event_recv_entry(eq, 0)
                {
                    Ok(e) if e.tag != 0 =>
                    {
                        watched.died(ep);
                        drop(watched);
                        drain(ep);
                        return;
                    }
                    Ok(_) => return,
                    Err(e) if e == SyscallError::InvalidCapability as i64 => return,
                    Err(_) =>
                    {
                        let _ = syscall::thread_yield();
                    }
                }
            }
        });
    if started.is_err()
    {
        let _ = syscall::cap_delete(eq);
        return None;
    }
    Some(eq)
}

/// How the IOMMU driver's spawn and settle ended.
enum Settled
{
    /// It reported ready: its process handle and release token, and its
    /// device badge.
    Ready
    {
        held: HeldChild, badge: u64
    },
    /// It was never started, so it turned no translation on and touched no
    /// unit.
    NotStarted,
    /// It was started but did not report ready: dead, destroyed at the
    /// settle bound, or destroyed when a resource-list round or an observer
    /// bind failed after its start; it may have touched a unit. Its process
    /// handle and release token, when devmgr kept them.
    NotReady(Option<HeldChild>),
}

/// Spawn the IOMMU driver `decl` from `source` with `grants`, delivering it
/// the `handed` units with `instance.0` as its service endpoint, in a
/// settle batch of its own, its death watched on `instance.1`
/// ([`watch_instance`]) as well as devmgr's death queue, and settle it. The
/// driver is created held, since its units walk its table pages by DMA:
/// procmgr keeps its pages after it dies until devmgr releases them on its
/// release token, which devmgr does only once a later instance has
/// committed tables of its own ([`Iommu::restart`]).
#[expect(
    clippy::too_many_arguments,
    reason = "the spawn and its settle consume the declaration, the instance's endpoint and death \
              watch, the batch's death queue, the catalog, and the registry"
)]
fn spawn_and_settle(
    caps: &mut caps::DevmgrCaps,
    decl: &DriverDecl,
    grants: &firmware::binding::Grants,
    source: spawn::CreateSource<'_>,
    handed: &Handed,
    instance: (u64, u64),
    watch: &mut settle::DriverWatch,
    catalog: &mut DeviceCatalog,
    registry: &Registry,
    ipc_buf: *mut u64,
) -> Settled
{
    let (service_ep, death_eq) = instance;
    // Deletes the source copy on the exits before the spawn takes it.
    let mut source_guard = spawn::ModuleCapGuard::new(match source
    {
        spawn::CreateSource::Module { cap, .. } => cap,
        spawn::CreateSource::File { file_cap, .. } => file_cap,
    });
    let batch = settle::SettleBatch::new();
    let badge = catalog.add_without_info();
    let mut roster = firmware::roster::Roster::new();
    let (Some(batch), Some(device_badge), Ok(())) = (batch, badge, roster.try_reserve_one())
    else
    {
        std::os::seraph::log!(warn: "IOMMU driver: no settle batch or badge; not spawned");
        return Settled::NotStarted;
    };
    let config = spawn::BoundSpawnConfig {
        procmgr_ep: caps.procmgr_ep,
        bootstrap_ep: caps.self_bootstrap_ep,
        source,
        resources: &handed.registers,
        units: &handed.units,
        dma_cap: None,
        held: true,
        phys_access: grants.phys_access,
        reserve: grants.reserve,
        service_ep,
        query_ep: batch.driver_ep(),
        watch,
        watch_eq: Some(death_eq),
        device_badge,
        // devmgr's DMA thread, at the boot drivers' level, calls the driver
        // on every map and unmap of the root-disk path; a boot-module
        // declaration of the boot tier is given it.
        priority: spawn::tier_priority(grants.tier),
    };
    // The spawn deletes the source on every exit.
    source_guard.disarm();
    let spawn = spawn::spawn_bound_driver(&config, ipc_buf);
    let child = match spawn
    {
        spawn::DriverSpawn::Bootstrapped(child) => child,
        spawn::DriverSpawn::Unbootstrapped(child) =>
        {
            // It may have taken its units' groups and be setting them up;
            // its pages stay held.
            spawn::send_destroy(child.process_handle, ipc_buf);
            return Settled::NotReady(Some(child));
        }
        spawn::DriverSpawn::Failed => return Settled::NotStarted,
    };
    // devmgr keeps a copy of the process handle for the instance's life
    // ([`Kit::serving`]); the registry's record releases the one it holds
    // once the instance is served.
    let Ok(kept_handle) = syscall::cap_derive(child.process_handle, syscall::RIGHTS_ALL)
    else
    {
        std::os::seraph::log!(warn: "IOMMU driver: process handle not kept; destroyed");
        spawn::destroy_held(child, ipc_buf);
        return Settled::NotReady(None);
    };
    let kept = HeldChild {
        process_handle: kept_handle,
        release_token: child.release_token,
    };
    let spawned = SpawnedDriver {
        name: decl.name,
        serves: Serves::Iommu,
        badge: device_badge,
        driver: ServedDriver {
            // The endpoint stays the client's: no withdrawal of the driver
            // deletes it.
            ep: 0,
            dev_caps: None,
            platform_caps: None,
            process_handle: child.process_handle,
            // devmgr restarts the IOMMU driver from what it keeps itself
            // (`Iommu::restart`), not from a restart source.
            restart: None,
            declined: false,
        },
    };
    crate::record_spawned(&mut roster, spawned, &mut caps.slot_bars, ipc_buf);
    crate::settle_batch(
        batch,
        roster,
        watch,
        catalog,
        registry,
        &mut caps.slot_bars,
        settle::SETTLE_TIMEOUT,
        ipc_buf,
    );
    if registry.iommu_serves(device_badge)
    {
        Settled::Ready {
            held: kept,
            badge: device_badge,
        }
    }
    else
    {
        Settled::NotReady(Some(kept))
    }
}

impl Iommu
{
    /// Restart the IOMMU driver, the instance devmgr served having died with
    /// a fault or a kill (`docs/device-management.md` § IOMMU Driver
    /// Restart). The dead instance's hold is kept until a commit. Each
    /// attempt ([`iommu_restart::attempt`]) is charged to the driver's
    /// budget and starts an instance from devmgr's image copy over the same
    /// units, each to be adopted; once it reports ready with the same unit
    /// widths, devmgr replays its records into it ([`Self::replay`]) and has
    /// it commit its tables into the anchors (`COMMIT`). The instance then
    /// serves, every call waiting for it is made on it, and every dead hold
    /// is released. An attempt that fails before the commit leaves the units
    /// on the tables they translated through, its instance destroyed and its
    /// hold kept, and the next attempt follows.
    ///
    /// # Errors
    /// The [`Refusal`] that ends the attempts; the caller fails the driver
    /// closed.
    #[expect(
        clippy::significant_drop_tightening,
        reason = "the kit stays locked across every attempt, through its explicit drop: the \
                  attempts spawn from it, keep holds in it, and charge its budget"
    )]
    pub(crate) fn restart(
        &self,
        caps: &mut caps::DevmgrCaps,
        watch: &mut settle::DriverWatch,
        catalog: &mut DeviceCatalog,
        registry: &Registry,
        ipc_buf: *mut u64,
    ) -> Result<Replayed, Refusal>
    {
        let mut kit = self.kit.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(dead) = kit.serving.take()
        {
            kit.retire(dead, ipc_buf);
        }
        loop
        {
            let kept = kit.image.is_some();
            iommu_restart::attempt(kept, || kit.budget.try_charge(crate::now_ns()))?;
            if let Some(replayed) = self.attempt(&mut kit, caps, watch, catalog, registry, ipc_buf)
            {
                return Ok(replayed);
            }
        }
    }

    /// One restart attempt ([`Self::restart`]): what the replay rebuilt, or
    /// `None`, logged, when the attempt failed.
    fn attempt(
        &self,
        kit: &mut Kit,
        caps: &mut caps::DevmgrCaps,
        watch: &mut settle::DriverWatch,
        catalog: &mut DeviceCatalog,
        registry: &Registry,
        ipc_buf: *mut u64,
    ) -> Option<Replayed>
    {
        let started = crate::create_service_endpoint().and_then(|ep| {
            let eq = watch_instance(&self.client, ep);
            if eq.is_none()
            {
                let _ = syscall::cap_delete(ep);
            }
            eq.map(|eq| (ep, eq))
        });
        let Some((ep, eq)) = started
        else
        {
            std::os::seraph::log!(warn: "IOMMU restart: no endpoint or death watch");
            return None;
        };
        let Some(source) = kit.image.as_ref().and_then(Binary::source_copy)
        else
        {
            let _ = syscall::event_post(eq, 0);
            kit.retire(Instance { hold: None, ep, eq }, ipc_buf);
            std::os::seraph::log!(warn: "IOMMU restart: image cap not derived");
            return None;
        };
        let settled = spawn_and_settle(
            caps,
            &kit.decl,
            &kit.grants,
            source,
            &kit.handed,
            (ep, eq),
            watch,
            catalog,
            registry,
            ipc_buf,
        );
        let (held, badge) = match settled
        {
            Settled::Ready { held, badge } => (held, badge),
            Settled::NotStarted =>
            {
                let _ = syscall::event_post(eq, 0);
                kit.retire(Instance { hold: None, ep, eq }, ipc_buf);
                std::os::seraph::log!(warn: "IOMMU restart: instance not started");
                return None;
            }
            Settled::NotReady(hold) =>
            {
                let _ = syscall::event_post(eq, 0);
                kit.retire(Instance { hold, ep, eq }, ipc_buf);
                std::os::seraph::log!(warn: "IOMMU restart: instance not ready");
                return None;
            }
        };
        let replayed = self
            .replay(ep, kit.handed.units.len(), caps.dma.as_ref())
            .and_then(|replayed| {
                call_on(ep, &request(iommu_labels::COMMIT).build())
                    .map(|_| replayed)
                    .map_err(|code| {
                        std::os::seraph::log!(warn: "IOMMU restart: COMMIT failed ({})", code);
                    })
            });
        let Ok(replayed) = replayed
        else
        {
            // Not served: its death, which the destroy below causes, is no
            // restart's.
            registry.forget_iommu_instance(badge);
            spawn::send_destroy(held.process_handle, ipc_buf);
            kit.retire(
                Instance {
                    hold: Some(held),
                    ep,
                    eq,
                },
                ipc_buf,
            );
            return None;
        };
        self.client.serve_restarted(ep, badge);
        let mut released = 0usize;
        for retired in kit.retired.committed()
        {
            if retired.release(ipc_buf)
            {
                released = released.saturating_add(1);
            }
        }
        kit.serving = Some(Instance {
            hold: Some(held),
            ep,
            eq,
        });
        std::os::seraph::log!(
            "IOMMU driver restarted: {} domains attached again, {} mappings installed again, \
             {} holds released",
            replayed.domains as u64,
            replayed.mappings as u64,
            released as u64
        );
        Some(replayed)
    }

    /// Replay devmgr's records into the restarted instance whose endpoint is
    /// `ep`, which drives `units` units: check that it reports the widths
    /// the boot instance did, then for each confined device of the DMA table
    /// (`firmware::dma::DmaTable::replay`) `ATTACH` its function with its
    /// recorded handle and domain ID, `MAP_RESERVED` each firmware-reserved
    /// range, `MAP_MSI` each held interrupt file and `MAP` each mapping it
    /// may reach; and on VT-d set the interrupt remapping table up again on
    /// devmgr's cap and write each entry recorded. A device whose replay
    /// fails is blocked in the instance, forgotten from the domain ledger, and
    /// named in [`Replayed::failed`].
    ///
    /// # Errors
    /// The widths differ, the table cannot be read, a device's domain is
    /// neither rebuilt nor blocked, or the remapping table or an entry is
    /// refused; logged.
    fn replay(
        &self,
        ep: u64,
        units: usize,
        dma: Option<&crate::dma::DmaService>,
    ) -> Result<Replayed, ()>
    {
        if Some(&query_widths(ep, units)) != self.client.widths.get()
        {
            std::os::seraph::log!(warn: "IOMMU restart: the instance reports other unit widths");
            return Err(());
        }
        let Some(Ok(plan)) = dma.map(crate::dma::DmaService::replay)
        else
        {
            std::os::seraph::log!(warn: "IOMMU restart: no memory to read the DMA table");
            return Err(());
        };
        let mut replayed = Replayed {
            domains: 0,
            mappings: 0,
            failed: Vec::new(),
        };
        for device in &plan
        {
            let domain = self.client.domains().get(device.handle);
            let rebuilt = domain.map_or(
                Err(ReplayFailed::Device(iommu_errors::INVALID_REQUEST)),
                |domain| replay_device(ep, domain, device),
            );
            match rebuilt
            {
                Ok(mappings) =>
                {
                    replayed.domains = replayed.domains.saturating_add(1);
                    replayed.mappings = replayed.mappings.saturating_add(mappings);
                }
                Err(ReplayFailed::Unblocked) =>
                {
                    std::os::seraph::log!(
                        warn: "IOMMU restart: device {}'s domain neither rebuilt nor blocked",
                        device.badge
                    );
                    return Err(());
                }
                Err(ReplayFailed::Device(code)) =>
                {
                    // Absent from the instance's tables: a withdrawal finds the
                    // function blocked (`IommuClient::block_withdrawn`).
                    self.client.domains().forget(device.handle);
                    std::os::seraph::log!(
                        warn: "IOMMU restart: device {}'s domain not rebuilt ({})",
                        device.badge,
                        code
                    );
                    if replayed.failed.try_reserve(1).is_err()
                    {
                        return Err(());
                    }
                    replayed.failed.push(device.badge);
                }
            }
        }
        let (table, entries) = {
            let remaps = self.client.remaps();
            let entries: Vec<RemapEntry> = remaps.entries().to_vec();
            (remaps.table(), entries)
        };
        if let Some(table) = table
        {
            let msg = remap_setup_msg(table.entries, table.extended, table.cap);
            let set_up = msg
                .ok_or(iommu_errors::OUT_OF_RESOURCES)
                .and_then(|msg| call_on(ep, &msg))
                .map(|reply| reply.word(0) == 1);
            if set_up != Ok(table.extended)
            {
                std::os::seraph::log!(warn: "IOMMU restart: interrupt remapping table not taken");
                return Err(());
            }
            for entry in &entries
            {
                if let Err(code) = call_on(ep, &remap_set_msg(entry))
                {
                    std::os::seraph::log!(
                        warn: "IOMMU restart: remapping entry {} not written ({})",
                        u64::from(entry.handle),
                        code
                    );
                    return Err(());
                }
            }
        }
        Ok(replayed)
    }
}

/// Why a device's replay failed.
enum ReplayFailed
{
    /// A refusal, with its error label: the device's domain is absent from
    /// the instance's staged tables, so the units block the device from the
    /// commit on.
    Device(u64),
    /// A refusal after the `ATTACH`, whose `BLOCK` the instance refused too:
    /// the staged tables hold the device's domain with only part of its
    /// mappings.
    Unblocked,
}

/// Rebuild `device`'s domain, `domain`, in the instance whose endpoint is
/// `ep`; the mappings installed. A refusal after the `ATTACH` blocks the
/// domain again, so the device is absent from the staged tables whichever
/// step was refused.
///
/// # Errors
/// [`ReplayFailed`].
fn replay_device(ep: u64, domain: Domain, device: &DeviceReplay) -> Result<usize, ReplayFailed>
{
    let reply = call_on(
        ep,
        &attach_msg(domain.unit, domain.rid, domain.handle, domain.did),
    )
    .map_err(ReplayFailed::Device)?;
    if reply.word(0) != domain.handle || reply.word(1) != domain.did
    {
        // The reply names another domain, which the instance attached: block
        // it, as for a refusal after the attach.
        let handle = reply.word(0);
        return Err(block_on(ep, handle, iommu_errors::INVALID_REQUEST));
    }
    fill_domain(ep, domain, device).map_err(|code| block_on(ep, domain.handle, code))
}

/// Block the domain `handle` the instance whose endpoint is `ep` attached,
/// after the replay of its device was refused with `code`.
fn block_on(ep: u64, handle: u64, code: u64) -> ReplayFailed
{
    let msg = request(iommu_labels::BLOCK).word(1, handle).build();
    match call_on(ep, &msg)
    {
        Ok(_) => ReplayFailed::Device(code),
        Err(_) => ReplayFailed::Unblocked,
    }
}

/// Install `device`'s reserved ranges, interrupt files and mappings in its
/// domain `domain`, attached in the instance whose endpoint is `ep`; the
/// mappings installed.
///
/// # Errors
/// The first refusal's error label.
fn fill_domain(ep: u64, domain: Domain, device: &DeviceReplay) -> Result<usize, u64>
{
    for r in &device.reserved
    {
        send(ep, &map_reserved_msg(domain.handle, r.base, r.len))?;
    }
    for file in &device.files
    {
        send(ep, &map_msi_msg(domain.handle, file.base))?;
    }
    for m in &device.mappings
    {
        IommuClient::map_on(ep, domain.handle, m.device_addr, m.access, m.cap)?;
    }
    Ok(device.mappings.len())
}

/// Start devmgr's fault-log thread: every [`FAULT_LOG_MS`] it takes the
/// driver's recorded faults and logs each against its device.
fn start_fault_log(client: &Arc<IommuClient>, faults: &Arc<Mutex<firmware::dma::FaultCounts>>)
{
    let client = Arc::clone(client);
    let faults = Arc::clone(faults);
    let started = std::thread::Builder::new()
        .name("iommu-faults".into())
        .spawn_at_priority(ipc::sched_policy::DEVMGR_PRIORITY, move || {
            while !client.failed()
            {
                let _ = syscall::thread_sleep(FAULT_LOG_MS);
                take_and_log(&client, &faults);
            }
        });
    if started.is_err()
    {
        std::os::seraph::log!(
            warn: "IOMMU fault-log thread not started; faults are logged on request"
        );
    }
}

/// The requester ID of `pci_dev`.
pub fn requester_id(pci_dev: &pci::PciDevice) -> u64
{
    iommu_labels::requester_id(pci_dev.segment, pci_dev.bus, pci_dev.dev, pci_dev.func)
}
