// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/devmgr/src/iommu.rs

//! devmgr's side of the IOMMU: discovering the remapping units, spawning the
//! IOMMU driver that programs them, deciding each DMA-capable device's
//! confinement, and calling the driver over `ipc::iommu_labels`.
//!
//! At boot, before the boot batch, [`bring_up`] reads the firmware table of
//! the architecture's IOMMU family (`arch::current::IOMMU_FAMILY`): on
//! x86-64 the ACPI DMAR, whose VT-d units' register `Mmio` caps it carves
//! from the apertures; on riscv64 the ACPI RIMT, whose RISC-V IOMMUs are PCI
//! functions, each unit's register cap being its BAR 0, carved after devmgr
//! turns on the function's memory decode and bus mastering. It spawns the
//! family's driver (`iommu-vtd`, `iommu-riscv`) from its boot module in a
//! settle batch of its own, handing it every unit (`iommu_core::bootstrap`);
//! devmgr keeps no copy of a register cap. Once the driver reports ready
//! every function a unit translates is blocked until devmgr attaches it, so
//! [`Iommu::confine`] attaches each DMA-capable device before its DMA grant
//! and maps, at their own addresses, the regions the firmware reserves for it
//! (each DMAR RMRR that names it; the RIMT describes none). It refuses a
//! device whose reserved regions overlap memory memmgr pools, pass its unit's
//! width, or number past `MAX_RESERVED_RANGES_PER_DEVICE`, one the RIMT gives
//! a device ID other than its requester ID, one whose unit it could not hand
//! over, and one whose `ATTACH` or reserved mapping fails. When no
//! unit is found, no driver module was delivered, or the driver does not
//! report ready within the settle bound, devmgr logs once that DMA runs
//! unconfined and every device runs so; a driver that fails its own setup
//! turns translation off again first, but one that dies or hangs after it
//! turned a unit's translation on leaves that unit blocking the devices
//! behind it, which devmgr, holding no register cap, cannot undo, and logs
//! as such.
//!
//! The [`IommuClient`] is shared by devmgr's registry thread (`ATTACH`,
//! `BLOCK`), its DMA thread (`MAP`, `UNMAP`), and its fault-log thread
//! (`TAKE_FAULTS`), each call made with no devmgr lock held. When the driver
//! dies after it reported ready, the hardware goes on translating, so devmgr
//! cannot fall back to unconfined DMA. A death watch thread of its own sees
//! the death at once, independent of the registry loop, which may itself be
//! blocked in a call to the dead driver: [`IommuClient::fail`] makes every
//! later call fail at once, logged once, and starts a thread that answers any
//! call still queued on the driver's endpoint with an error. When the
//! registry loop takes the death, devmgr withdraws every confined device's
//! driver. No restart is attempted;
//! restartability is [#262](https://github.com/kottlerg/seraph/issues/262).
//! See `docs/device-management.md` § IOMMU Discovery and Programming.

use std::os::seraph::thread::BuilderExt;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use firmware::dma::{Confinement, ReservedError, ReservedRange, iova_limit, reserved_ranges};
use firmware::dmar::{self, Bdf, Resolved};
use firmware::rimt;
use iommu_core::Scope;
use ipc::{IpcMessage, iommu_errors, iommu_labels};
use syscall_abi::PAGE_SIZE;

use crate::{DeviceCatalog, ServedDriver, ServedDrivers, Serves, SpawnedDriver};
use crate::{arch, caps, pci, settle, spawn};

/// The IOMMU family an architecture's platforms carry, which decides the
/// firmware table devmgr discovers the units in and the driver module it
/// spawns over them (`arch::current::IOMMU_FAMILY`).
// dead_code: each architecture's build constructs only its own family
// (`arch::current::IOMMU_FAMILY`), so the other variant is never constructed
// there; both stay, since devmgr's discovery handles each family on either
// build.
#[allow(dead_code)]
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

/// The IOMMU driver's endpoint as devmgr calls it, the units' translation
/// widths, and whether the driver has failed.
pub struct IommuClient
{
    /// The driver's service endpoint, the original devmgr created; the
    /// driver receives on a copy. Never deleted, whatever becomes of the
    /// driver, so no devmgr thread ever calls or drains a slot another cap
    /// has since taken.
    ep: u64,
    /// Each unit's IOVA width (`QUERY_UNIT`), by unit index; set once the
    /// driver is ready.
    widths: OnceLock<Vec<u8>>,
    /// [`STATE_READY`] once the driver reported ready, after which its death
    /// leaves the units translating, and [`STATE_FAILED`] once it died. One
    /// atomic, so of the two threads that set them (the bring-up and the
    /// death watch), exactly the one that sets the second bit sees both.
    state: AtomicU8,
}

/// [`IommuClient::state`]: the driver reported ready.
const STATE_READY: u8 = 1 << 0;
/// [`IommuClient::state`]: the driver died.
const STATE_FAILED: u8 = 1 << 1;

impl IommuClient
{
    /// Whether the driver has failed: every call is refused from then on.
    pub fn failed(&self) -> bool
    {
        self.state.load(Ordering::Acquire) & STATE_FAILED != 0
    }

    /// Record that the driver reported ready, logging the fail-closed state
    /// when it has already died.
    fn mark_ready(&self)
    {
        let before = self.state.fetch_or(STATE_READY, Ordering::AcqRel);
        if before & STATE_FAILED != 0
        {
            Self::log_failed();
        }
    }

    /// Log the fail-closed state a death after the ready report leaves; the
    /// one log line it gets.
    fn log_failed()
    {
        std::os::seraph::log!(
            "IOMMU driver died with translation enabled: every later DMA_MAP refused, \
             confined devices withdrawn, no restart (#262)"
        );
    }

    /// Call the driver with `msg` from the calling thread. `Err` with the
    /// driver's error label, or `HARDWARE_TIMEOUT` when the driver has failed
    /// or the call itself fails (the driver died with it in flight).
    fn call(&self, msg: &IpcMessage) -> Result<IpcMessage, u64>
    {
        if self.failed()
        {
            return Err(iommu_errors::HARDWARE_TIMEOUT);
        }
        let ipc_buf = std::os::seraph::current_ipc_buf();
        // SAFETY: `ipc_buf` is the calling thread's registered IPC buffer.
        match unsafe { ipc::ipc_call(self.ep, msg, ipc_buf) }
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

    fn request(label: u64) -> ipc::IpcMessageBuilder
    {
        IpcMessage::builder(label).word(0, u64::from(ipc::IOMMU_LABELS_VERSION))
    }

    /// Attach the function `rid` (`iommu_labels::requester_id`) of unit
    /// `unit` to a domain of its own; its domain handle.
    ///
    /// # Errors
    /// The driver's error label.
    pub fn attach(&self, unit: usize, rid: u64) -> Result<u64, u64>
    {
        let msg = Self::request(iommu_labels::ATTACH)
            .word(1, unit as u64)
            .word(2, rid)
            .build();
        self.call(&msg).map(|r| r.word(0))
    }

    /// Install the frames of `cap`, a derivation devmgr moves to the driver,
    /// at `iova` in the domain `handle` with `access`.
    ///
    /// # Errors
    /// The driver's error label; the driver has deleted the cap.
    pub fn map(&self, handle: u64, iova: u64, access: u64, cap: u64) -> Result<(), u64>
    {
        let msg = Self::request(iommu_labels::MAP)
            .word(1, handle)
            .word(2, iova)
            .word(3, access)
            .cap(cap)
            .build();
        self.call(&msg).map(|_| ())
    }

    /// Install the firmware-reserved range of `len` bytes at `base` in the
    /// domain `handle` at its own address (`MAP_RESERVED`).
    ///
    /// # Errors
    /// The driver's error label; nothing is installed.
    pub fn map_reserved(&self, handle: u64, base: u64, len: u64) -> Result<(), u64>
    {
        let msg = Self::request(iommu_labels::MAP_RESERVED)
            .word(1, handle)
            .word(2, base)
            .word(3, len)
            .build();
        self.call(&msg).map(|_| ())
    }

    /// Remove the range at `iova` of the domain `handle`.
    ///
    /// # Errors
    /// The driver's error label; the range stands.
    pub fn unmap(&self, handle: u64, iova: u64) -> Result<(), u64>
    {
        let msg = Self::request(iommu_labels::UNMAP)
            .word(1, handle)
            .word(2, iova)
            .build();
        self.call(&msg).map(|_| ())
    }

    /// Block the domain `handle`'s function; whether the block is in place.
    pub fn block(&self, handle: u64) -> bool
    {
        let msg = Self::request(iommu_labels::BLOCK).word(1, handle).build();
        self.call(&msg).is_ok()
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
    /// refused or has failed.
    pub fn take_faults(&self, mut each: impl FnMut(u64, u16, u64)) -> bool
    {
        loop
        {
            let Ok(reply) = self.call(&Self::request(iommu_labels::TAKE_FAULTS).build())
            else
            {
                return false;
            };
            let count = usize::try_from(reply.word(0))
                .unwrap_or(0)
                .min(iommu_labels::MAX_FAULTS_PER_REPLY);
            for i in 0..count
            {
                let word = reply.word(1 + 2 * i);
                let reason = u16::try_from((word >> 32) & 0xffff).unwrap_or(0);
                each(word & 0xFFFF_FFFF, reason, reply.word(2 + 2 * i));
            }
            if count < iommu_labels::MAX_FAULTS_PER_REPLY
            {
                return true;
            }
        }
    }

    /// The driver has died: refuse every later call, log it once when the
    /// driver had reported ready (when the ready report is recorded after
    /// this, [`Self::mark_ready`] logs it instead), and answer every call
    /// still queued on its endpoint with an error from a thread of devmgr's
    /// own, so no devmgr thread waits on a driver that will never receive.
    /// Called by the death watch ([`start_death_watch`]) as soon as the
    /// death posts, and again, to no effect, by the registry loop when it
    /// takes the death; returns whether this call was the first.
    pub fn fail(&self) -> bool
    {
        let before = self.state.fetch_or(STATE_FAILED, Ordering::AcqRel);
        if before & STATE_FAILED != 0
        {
            return false;
        }
        if before & STATE_READY != 0
        {
            Self::log_failed();
        }
        let ep = self.ep;
        if std::thread::Builder::new()
            .name("iommu-drain".into())
            .spawn(move || drain(ep))
            .is_err()
        {
            std::os::seraph::log!("IOMMU drain thread not started; a queued IOMMU call may hang");
        }
        true
    }
}

/// Answer every call queued on the dead IOMMU driver's endpoint `ep` with
/// `HARDWARE_TIMEOUT`, deleting the caps it carries, for the rest of the
/// boot.
fn drain(ep: u64)
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    if ipc_buf.is_null()
    {
        return;
    }
    let reply = IpcMessage::new(iommu_errors::HARDWARE_TIMEOUT);
    loop
    {
        // SAFETY: ipc_buf is this thread's registered IPC buffer.
        let Ok(msg) = (unsafe { ipc::ipc_recv(ep, ipc_buf) })
        else
        {
            let _ = syscall::thread_yield();
            continue;
        };
        for &c in msg.caps()
        {
            let _ = syscall::cap_delete(c);
        }
        // SAFETY: as above.
        let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
    }
}

/// The faults devmgr has taken for each device, by requester ID.
#[derive(Default)]
struct FaultCounts(Vec<(u64, u64, u64)>);

impl FaultCounts
{
    fn record(&mut self, rid: u64, iova: u64)
    {
        if let Some(e) = self.0.iter_mut().find(|e| e.0 == rid)
        {
            e.1 += 1;
            e.2 = iova;
        }
        else if self.0.try_reserve(1).is_ok()
        {
            self.0.push((rid, 1, iova));
        }
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
/// and the extents of memory memmgr pools, which no device's reserved region
/// may overlap.
pub struct Iommu
{
    client: Arc<IommuClient>,
    topology: Topology,
    faults: Arc<Mutex<FaultCounts>>,
    /// The `(base, size)` of every extent of memory memmgr pools, as init
    /// reports it; `None` when the set is not known in full.
    pooled: Option<Vec<(u64, u64)>>,
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
                    "{}: no remapping unit translates the device; unconfined",
                    name
                );
                Ok(None)
            }
            Placement::Renamed =>
            {
                std::os::seraph::log!(
                    "{}: the firmware gives the device another IOMMU device ID; refused",
                    name
                );
                Err(Refused)
            }
            Placement::NotProgrammed =>
            {
                std::os::seraph::log!("{}: its remapping unit is not programmed; refused", name);
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
    /// addresses, the regions the firmware reserves for it: its confinement
    /// and those ranges, unconfined with none when no unit translates it.
    /// Logged `Err` when it is refused: the RIMT renames its device ID, its
    /// unit is not programmed, the driver has failed, its reserved regions
    /// overlap pooled memory, pass the unit's width, or are too many, or the
    /// `ATTACH` or a reserved mapping fails; a device attached by then is
    /// blocked again.
    pub fn confine(
        &self,
        name: &str,
        pci_dev: &pci::PciDevice,
    ) -> Result<(Confinement, Vec<ReservedRange>), Refused>
    {
        let Some(unit) = self.unit_of(name, pci_dev)?
        else
        {
            return Ok((Confinement::Unconfined, Vec::new()));
        };
        let reserved = self.reserved_ranges(name, pci_dev, unit)?;
        let rid =
            iommu_labels::requester_id(pci_dev.segment, pci_dev.bus, pci_dev.dev, pci_dev.func);
        let handle = match self.client.attach(unit, rid)
        {
            Ok(handle) => handle,
            Err(code) =>
            {
                std::os::seraph::log!("{}: IOMMU ATTACH refused ({}); not spawned", name, code);
                return Err(Refused);
            }
        };
        for r in &reserved
        {
            if let Err(code) = self.client.map_reserved(handle, r.base, r.len)
            {
                std::os::seraph::log!(
                    "{}: firmware-reserved range {:#x}..{:#x} not mapped ({}); refused",
                    name,
                    r.base,
                    r.base + r.len,
                    code
                );
                self.client.block(handle);
                return Err(Refused);
            }
            std::os::seraph::log!(
                "{}: firmware-reserved range {:#x}..{:#x} identity-mapped",
                name,
                r.base,
                r.base + r.len
            );
        }
        let limit = iova_limit(
            self.client.width(unit),
            pci_dev.vendor_id,
            pci_dev.device_id,
        );
        Ok((Confinement::Domain { handle, limit }, reserved))
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
            std::os::seraph::log!("{}: reserved regions not read (no memory); refused", name);
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
                "{}: firmware-reserved regions not checked (pooled memory not known); refused",
                name
            );
            return Err(Refused);
        };
        reserved_ranges(&regions, pooled, self.client.width(unit)).map_err(|e| {
            match e
            {
                ReservedError::Pooled(r) => std::os::seraph::log!(
                    "{}: firmware-reserved range {:#x}..{:#x} overlaps pooled memory; \
                     refused (platform error)",
                    name,
                    r.base,
                    r.base + r.len
                ),
                ReservedError::PastWidth { base, last } => std::os::seraph::log!(
                    "{}: firmware-reserved region {:#x}..={:#x} past the unit's width; refused",
                    name,
                    base,
                    last
                ),
                ReservedError::TooMany => std::os::seraph::log!(
                    "{}: more than {} firmware-reserved ranges; refused",
                    name,
                    firmware::dma::MAX_RESERVED_RANGES_PER_DEVICE as u64
                ),
                ReservedError::OutOfMemory => std::os::seraph::log!(
                    "{}: reserved ranges not built (no memory); refused",
                    name
                ),
            }
            Refused
        })
    }

    /// Take the driver's recorded faults and log each against its device;
    /// returns the faults taken for the function `rid` over the boot and the
    /// IOVA of the latest.
    pub fn log_faults(&self, rid: u64) -> (u64, u64)
    {
        take_and_log(&self.client, &self.faults);
        let counts = self.faults.lock().unwrap_or_else(PoisonError::into_inner);
        counts
            .0
            .iter()
            .find(|e| e.0 == rid)
            .map_or((0, 0), |e| (e.1, e.2))
    }
}

/// Take `client`'s recorded faults and log each, recording it in `counts`.
///
/// `counts` stays locked from before the take until every fault taken is
/// recorded, so a caller that reads `counts` after its own take sees every
/// fault another thread's take has handed devmgr (`TEST_DMA_FAULTS` reads
/// it beside the fault-log thread). The lock is held across the
/// `TAKE_FAULTS` IPC, which `docs/coding-standards.md` § Concurrency advises
/// against: only the fault-log thread and `TEST_DMA_FAULTS` take it, so the
/// one waiter waits no longer than its own call to the driver would, and a
/// dead driver's calls are answered (`IommuClient::fail`), so the holder
/// does not block for good.
fn take_and_log(client: &IommuClient, counts: &Mutex<FaultCounts>)
{
    let mut counts = counts.lock().unwrap_or_else(PoisonError::into_inner);
    let mut taken = Vec::new();
    let _ = client.take_faults(|rid, reason, iova| {
        if taken.try_reserve(1).is_ok()
        {
            taken.push((rid, reason, iova));
        }
    });
    for (rid, reason, iova) in taken
    {
        std::os::seraph::log!(
            "IOMMU fault: device {}:{}:{}.{} reason {:#x} IOVA {:#x}",
            rid >> 16,
            (rid >> 8) & 0xff,
            (rid >> 3) & 0x1f,
            rid & 7,
            reason,
            iova
        );
        counts.record(rid, iova);
    }
}

/// Copy the ACPI table of signature `sig` out of the firmware tables; `None`
/// when there is none.
fn read_acpi(caps: &caps::DevmgrCaps, sig: [u8; 4]) -> Option<Vec<u8>>
{
    let phys = crate::tables::locate_table_by_sig(caps, sig)?;
    crate::tables::with_acpi_table(caps, phys, |t| {
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

/// Carve each DRHD's register cap and encode its unit round: the rounds,
/// and the DMAR topology devmgr places devices against. A DRHD whose
/// register range no aperture covers, whose scope or register span exceeds
/// what a round carries, or past the driver's unit bound is not handed over
/// and its functions are refused.
fn vtd_rounds(
    caps: &mut caps::DevmgrCaps,
    dmar_bytes: Vec<u8>,
    devices: &[pci::PciDevice],
) -> (Vec<spawn::UnitRound>, Topology)
{
    let bridges = bridges(devices);
    let mut rounds = Vec::new();
    let mut unit_index = Vec::new();
    for unit in dmar::drhd_units(&dmar_bytes)
    {
        if unit_index.try_reserve(1).is_err() || rounds.try_reserve(1).is_err()
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
        let words = iommu_core::bootstrap::unit_round_words(
            seg,
            unit.include_pci_all,
            unit.register_pages,
            &scopes,
        );
        let handed = rounds.len() < iommu_core::bootstrap::MAX_UNITS;
        let cap = words.as_ref().filter(|_| handed).and_then(|_| {
            crate::carve_subrange(caps, unit.register_base, unit.register_pages * PAGE_SIZE)
        });
        if let (Some(words), Some(cap)) = (words, cap)
        {
            unit_index.push(Some(rounds.len()));
            rounds.push(spawn::UnitRound { cap, words });
        }
        else
        {
            std::os::seraph::log!(
                "VT-d unit at {:#x} not handed over; its devices are refused",
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
    (rounds, topology)
}

/// Encode each RIMT PCI IOMMU's unit round and carve its register cap: the
/// rounds, and the RIMT topology devmgr places devices against. An IOMMU
/// the PCI scan did not find, without a memory BAR 0 of at least a page,
/// whose scope exceeds what a round carries, whose memory decode and bus
/// mastering devmgr cannot turn on, whose BAR no aperture covers, or past
/// the driver's unit bound is not handed over and its functions are refused.
fn riscv_rounds(
    caps: &mut caps::DevmgrCaps,
    rimt_bytes: Vec<u8>,
    devices: &[pci::PciDevice],
) -> (Vec<spawn::UnitRound>, Topology)
{
    let mut rounds = Vec::new();
    let mut unit_index = Vec::new();
    for iommu in rimt::pci_iommus(&rimt_bytes)
    {
        if unit_index.try_reserve(1).is_err() || rounds.try_reserve(1).is_err()
        {
            break;
        }
        let round = (rounds.len() < iommu_core::bootstrap::MAX_UNITS)
            .then(|| riscv_round(caps, &rimt_bytes, iommu, devices))
            .flatten();
        if let Some(round) = round
        {
            unit_index.push((iommu.node, Some(rounds.len())));
            rounds.push(round);
        }
        else
        {
            let f = iommu.function;
            std::os::seraph::log!(
                "RISC-V IOMMU {}:{}:{}.{} not handed over; its devices are refused",
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
    (rounds, topology)
}

/// The unit round of the PCI IOMMU `iommu`: its scope resolved against the
/// scanned `devices`, and its BAR 0's first page, which holds every register,
/// carved once devmgr has turned on the function's memory decode (for the
/// registers) and bus mastering (the IOMMU reads its tables and queues by
/// DMA); `None`, logged where the step logs, when any step fails.
fn riscv_round(
    caps: &mut caps::DevmgrCaps,
    rimt_bytes: &[u8],
    iommu: rimt::PciIommu,
    devices: &[pci::PciDevice],
) -> Option<spawn::UnitRound>
{
    let f = iommu.function;
    let dev = devices.iter().find(|d| {
        (d.segment, d.bus, d.dev, d.func) == (iommu.segment, f.bus, f.device, f.function)
    })?;
    let bar = (0..dev.bar_count)
        .find(|&b| dev.bar_pci_idx[b] == 0 && dev.bar_is_mmio[b] && dev.bar_size[b] >= PAGE_SIZE)?;
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
    let words = iommu_core::bootstrap::unit_round_words(iommu.segment, false, 1, &scopes)?;
    let config = crate::bind::carve_function_config("RISC-V IOMMU", dev, caps)?;
    let enabled = config.enable_memory_and_bus_master();
    // devmgr needs the function's configuration no further.
    let _ = syscall::cap_delete(config.cap);
    if !enabled
    {
        return None;
    }
    let cap = crate::carve_subrange(caps, dev.bar_phys[bar], PAGE_SIZE)?;
    Some(spawn::UnitRound { cap, words })
}

/// Discover the remapping units, spawn the IOMMU driver over them, and
/// settle it; the [`Iommu`] once the driver reports ready, else `None`,
/// logged once, and every device then runs unconfined, except, when the
/// driver was started but did not report ready, those behind a unit it
/// turned translation on for before it failed, which that unit blocks.
/// `pooled` holds the `(base, size)` of every extent of memory memmgr
/// pools, from init's bootstrap, against which each device's reserved regions
/// are checked; `None` when the set is not known in full, which refuses every
/// device with a reserved region.
pub fn bring_up(
    devices: &[pci::PciDevice],
    pooled: Option<Vec<(u64, u64)>>,
    caps: &mut caps::DevmgrCaps,
    watch: &mut settle::DriverWatch,
    catalog: &mut DeviceCatalog,
    served: &mut ServedDrivers,
    ipc_buf: *mut u64,
) -> Option<Iommu>
{
    // Released on every exit the spawn does not take it on: a retained
    // module cap pins init's donated pool run.
    let module_cap = caps.module_cap_for_kind(caps::module_kind::IOMMU);
    let module_guard = spawn::ModuleCapGuard::new(module_cap);
    let unconfined = |why: &str| {
        std::os::seraph::log!("{}: DMA-capable devices run unconfined", why);
    };
    let family = arch::current::IOMMU_FAMILY;
    let Some(table) = read_units_table(caps, family)
    else
    {
        unconfined("no IOMMU found");
        return None;
    };
    if module_cap == 0
    {
        unconfined("no IOMMU driver module");
        return None;
    }
    let (rounds, topology) = match family
    {
        Family::Vtd => vtd_rounds(caps, table, devices),
        Family::Riscv => riscv_rounds(caps, table, devices),
    };
    if rounds.is_empty()
    {
        unconfined("no IOMMU unit can be programmed");
        return None;
    }
    let Some((client, death_eq)) = start_death_watch()
    else
    {
        release_rounds(&rounds);
        unconfined("no IOMMU driver endpoint or death watch");
        return None;
    };
    let settled = spawn_and_settle(
        caps,
        module_guard,
        &rounds,
        &client,
        death_eq,
        watch,
        catalog,
        served,
        ipc_buf,
    );
    match settled
    {
        Settled::Ready =>
        {}
        Settled::NotStarted =>
        {
            // Wake the death watch, whose observer was never bound, so it
            // exits.
            let _ = syscall::event_post(death_eq, 0);
            unconfined("IOMMU driver not started");
            return None;
        }
        Settled::NotReady =>
        {
            // Wake the death watch: a spawn that failed before its observer
            // bind leaves it no death to post. A queued death post, received
            // first, ends it all the same.
            let _ = syscall::event_post(death_eq, 0);
            std::os::seraph::log!(
                "IOMMU driver not ready after its bootstrap: DMA-capable devices run \
                 unconfined, except those behind a unit it turned translation on for \
                 before it failed, which that unit blocks"
            );
            return None;
        }
    }
    client.mark_ready();
    let handed = rounds.len();
    let _ = client.widths.set(query_widths(&client, handed));
    served.set_iommu(Arc::clone(&client));
    let faults = Arc::new(Mutex::new(FaultCounts::default()));
    start_fault_log(&client, &faults);
    std::os::seraph::log!("IOMMU: {} {} translating", handed as u64, family.units());
    Some(Iommu {
        client,
        topology,
        faults,
        pooled,
    })
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

/// The IOVA width of each of the driver's `units` units (`QUERY_UNIT`); 0
/// for one it does not report, which then takes no mapping.
fn query_widths(client: &IommuClient, units: usize) -> Vec<u8>
{
    let mut widths = Vec::new();
    if widths.try_reserve(units).is_err()
    {
        return widths;
    }
    for unit in 0..units
    {
        let msg = IommuClient::request(iommu_labels::QUERY_UNIT)
            .word(1, unit as u64)
            .build();
        let width = client
            .call(&msg)
            .map_or(0, |r| u8::try_from(r.word(0)).unwrap_or(0));
        widths.push(width);
    }
    widths
}

/// Delete the register caps of `rounds`, which no driver was given.
fn release_rounds(rounds: &[spawn::UnitRound])
{
    for r in rounds
    {
        let _ = syscall::cap_delete(r.cap);
    }
}

/// Create the IOMMU driver's service endpoint and the client devmgr calls it
/// through, and start the thread that watches for the driver's death: it
/// waits on an event queue of its own, to which the driver's spawn binds a
/// second death observer, and fails the client at once on a death post, so
/// the failure never waits on devmgr's registry loop, which may itself be
/// blocked in a call to the dead driver (directly, or through a read whose
/// buffer the DMA thread is mapping). A post with tag 0, which no death post
/// carries (the correlator is a nonzero device badge), only ends the thread.
/// `None`, logged, when the endpoint, the queue, or the thread cannot be
/// created.
fn start_death_watch() -> Option<(Arc<IommuClient>, u64)>
{
    let ep = crate::create_service_endpoint()?;
    let eq = std::os::seraph::object_slab_retype(
        std::os::seraph::event_queue_retype_bytes(2, 1),
        |slab| syscall::event_queue_create_observed(slab, 2, 1).ok(),
    );
    let Some(eq) = eq
    else
    {
        let _ = syscall::cap_delete(ep);
        return None;
    };
    let client = Arc::new(IommuClient {
        ep,
        widths: OnceLock::new(),
        state: AtomicU8::new(0),
    });
    let watched = Arc::clone(&client);
    let started = std::thread::Builder::new()
        .name("iommu-watch".into())
        .spawn(move || {
            loop
            {
                match syscall::event_recv_entry(eq, 0)
                {
                    Ok(e) if e.tag != 0 =>
                    {
                        watched.fail();
                        return;
                    }
                    Ok(_) => return,
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
        let _ = syscall::cap_delete(ep);
        return None;
    }
    Some((client, eq))
}

/// How the IOMMU driver's spawn and settle ended.
enum Settled
{
    /// It reported ready.
    Ready,
    /// It was never started, so it turned no translation on.
    NotStarted,
    /// It was started but did not report ready: dead, destroyed at the
    /// settle bound, or destroyed when a bootstrap round or an observer bind
    /// failed after its start; it may have turned a unit's translation on.
    NotReady,
}

/// Spawn the IOMMU driver from its module, which `module_guard` holds, over
/// `rounds` with the client's endpoint as its service endpoint, in a settle
/// batch of its own, its death watched on `death_eq` as well as devmgr's
/// death queue, and settle it.
// too_many_arguments: the spawn and its settle consume the client, the death
// watch, the batch's death queue, the catalog, and the served classes.
#[allow(clippy::too_many_arguments)]
fn spawn_and_settle(
    caps: &caps::DevmgrCaps,
    mut module_guard: spawn::ModuleCapGuard,
    rounds: &[spawn::UnitRound],
    client: &IommuClient,
    death_eq: u64,
    watch: &mut settle::DriverWatch,
    catalog: &mut DeviceCatalog,
    served: &mut ServedDrivers,
    ipc_buf: *mut u64,
) -> Settled
{
    let batch = settle::SettleBatch::new();
    let badge = catalog.add_without_info();
    let mut roster = firmware::roster::Roster::new();
    let (Some(batch), Some(device_badge), Ok(())) = (batch, badge, roster.try_reserve_one())
    else
    {
        std::os::seraph::log!("IOMMU driver: no settle batch or badge; not spawned");
        release_rounds(rounds);
        return Settled::NotStarted;
    };
    // `spawn_iommu_driver` owns the module cap's lifecycle from here
    // (consumed by CREATE_PROCESS, or released on failure).
    module_guard.disarm();
    let config = spawn::IommuSpawnConfig {
        procmgr_ep: caps.procmgr_ep,
        bootstrap_ep: caps.self_bootstrap_ep,
        module_cap: caps.module_cap_for_kind(caps::module_kind::IOMMU),
        units: rounds,
        service_ep: client.ep,
        query_ep: batch.driver_ep(),
        death_eq: watch.death_eq(),
        watch_eq: death_eq,
        device_badge,
        // devmgr's DMA thread, at the boot drivers' level, calls the driver
        // on every map and unmap of the root-disk path.
        priority: ipc::sched_policy::BOOT_DRIVER_PRIORITY,
    };
    let process_handle = match spawn::spawn_iommu_driver(&config, ipc_buf)
    {
        spawn::DriverSpawn::Bootstrapped(h) => h,
        spawn::DriverSpawn::Unbootstrapped(h) =>
        {
            // Every unit round reached it only when the endpoint round or
            // an observer bind failed; it may then be setting its units up.
            spawn::destroy_child(h, ipc_buf);
            return Settled::NotReady;
        }
        spawn::DriverSpawn::Failed => return Settled::NotStarted,
    };
    let spawned = SpawnedDriver {
        name: crate::fixed::IOMMU,
        serves: Serves::Iommu,
        badge: device_badge,
        driver: ServedDriver {
            ep: client.ep,
            dev_caps: None,
            process_handle,
        },
    };
    crate::record_spawned(&mut roster, spawned, ipc_buf);
    crate::settle_batch(
        batch,
        roster,
        watch,
        catalog,
        served,
        settle::SETTLE_TIMEOUT,
        ipc_buf,
    );
    if served.iommu_served()
    {
        Settled::Ready
    }
    else
    {
        Settled::NotReady
    }
}

/// Start devmgr's fault-log thread: every [`FAULT_LOG_MS`] it takes the
/// driver's recorded faults and logs each against its device.
fn start_fault_log(client: &Arc<IommuClient>, faults: &Arc<Mutex<FaultCounts>>)
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
        std::os::seraph::log!("IOMMU fault-log thread not started; faults are logged on request");
    }
}

/// The requester ID of `pci_dev`.
pub fn requester_id(pci_dev: &pci::PciDevice) -> u64
{
    iommu_labels::requester_id(pci_dev.segment, pci_dev.bus, pci_dev.dev, pci_dev.func)
}
