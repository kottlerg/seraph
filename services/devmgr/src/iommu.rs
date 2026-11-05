// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/devmgr/src/iommu.rs

//! devmgr's side of the IOMMU: discovering the remapping units, spawning the
//! IOMMU driver that programs them, deciding each DMA-capable device's
//! confinement, and calling the driver over `ipc::iommu_labels`.
//!
//! At boot, before the boot batch, [`bring_up`] reads the ACPI DMAR, carves
//! each VT-d unit's register `Mmio` cap from the apertures, and spawns
//! `iommu-vtd` from its boot module in a settle batch of its own, handing it
//! every unit (`iommu_core::bootstrap`); devmgr keeps no copy of a register
//! cap. Once the driver reports ready every function a unit translates is
//! blocked until devmgr attaches it, so [`Iommu::confine`] attaches each
//! DMA-capable device before its DMA grant, refusing a device the firmware
//! reserves memory for (an RMRR names it; identity-mapping such regions is
//! [#773](https://github.com/kottlerg/seraph/issues/773)) or whose `ATTACH`
//! fails. When no unit is found, no driver module was delivered, or the
//! driver does not report ready within the settle bound, devmgr logs once
//! that DMA runs unconfined and every device runs so.
//!
//! The [`IommuClient`] is shared by devmgr's registry thread (`ATTACH`,
//! `BLOCK`), its DMA thread (`MAP`, `UNMAP`), and its fault-log thread
//! (`TAKE_FAULTS`), each call made with no devmgr lock held. When the driver
//! dies after it enabled translation, the hardware goes on translating, so
//! devmgr cannot fall back to unconfined DMA: [`IommuClient::fail`] makes
//! every later call fail at once, logged once, and starts a thread that
//! answers any call still queued on the driver's endpoint with an error, and
//! devmgr withdraws every confined device's driver. No restart is attempted;
//! restartability is [#262](https://github.com/kottlerg/seraph/issues/262).
//! See `docs/device-management.md` § IOMMU Discovery and Programming.

use std::os::seraph::thread::BuilderExt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use firmware::dma::{Confinement, EDU_ID, iova_limit};
use firmware::dmar::{self, Bdf, Resolved};
use iommu_core::Scope;
use ipc::{IpcMessage, iommu_errors, iommu_labels};
use syscall_abi::PAGE_SIZE;

use crate::{DeviceCatalog, DriverClass, ServedDriver, ServedDrivers, SpawnedDriver};
use crate::{caps, pci, settle, spawn};

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
    /// driver receives on a copy. Never deleted, so no devmgr thread ever
    /// calls a slot another cap has since taken.
    ep: u64,
    /// Each unit's IOVA width (`QUERY_UNIT`), by unit index.
    widths: Vec<u8>,
    failed: AtomicBool,
}

impl IommuClient
{
    /// Whether the driver has failed: every call is refused from then on.
    pub fn failed(&self) -> bool
    {
        self.failed.load(Ordering::Acquire)
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
        self.widths.get(unit).copied().unwrap_or(0)
    }

    /// Take the faults the driver recorded since the last take, passing each
    /// as (requester ID, reason, IOVA) to `each`; `false` when the driver
    /// refused or has failed.
    pub fn take_faults(&self, mut each: impl FnMut(u64, u8, u64)) -> bool
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
                let reason = u8::try_from((word >> 32) & 0xff).unwrap_or(0);
                each(word & 0xFFFF_FFFF, reason, reply.word(2 + 2 * i));
            }
            if count < iommu_labels::MAX_FAULTS_PER_REPLY
            {
                return true;
            }
        }
    }

    /// The driver has died with translation enabled: refuse every later call,
    /// log it once, and answer every call still queued on its endpoint with
    /// an error from a thread of devmgr's own, so no devmgr thread waits on a
    /// driver that will never receive. Returns whether this call was the
    /// first, which withdraws the confined devices' drivers.
    pub fn fail(&self) -> bool
    {
        if self.failed.swap(true, Ordering::AcqRel)
        {
            return false;
        }
        std::os::seraph::log!(
            "IOMMU driver died with translation enabled: every later DMA_MAP refused, \
             confined devices withdrawn, no restart (#262)"
        );
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

/// The units devmgr discovered and handed to the IOMMU driver, the DMAR they
/// came from, and the client devmgr calls the driver through.
pub struct Iommu
{
    client: Arc<IommuClient>,
    /// The DMAR's bytes, for the RMRR and unit lookups of each device.
    dmar: Vec<u8>,
    /// For each DRHD in table order, its unit index in the driver; `None`
    /// for a unit devmgr could not hand over.
    unit_index: Vec<Option<usize>>,
    /// Every PCI-to-PCI bridge: its segment, function, and bus range.
    bridges: Vec<(u16, Bdf, (u8, u8))>,
    faults: Arc<Mutex<FaultCounts>>,
}

/// Why a device is not given DMA.
pub struct Refused;

impl Iommu
{
    /// The client devmgr calls the driver through.
    pub fn client(&self) -> &Arc<IommuClient>
    {
        &self.client
    }

    fn secondary_bus(&self, segment: u16) -> impl FnMut(Bdf) -> Option<u8> + '_
    {
        move |b| self.bus_range(segment)(b).map(|r| r.0)
    }

    fn bus_range(&self, segment: u16) -> impl FnMut(Bdf) -> Option<(u8, u8)> + '_
    {
        move |b| {
            self.bridges
                .iter()
                .find(|(s, f, _)| *s == segment && *f == b)
                .map(|e| e.2)
        }
    }

    /// The driver's unit index for `pci_dev`: `Ok(None)` when no unit
    /// translates it, so it runs unconfined; `Err` when it must be refused
    /// (an RMRR names it, or its unit was not handed over), logged.
    fn unit_of(&self, name: &str, pci_dev: &pci::PciDevice) -> Result<Option<usize>, Refused>
    {
        let target = Bdf {
            bus: pci_dev.bus,
            device: pci_dev.dev,
            function: pci_dev.func,
        };
        let seg = pci_dev.segment;
        if dmar::has_reserved_region(
            &self.dmar,
            seg,
            target,
            self.secondary_bus(seg),
            self.bus_range(seg),
        )
        {
            std::os::seraph::log!(
                "{}: firmware reserves memory for the device (RMRR); refused (#773)",
                name
            );
            return Err(Refused);
        }
        let Some(drhd) = dmar::unit_for(
            &self.dmar,
            seg,
            target,
            self.secondary_bus(seg),
            self.bus_range(seg),
        )
        else
        {
            std::os::seraph::log!(
                "{}: no remapping unit translates the device; unconfined",
                name
            );
            return Ok(None);
        };
        if let Some(unit) = self.unit_index.get(drhd).copied().flatten()
        {
            return Ok(Some(unit));
        }
        std::os::seraph::log!("{}: its remapping unit is not programmed; refused", name);
        Err(Refused)
    }

    /// Whether `pci_dev` would be confined: a unit translates it and the
    /// driver has not failed. No IPC; [`Self::confine`] decides.
    pub fn would_confine(&self, pci_dev: &pci::PciDevice) -> bool
    {
        let target = Bdf {
            bus: pci_dev.bus,
            device: pci_dev.dev,
            function: pci_dev.func,
        };
        let seg = pci_dev.segment;
        let drhd = dmar::unit_for(
            &self.dmar,
            seg,
            target,
            self.secondary_bus(seg),
            self.bus_range(seg),
        );
        drhd.is_some() && !self.client.failed()
    }

    /// Attach `pci_dev` to a domain of its own before its DMA grant, so its
    /// driver's mappings are confined to it: its confinement, unconfined
    /// when no unit translates it. Logged `Err` when it is refused: an RMRR
    /// names it, its unit is not programmed, the driver has failed, or the
    /// `ATTACH` fails.
    pub fn confine(&self, name: &str, pci_dev: &pci::PciDevice) -> Result<Confinement, Refused>
    {
        let Some(unit) = self.unit_of(name, pci_dev)?
        else
        {
            return Ok(Confinement::Unconfined);
        };
        let rid =
            iommu_labels::requester_id(pci_dev.segment, pci_dev.bus, pci_dev.dev, pci_dev.func);
        match self.client.attach(unit, rid)
        {
            Ok(handle) => Ok(Confinement::Domain {
                handle,
                limit: iova_limit(
                    self.client.width(unit),
                    pci_dev.vendor_id,
                    pci_dev.device_id,
                ),
            }),
            Err(code) =>
            {
                std::os::seraph::log!("{}: IOMMU ATTACH refused ({}); not spawned", name, code);
                Err(Refused)
            }
        }
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
fn take_and_log(client: &IommuClient, counts: &Mutex<FaultCounts>)
{
    let mut taken = Vec::new();
    let _ = client.take_faults(|rid, reason, iova| {
        if taken.try_reserve(1).is_ok()
        {
            taken.push((rid, reason, iova));
        }
    });
    let mut counts = counts.lock().unwrap_or_else(PoisonError::into_inner);
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

/// Copy the DMAR out of the firmware tables; `None` when there is none.
fn read_dmar(caps: &caps::DevmgrCaps) -> Option<Vec<u8>>
{
    let phys = crate::tables::locate_table_by_sig(caps, *b"DMAR")?;
    crate::tables::with_acpi_table(caps, phys, |t| {
        let mut v = Vec::new();
        v.try_reserve(t.len()).ok()?;
        v.extend_from_slice(t);
        Some(v)
    })
}

/// The units devmgr hands the driver, built from the DMAR: each unit's
/// carved register cap and bootstrap words, and each DRHD's unit index.
struct UnitRounds
{
    rounds: Vec<spawn::UnitRound>,
    unit_index: Vec<Option<usize>>,
}

/// Carve each DRHD's register cap and encode its unit round; a DRHD whose
/// register range no aperture covers, whose scope or register span exceeds
/// what a round carries, or past the driver's unit bound is not handed over
/// and its functions are refused.
fn unit_rounds(
    caps: &mut caps::DevmgrCaps,
    dmar_bytes: &[u8],
    bridges: &[(u16, Bdf, (u8, u8))],
) -> UnitRounds
{
    let mut out = UnitRounds {
        rounds: Vec::new(),
        unit_index: Vec::new(),
    };
    for unit in dmar::drhd_units(dmar_bytes)
    {
        if out.unit_index.try_reserve(1).is_err() || out.rounds.try_reserve(1).is_err()
        {
            break;
        }
        let seg = unit.segment;
        let mut scopes = Vec::new();
        let range = |b: Bdf| {
            bridges
                .iter()
                .find(|(s, f, _)| *s == seg && *f == b)
                .map(|e| e.2)
        };
        unit.resolve_scopes(
            dmar_bytes,
            |b| range(b).map(|r| r.0),
            range,
            |r| {
                if scopes.try_reserve(1).is_ok()
                {
                    scopes.push(match r
                    {
                        Resolved::Function(f) =>
                        {
                            Scope::Function(bdf_word(f.bus, f.device, f.function))
                        }
                        Resolved::Buses(first, last) => Scope::Buses { first, last },
                    });
                }
            },
        );
        let words = iommu_core::bootstrap::unit_round_words(
            seg,
            unit.include_pci_all,
            unit.register_pages,
            &scopes,
        );
        let handed = out.rounds.len() < iommu_core::bootstrap::MAX_UNITS;
        let cap = words.as_ref().filter(|_| handed).and_then(|_| {
            crate::carve_subrange(caps, unit.register_base, unit.register_pages * PAGE_SIZE)
        });
        if let (Some(words), Some(cap)) = (words, cap)
        {
            out.unit_index.push(Some(out.rounds.len()));
            out.rounds.push(spawn::UnitRound { cap, words });
        }
        else
        {
            std::os::seraph::log!(
                "VT-d unit at {:#x} not handed over; its devices are refused",
                unit.register_base
            );
            out.unit_index.push(None);
        }
    }
    out
}

/// Discover the remapping units, spawn the IOMMU driver over them, and
/// settle it; the [`Iommu`] once the driver reports ready, else `None`,
/// logged once, and every device then runs unconfined.
pub fn bring_up(
    devices: &[pci::PciDevice],
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
    let Some(dmar_bytes) = read_dmar(caps)
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
    let mut bridges = Vec::new();
    for d in devices
    {
        if let Some(range) = d.bridge_buses
            && bridges.try_reserve(1).is_ok()
        {
            let f = Bdf {
                bus: d.bus,
                device: d.dev,
                function: d.func,
            };
            bridges.push((d.segment, f, range));
        }
    }
    let units = unit_rounds(caps, &dmar_bytes, &bridges);
    if units.rounds.is_empty()
    {
        unconfined("no IOMMU unit can be programmed");
        return None;
    }
    let ep = spawn_and_settle(
        caps,
        module_guard,
        &units.rounds,
        watch,
        catalog,
        served,
        ipc_buf,
    );
    let Some(ep) = ep
    else
    {
        unconfined("IOMMU driver not ready");
        return None;
    };
    let mut client = IommuClient {
        ep,
        widths: Vec::new(),
        failed: AtomicBool::new(false),
    };
    let handed = units.unit_index.iter().flatten().count();
    if client.widths.try_reserve(handed).is_err()
    {
        unconfined("no memory for the IOMMU units");
        return None;
    }
    for unit in 0..handed
    {
        let msg = IommuClient::request(iommu_labels::QUERY_UNIT)
            .word(1, unit as u64)
            .build();
        let width = client
            .call(&msg)
            .map_or(0, |r| u8::try_from(r.word(0)).unwrap_or(0));
        client.widths.push(width);
    }
    let client = Arc::new(client);
    served.set_iommu(Arc::clone(&client));
    let faults = Arc::new(Mutex::new(FaultCounts::default()));
    start_fault_log(&client, &faults);
    std::os::seraph::log!("IOMMU: {} VT-d units translating", handed as u64);
    Some(Iommu {
        client,
        dmar: dmar_bytes,
        unit_index: units.unit_index,
        bridges,
        faults,
    })
}

/// Spawn the IOMMU driver from its module, which `module_guard` holds, over
/// `rounds` in a settle batch of its own and settle it; the driver's service
/// endpoint when it reported ready.
fn spawn_and_settle(
    caps: &caps::DevmgrCaps,
    mut module_guard: spawn::ModuleCapGuard,
    rounds: &[spawn::UnitRound],
    watch: &mut settle::DriverWatch,
    catalog: &mut DeviceCatalog,
    served: &mut ServedDrivers,
    ipc_buf: *mut u64,
) -> Option<u64>
{
    let release = |rounds: &[spawn::UnitRound]| {
        for r in rounds
        {
            let _ = syscall::cap_delete(r.cap);
        }
    };
    let batch = settle::SettleBatch::new();
    let badge = catalog.add_without_info();
    let ep = crate::create_service_endpoint();
    let mut roster = firmware::roster::Roster::new();
    let (Some(batch), Some(device_badge), Some(ep), Ok(())) =
        (batch, badge, ep, roster.try_reserve_one())
    else
    {
        std::os::seraph::log!("IOMMU driver: no settle batch, badge, or endpoint; not spawned");
        release(rounds);
        return None;
    };
    // `spawn_iommu_driver` owns the module cap's lifecycle from here
    // (consumed by CREATE_PROCESS, or released on failure).
    module_guard.disarm();
    let config = spawn::IommuSpawnConfig {
        procmgr_ep: caps.procmgr_ep,
        bootstrap_ep: caps.self_bootstrap_ep,
        module_cap: caps.module_cap_for_kind(caps::module_kind::IOMMU),
        units: rounds,
        service_ep: ep,
        query_ep: batch.driver_ep(),
        death_eq: watch.death_eq(),
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
            spawn::destroy_child(h, ipc_buf);
            let _ = syscall::cap_delete(ep);
            return None;
        }
        spawn::DriverSpawn::Failed =>
        {
            let _ = syscall::cap_delete(ep);
            return None;
        }
    };
    let spawned = SpawnedDriver {
        class: DriverClass::Iommu,
        badge: device_badge,
        driver: ServedDriver {
            ep,
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
    served.take_iommu_ep()
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

/// Whether `pci_dev` is QEMU's `edu` DMA test device.
pub fn is_edu(pci_dev: &pci::PciDevice) -> bool
{
    (pci_dev.vendor_id, pci_dev.device_id) == EDU_ID
}

/// The requester ID of `pci_dev`.
pub fn requester_id(pci_dev: &pci::PciDevice) -> u64
{
    iommu_labels::requester_id(pci_dev.segment, pci_dev.bus, pci_dev.dev, pci_dev.func)
}
