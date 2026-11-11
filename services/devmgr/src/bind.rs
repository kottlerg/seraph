// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/devmgr/src/bind.rs

//! Binding PCI records to the drivers whose declarations match them, and
//! taking a device back from its driver
//! ([docs/driver-binding.md](../../../docs/driver-binding.md) § Matching,
//! § Binding).
//!
//! Two passes bind: the boot pass, over the declarations of the boot modules
//! devmgr holds, in the boot settle batch; and the drivers-directory pass,
//! over the declarations of the `/services/drivers/` entries, once svcmgr
//! hands devmgr that directory. Each pass collects the declarations that
//! match a record no driver is bound to ([`crate::decls`]) into a
//! [`MatchTable`], walks the records in record order, and binds each to the
//! declaration the table chooses ([`bind_pci`]). A record is bound at most
//! once a boot: once a driver was started for it.
//!
//! No step names a driver. What a bound driver is given follows from its
//! declaration (its interrupt need, whether it performs DMA, its reset, its
//! tier, within the bounds of its source) and from the record (its BARs, its
//! wired line, and, for a function that presents the `VirtIO` register
//! layout, that layout).

use driver_binding::decl::{DriverDecl, InterruptNeed, Reset, Tier};
use driver_binding::resources::{InterruptKind, Resource};
use firmware::aml::CrsResource;
use firmware::binding::{
    Candidate, Choice, MatchTable, PciIdentity, RecordKeys, Source, class_admits,
};
use firmware::classes::Classes;
use firmware::dma::Confinement;
use firmware::lines::{HoldError, LineError};
use firmware::records::{PlatformRecord, PlatformRecords};
use firmware::resource::{CarveError, Span, SplitError};
use firmware::roster::Roster;
use syscall_abi::PAGE_SIZE;

use crate::decls::{self, Binary};
use crate::spawn::{self, MAX_BOUND_RESOURCES};
use crate::{
    DeviceCatalog, IrqRangeAllocator, ServedDriver, Serves, SpawnedDriver, arch, caps, dma, pci,
    settle,
};

// ── Records ─────────────────────────────────────────────────────────────────

/// The PCI functions the ECAM walk found, in record order (segment, bus,
/// device, function), and which of them a driver has been started for.
pub struct PciRecords
{
    devices: Vec<pci::PciDevice>,
    bound: Vec<bool>,
}

impl PciRecords
{
    /// The records of `devices`, sorted into record order, none bound;
    /// `None` when the bound flags cannot be allocated.
    pub fn new(mut devices: Vec<pci::PciDevice>) -> Option<Self>
    {
        devices.sort_unstable_by_key(|d| (d.segment, d.bus, d.dev, d.func));
        let mut bound = Vec::new();
        bound.try_reserve_exact(devices.len()).ok()?;
        bound.resize(devices.len(), false);
        Some(Self { devices, bound })
    }

    /// Every record, in record order.
    pub fn devices(&self) -> &[pci::PciDevice]
    {
        &self.devices
    }

    /// Whether `decl`, from `source`, matches a record no driver is bound
    /// to.
    fn matches_unbound(&self, decl: &DriverDecl, source: Source) -> bool
    {
        self.devices.iter().zip(&self.bound).any(|(d, &bound)| {
            !bound && firmware::binding::decl_rank(decl, source, &keys(d)).is_some()
        })
    }
}

/// Every device record a bind pass walks, in record order: the PCI records,
/// then the platform records ([`crate::platform`]), and which of them a
/// driver has been started for.
pub struct Records
{
    pub pci: PciRecords,
    platform: PlatformRecords,
    platform_bound: Vec<bool>,
}

impl Records
{
    /// The PCI and platform records, none bound; `None` when the bound flags
    /// cannot be allocated.
    pub fn new(pci: PciRecords, platform: PlatformRecords) -> Option<Self>
    {
        let mut platform_bound = Vec::new();
        platform_bound
            .try_reserve_exact(platform.records().len())
            .ok()?;
        platform_bound.resize(platform.records().len(), false);
        Some(Self {
            pci,
            platform,
            platform_bound,
        })
    }

    /// The number of records, PCI and platform: the most drivers the bind
    /// passes can start, each record being bound at most once.
    pub fn count(&self) -> usize
    {
        self.pci.devices.len() + self.platform_bound.len()
    }

    /// Whether `decl`, from `source`, matches a record no driver is bound
    /// to.
    fn matches_unbound(&self, decl: &DriverDecl, source: Source) -> bool
    {
        self.pci.matches_unbound(decl, source)
            || self
                .platform
                .records()
                .iter()
                .zip(&self.platform_bound)
                .any(|(r, &bound)| {
                    !bound
                        && r.with_keys(|k| firmware::binding::decl_rank(decl, source, k))
                            .is_some()
                })
    }

    /// Whether every record has a driver.
    fn all_bound(&self) -> bool
    {
        self.pci
            .bound
            .iter()
            .chain(&self.platform_bound)
            .all(|&b| b)
    }
}

/// The identity keys of a PCI record.
fn keys(pci_dev: &pci::PciDevice) -> RecordKeys<'static>
{
    RecordKeys {
        pci: Some(PciIdentity {
            vendor: pci_dev.vendor_id,
            device: pci_dev.device_id,
            class_code: pci_dev.class_code,
        }),
        ..RecordKeys::default()
    }
}

// ── Passes ──────────────────────────────────────────────────────────────────

/// The settle batch a pass starts its drivers into, and the roster that
/// records them.
pub struct Pass<'a>
{
    pub batch: &'a settle::SettleBatch,
    pub death_eq: u64,
    pub roster: &'a mut Roster<SpawnedDriver>,
}

/// What a bind carves from and records into: devmgr's held caps, its
/// interrupt lines, and the device catalog.
pub struct Carve<'a>
{
    pub caps: &'a mut caps::DevmgrCaps,
    pub irq_range: &'a mut IrqRangeAllocator,
    pub catalog: &'a mut DeviceCatalog,
}

/// The boot pass: bind the unbound records to the declarations of `modules`,
/// the declared boot modules the IOMMU pass left ([`decls::BootModules`]),
/// and release every module cap, which would otherwise pin the pool run init
/// donated it from.
pub fn boot_pass(
    records: &mut Records,
    modules: Vec<(DriverDecl, u64)>,
    carve: &mut Carve,
    pass: &mut Pass,
    ipc_buf: *mut u64,
)
{
    let mut table = MatchTable::new();
    for (decl, module) in modules
    {
        collect(
            &mut table,
            records,
            Some(&decl),
            Source::BootModule,
            Binary::Module(module),
        );
    }
    bind_records(records, &mut table, carve, pass, ipc_buf);
    for binary in table.drain_binaries()
    {
        binary.release();
    }
}

/// The drivers-directory pass: list `dir_cap`, the `/services/drivers/`
/// directory svcmgr handed devmgr, read the declaration of each entry, and
/// bind the records still unbound to them. A declaration of a class
/// `classes` marks boot-only is not considered, logged
/// ([`firmware::binding::class_admits`]). Every file cap is released once
/// the pass ends.
pub fn drivers_dir_pass<T>(
    records: &mut Records,
    dir_cap: u64,
    classes: &Classes<T>,
    carve: &mut Carve,
    pass: &mut Pass,
    ipc_buf: *mut u64,
)
{
    if records.all_bound()
    {
        return;
    }
    let mut table = MatchTable::new();
    let requested_rights = u64::from(namespace_protocol::rights::READ);
    decls::list_dir(dir_cap, ipc_buf, |name| {
        // SAFETY: `ipc_buf` is devmgr's registered IPC buffer.
        let walked = unsafe { ns_client::walk_to_file(dir_cap, name, requested_rights, ipc_buf) };
        let Some(walked) = walked
        else
        {
            return;
        };
        let label = core::str::from_utf8(name).unwrap_or("drivers-directory entry");
        let mut decl = decls::file_decl(label, walked.file_cap, walked.size, ipc_buf);
        if let Some(d) = decl.filter(|d| !class_admits(classes, d, Source::DriversDir))
        {
            std::os::seraph::log!(
                "{}: declares boot-only class {}; not considered",
                d.name.as_str(),
                d.class.as_ref().map_or("", |c| c.as_str())
            );
            decl = None;
        }
        let binary = Binary::File {
            cap: walked.file_cap,
            size: walked.size,
        };
        collect(
            &mut table,
            records,
            decl.as_ref(),
            Source::DriversDir,
            binary,
        );
    });
    bind_records(records, &mut table, carve, pass, ipc_buf);
    for binary in table.drain_binaries()
    {
        binary.release();
    }
}

/// Add `decl`, read from `binary`, to `table` when it matches a record no
/// driver is bound to; otherwise release `binary`.
fn collect(
    table: &mut MatchTable<Binary>,
    records: &Records,
    decl: Option<&DriverDecl>,
    source: Source,
    binary: Binary,
)
{
    let Some(&decl) = decl.filter(|d| records.matches_unbound(d, source))
    else
    {
        binary.release();
        return;
    };
    let name = decl.name;
    if table.add(decl, source, binary).is_err()
    {
        std::os::seraph::log!(
            "{}: no memory to consider the driver; not bound",
            name.as_str()
        );
        binary.release();
    }
}

/// Bind each record no driver is bound to, in record order, to the
/// declaration `table` chooses for it.
fn bind_records(
    records: &mut Records,
    table: &mut MatchTable<Binary>,
    carve: &mut Carve,
    pass: &mut Pass,
    ipc_buf: *mut u64,
)
{
    if table.is_empty()
    {
        return;
    }
    bind_pci_records(&mut records.pci, table, carve, pass, ipc_buf);
    let platform = records.platform.records();
    for (index, (record, bound)) in platform
        .iter()
        .zip(records.platform_bound.iter_mut())
        .enumerate()
    {
        if *bound
        {
            continue;
        }
        match record.with_keys(|k| table.choose(k))
        {
            Choice::Unmatched =>
            {}
            Choice::Conflict(first, second) =>
            {
                let candidates = table.candidates();
                std::os::seraph::log!(
                    "platform record {}: {} and {} match it equally; neither bound",
                    index,
                    candidates[first].decl.name.as_str(),
                    candidates[second].decl.name.as_str()
                );
            }
            Choice::Bind(chosen) =>
            {
                if bind_platform(
                    index,
                    record,
                    &table.candidates()[chosen],
                    carve,
                    pass,
                    ipc_buf,
                )
                {
                    *bound = true;
                    table.note_bound(chosen);
                }
            }
        }
    }
}

/// [`bind_records`] over the PCI records.
fn bind_pci_records(
    records: &mut PciRecords,
    table: &mut MatchTable<Binary>,
    carve: &mut Carve,
    pass: &mut Pass,
    ipc_buf: *mut u64,
)
{
    for (pci_dev, bound) in records.devices.iter().zip(records.bound.iter_mut())
    {
        if *bound
        {
            continue;
        }
        match table.choose(&keys(pci_dev))
        {
            Choice::Unmatched =>
            {}
            Choice::Conflict(first, second) =>
            {
                let candidates = table.candidates();
                std::os::seraph::log!(
                    "PCI {}:{}:{}.{}: {} and {} match it equally; neither bound",
                    pci_dev.segment,
                    pci_dev.bus,
                    pci_dev.dev,
                    pci_dev.func,
                    candidates[first].decl.name.as_str(),
                    candidates[second].decl.name.as_str()
                );
            }
            Choice::Bind(index) =>
            {
                if bind_pci(pci_dev, &table.candidates()[index], carve, pass, ipc_buf)
                {
                    *bound = true;
                    table.note_bound(index);
                }
            }
        }
    }
}

// ── Binding one platform record ─────────────────────────────────────────────

/// Bind platform record `index`, `record`, to the driver of `candidate`:
/// carve its resources ([`carve_platform_device`]), start the driver from a
/// copy of its binary at the tier its source allows, deliver it the
/// resource list, and record it in the pass's roster to be served under its
/// declared class. Returns whether the driver was started; `false`, logged,
/// as for [`bind_pci`].
fn bind_platform(
    index: usize,
    record: &PlatformRecord,
    candidate: &Candidate<Binary>,
    carve: &mut Carve,
    pass: &mut Pass,
    ipc_buf: *mut u64,
) -> bool
{
    let decl = &candidate.decl;
    let name = decl.name.as_str();
    std::os::seraph::log!("{}: binds platform record {}", name, index);
    let Some(class) = decl.class
    else
    {
        std::os::seraph::log!("{}: declares no device class; not bound", name);
        return false;
    };
    // No platform record is an IOMMU record, and none has a `Dma` resource:
    // neither physical access nor a DMA capability is granted here.
    let grants = firmware::binding::grants(decl, candidate.source, false);
    if grants.tier_ignored
    {
        std::os::seraph::log!("{}: boot tier not granted from the drivers directory", name);
    }
    if grants.phys_access_ignored
    {
        std::os::seraph::log!("{}: physical access not granted", name);
    }
    if decl.dma
    {
        std::os::seraph::log!("{}: the record has no DMA resource; no DMA granted", name);
    }
    if pass.roster.try_reserve_one().is_err()
    {
        std::os::seraph::log!("{}: no memory to record the driver; not bound", name);
        return false;
    }
    let Some(dev_caps) = carve_platform_device(name, record, decl, carve)
    else
    {
        return false;
    };
    let Some(service_ep) = crate::create_service_endpoint()
    else
    {
        std::os::seraph::log!("{}: no service endpoint; not bound", name);
        dev_caps.release();
        return false;
    };
    let Some(source) = candidate.binary.source_copy()
    else
    {
        std::os::seraph::log!("{}: binary cap not copied; not bound", name);
        let _ = syscall::cap_delete(service_ep);
        dev_caps.release();
        return false;
    };
    let config = spawn::BoundSpawnConfig {
        procmgr_ep: carve.caps.procmgr_ep,
        bootstrap_ep: carve.caps.self_bootstrap_ep,
        source,
        resources: dev_caps.resources(),
        dma_cap: None,
        service_ep,
        query_ep: pass.batch.driver_ep(),
        death_eq: pass.death_eq,
        device_badge: dev_caps.device_badge,
        priority: match grants.tier
        {
            Tier::Boot => ipc::sched_policy::BOOT_DRIVER_PRIORITY,
            Tier::Auxiliary => ipc::sched_policy::AUX_DRIVER_PRIORITY,
        },
    };
    match spawn::spawn_bound_driver(&config, ipc_buf)
    {
        spawn::DriverSpawn::Bootstrapped(child) =>
        {
            let spawned = SpawnedDriver {
                name: decl.name,
                serves: Serves::Class(class),
                badge: dev_caps.device_badge,
                driver: ServedDriver {
                    ep: service_ep,
                    dev_caps: None,
                    platform_caps: Some(dev_caps),
                    process_handle: child.process_handle,
                },
            };
            crate::record_spawned(pass.roster, spawned, ipc_buf);
        }
        spawn::DriverSpawn::Unbootstrapped(child) =>
        {
            dev_caps.take_from_driver();
            spawn::destroy_child(child.process_handle, ipc_buf);
            let _ = syscall::cap_delete(service_ep);
            dev_caps.release();
        }
        spawn::DriverSpawn::Failed =>
        {
            let _ = syscall::cap_delete(service_ep);
            dev_caps.release();
            return false;
        }
    }
    true
}

/// Carve what the driver `decl` declares of the platform record `record`: a
/// cap on each `Mmio` and `IoPort` resource, the record's first interrupt
/// line, exclusive, for a driver that takes an interrupt
/// (docs/driver-binding.md § Declaration Bounds: only a PCI function's line
/// is shared), and the record's catalog entry, carrying its device info.
/// `None`, logged under `name` and with what was carved released, on any
/// failure, a required interrupt the record cannot give included.
fn carve_platform_device(
    name: &str,
    record: &PlatformRecord,
    decl: &DriverDecl,
    carve: &mut Carve,
) -> Option<PlatformDeviceCaps>
{
    let mut dev = PlatformDeviceCaps::empty();
    for resource in record.resources()
    {
        let carved = match resource
        {
            CrsResource::Mmio { base, size } =>
            {
                crate::carve_subrange(carve.caps, base, size).map(|cap| Resource::Mmio {
                    cap,
                    bar: None,
                    phys: base,
                    bytes: size,
                })
            }
            CrsResource::IoPort { base, count } =>
            {
                arch::current::carve_io_ports(carve.caps, base, count).map(|cap| Resource::IoPort {
                    cap,
                    base: u64::from(base),
                    count: u64::from(count),
                })
            }
            CrsResource::Interrupt { .. } => continue,
        };
        let Some(carved) = carved
        else
        {
            std::os::seraph::log!(
                "{}: a register range of the record not carved; not bound",
                name
            );
            dev.release();
            return None;
        };
        if !dev.push(carved)
        {
            std::os::seraph::log!(
                "{}: more resources than a driver is delivered; not bound",
                name
            );
            dev.release();
            return None;
        }
    }
    match platform_wired(name, record, decl, carve)
    {
        Some((cap, mode)) =>
        {
            if !dev.push(Resource::Interrupt {
                cap,
                kind: InterruptKind::Wired,
                vector: 0,
                mode,
            })
            {
                std::os::seraph::log!("{}: no room for the interrupt; not bound", name);
                dev.release();
                return None;
            }
        }
        None if decl.interrupt.need == InterruptNeed::Required =>
        {
            std::os::seraph::log!(
                "{}: no interrupt line for the device, which the driver requires; not bound",
                name
            );
            dev.release();
            return None;
        }
        None =>
        {}
    }
    let badge = match record.info()
    {
        Some(info) => carve.catalog.add(info.kind, info.version, info.bytes()),
        None => carve.catalog.add_without_info(),
    };
    let Some(badge) = badge
    else
    {
        std::os::seraph::log!("{}: catalog entry not added; not bound", name);
        dev.release();
        return None;
    };
    dev.device_badge = badge;
    Some(dev)
}

/// The cap on the first interrupt line of `record`, carved exclusive, and
/// the line's mode, for a driver `decl` that takes an interrupt; `None` when
/// it takes none, the record has no line, or the line cannot be carved
/// (logged under `name`).
fn platform_wired(
    name: &str,
    record: &PlatformRecord,
    decl: &DriverDecl,
    carve: &mut Carve,
) -> Option<(u64, u64)>
{
    if decl.interrupt.need == InterruptNeed::None
    {
        return None;
    }
    let (line, mode, isa) = record.resources().find_map(|r| match r
    {
        CrsResource::Interrupt {
            line, mode, isa, ..
        } => Some((line, mode, isa)),
        _ => None,
    })?;
    let (gsi, mode) = arch::current::platform_line(carve.irq_range, line, mode, isa);
    match carve.irq_range.exclusive_line(gsi)
    {
        Ok(cap) => Some((cap, mode)),
        Err(e) =>
        {
            std::os::seraph::log!("{}: no IRQ cap for line {:#x} ({:?})", name, gsi, e);
            None
        }
    }
}

/// The caps devmgr keeps for a platform record it bound a driver to: the
/// resources it delivered, each the cap the driver's copy derives from, and
/// the device's badge. A platform device has no configuration page, no DMA,
/// and no reset: withdrawing its driver revokes the driver's copies.
pub struct PlatformDeviceCaps
{
    resources: [Resource; MAX_BOUND_RESOURCES],
    count: usize,
    pub device_badge: u64,
}

impl PlatformDeviceCaps
{
    /// Nothing carved yet.
    fn empty() -> Self
    {
        Self {
            resources: [Resource::IoPort {
                cap: 0,
                base: 0,
                count: 0,
            }; MAX_BOUND_RESOURCES],
            count: 0,
            device_badge: 0,
        }
    }

    /// Record a carved resource; `false`, the cap deleted, when
    /// [`MAX_BOUND_RESOURCES`] are already held.
    fn push(&mut self, resource: Resource) -> bool
    {
        if let Some(slot) = self.resources.get_mut(self.count)
        {
            *slot = resource;
            self.count += 1;
            true
        }
        else
        {
            let _ = syscall::cap_delete(resource.cap());
            false
        }
    }

    /// The delivered resources, in delivery order.
    pub fn resources(&self) -> &[Resource]
    {
        &self.resources[..self.count]
    }

    /// Take the device from its driver, live or dead: revoke every copy
    /// derived from the caps devmgr keeps, so the driver reaches its
    /// registers and line no more.
    pub fn take_from_driver(&self)
    {
        for resource in self.resources()
        {
            let _ = syscall::cap_revoke_all(resource.cap());
        }
    }

    /// Release every cap devmgr keeps for the device.
    pub fn release(&self)
    {
        for resource in self.resources()
        {
            let _ = syscall::cap_delete(resource.cap());
        }
    }
}

// ── Binding one PCI record ──────────────────────────────────────────────────

/// Bind the PCI function `pci_dev` to the driver of `candidate`: carve its
/// resources ([`carve_pci_device`]), start the driver from a copy of its
/// binary at the tier its source allows, deliver it the resource list
/// ([`spawn::spawn_bound_driver`]), and record it in the pass's roster to be
/// served under its declared class when its batch settles. Returns whether
/// the driver was started; `false`, logged, when the declaration names no
/// class, a resource cannot be carved, a required interrupt cannot be had,
/// or the spawn fails before the start.
fn bind_pci(
    pci_dev: &pci::PciDevice,
    candidate: &Candidate<Binary>,
    carve: &mut Carve,
    pass: &mut Pass,
    ipc_buf: *mut u64,
) -> bool
{
    let decl = &candidate.decl;
    let name = decl.name.as_str();
    std::os::seraph::log!(
        "{}: binds PCI {}:{}:{}.{} ({:04x}:{:04x})",
        name,
        pci_dev.segment,
        pci_dev.bus,
        pci_dev.dev,
        pci_dev.func,
        pci_dev.vendor_id,
        pci_dev.device_id
    );
    let Some(class) = decl.class
    else
    {
        std::os::seraph::log!("{}: declares no device class; not bound", name);
        return false;
    };
    // No PCI record is an IOMMU record: physical access is never granted
    // here.
    let grants = firmware::binding::grants(decl, candidate.source, false);
    if grants.tier_ignored
    {
        std::os::seraph::log!("{}: boot tier not granted from the drivers directory", name);
    }
    if grants.phys_access_ignored
    {
        std::os::seraph::log!("{}: physical access not granted", name);
    }
    if pass.roster.try_reserve_one().is_err()
    {
        std::os::seraph::log!("{}: no memory to record the driver; not bound", name);
        return false;
    }
    let Some(mut dev_caps) = carve_pci_device(name, pci_dev, decl, carve)
    else
    {
        return false;
    };
    let Some(service_ep) = crate::create_service_endpoint()
    else
    {
        std::os::seraph::log!("{}: no service endpoint; not bound", name);
        dev_caps.release();
        return false;
    };
    let Some(source) = candidate.binary.source_copy()
    else
    {
        std::os::seraph::log!("{}: binary cap not copied; not bound", name);
        let _ = syscall::cap_delete(service_ep);
        dev_caps.release();
        return false;
    };
    let config = spawn::BoundSpawnConfig {
        procmgr_ep: carve.caps.procmgr_ep,
        bootstrap_ep: carve.caps.self_bootstrap_ep,
        source,
        resources: dev_caps.resources(),
        dma_cap: dev_caps.dma.as_ref().map(dma::DmaGrant::cap),
        service_ep,
        query_ep: pass.batch.driver_ep(),
        death_eq: pass.death_eq,
        // Index-derived, not random like the cross-boundary service badges
        // (#249): it names the device's catalog slot, which the driver
        // enforces per registered device.
        device_badge: dev_caps.device_badge,
        priority: match grants.tier
        {
            Tier::Boot => ipc::sched_policy::BOOT_DRIVER_PRIORITY,
            Tier::Auxiliary => ipc::sched_policy::AUX_DRIVER_PRIORITY,
        },
    };
    // `spawn_bound_driver` owns the binary copy from here (consumed by the
    // create call, or released on failure).
    match spawn::spawn_bound_driver(&config, ipc_buf)
    {
        spawn::DriverSpawn::Bootstrapped(child) =>
        {
            dev_caps.release_token = child.release_token;
            let spawned = SpawnedDriver {
                name: decl.name,
                serves: Serves::Class(class),
                badge: dev_caps.device_badge,
                driver: ServedDriver {
                    ep: service_ep,
                    dev_caps: Some(dev_caps),
                    platform_caps: None,
                    process_handle: child.process_handle,
                },
            };
            crate::record_spawned(pass.roster, spawned, ipc_buf);
        }
        spawn::DriverSpawn::Unbootstrapped(child) =>
        {
            withdraw_device(&dev_caps, child, ipc_buf);
            let _ = syscall::cap_delete(service_ep);
            dev_caps.release();
        }
        spawn::DriverSpawn::Failed =>
        {
            let _ = syscall::cap_delete(service_ep);
            dev_caps.release();
            return false;
        }
    }
    true
}

/// Carve what the driver `decl` declares of the PCI function `pci_dev`, and
/// turn the function on for it: a cap on each of its MMIO BARs (for a
/// function that presents the `VirtIO` register layout, the BARs the layout
/// names, each clipped to the pages its regions reach; otherwise every MMIO
/// BAR, whole), its wired line for a driver that takes an interrupt, its
/// configuration page, its catalog entry (the `VirtIO` startup info, or none),
/// its DMA grant for a DMA declaration ([`grant_dma`]), the target of its
/// declared reset, and the Command register written for the bind
/// ([`FunctionConfig::prepare_for_bind`]). `None`, logged under `name` and
/// with what was carved released, on any failure, a required interrupt the
/// function cannot be given included.
///
/// Message-signaled vectors are not delivered: a driver is given the wired
/// line only, whatever vectors it declares.
fn carve_pci_device(
    name: &str,
    pci_dev: &pci::PciDevice,
    decl: &DriverDecl,
    carve: &mut Carve,
) -> Option<PciDeviceCaps>
{
    // A driver that declares the VirtIO status reset drives the VirtIO
    // register layout; a function that presents no complete layout (one of
    // the four regions missing, VirtIO 1.2 § 4.1.4, or a common region too
    // short for the registers the transport addresses) could neither be set
    // up by it nor reset when it is withdrawn.
    if decl.reset == Reset::VirtioStatus && pci_dev.virtio_info.register_layout().is_none()
    {
        std::os::seraph::log!(
            "{}: the device presents no complete VirtIO register layout; not bound",
            name
        );
        return None;
    }
    let mut dev = PciDeviceCaps::empty(carve.caps.self_aspace, crate::iommu::requester_id(pci_dev));
    if carve_bars(name, pci_dev, carve.caps, &mut dev).is_none()
    {
        dev.release();
        return None;
    }
    let wired = if decl.interrupt.need == InterruptNeed::None
    {
        None
    }
    else
    {
        acquire_single_irq_cap(pci_dev, carve.irq_range)
    };
    if let Some(cap) = wired
    {
        let mode = device_gsi(pci_dev).map_or(0, |gsi| carve.irq_range.line_mode(gsi));
        dev.push(Resource::Interrupt {
            cap,
            kind: InterruptKind::Wired,
            vector: 0,
            mode,
        });
    }
    else if decl.interrupt.need == InterruptNeed::Required
    {
        std::os::seraph::log!(
            "{}: no interrupt line for the device, which the driver requires; not bound",
            name
        );
        dev.release();
        return None;
    }
    let Some(config) = carve_function_config(name, pci_dev, carve.caps)
    else
    {
        dev.release();
        return None;
    };
    dev.config = config;
    let Some(badge) = catalog_entry(pci_dev, carve.catalog)
    else
    {
        std::os::seraph::log!("{}: catalog entry not added; not bound", name);
        dev.release();
        return None;
    };
    dev.device_badge = badge;
    if decl.dma
    {
        let Some(grant) = grant_dma(name, pci_dev, decl.dma_width, carve.caps, badge)
        else
        {
            dev.release();
            return None;
        };
        dev.dma = Some(grant);
    }
    dev.reset = match decl.reset
    {
        Reset::None => StopReset::None,
        Reset::PcieFlr => StopReset::Flr,
        Reset::VirtioStatus =>
        {
            let reset =
                DeviceReset::for_device(&pci_dev.virtio_info, dev.resources(), dev.config.aspace);
            if reset.is_none()
            {
                std::os::seraph::log!(
                    "{}: the device offers no VirtIO status register to reset it by",
                    name
                );
            }
            reset.map_or(StopReset::None, StopReset::Virtio)
        }
    };
    if !dev.config.prepare_for_bind(decl.dma, wired.is_some())
    {
        std::os::seraph::log!("{}: configuration page not mapped; not bound", name);
        dev.release();
        return None;
    }
    Some(dev)
}

/// Add `pci_dev`'s catalog entry and return its device badge: the `VirtIO`
/// startup info for a function that presents the `VirtIO` register layout,
/// no startup info otherwise. `None` when the catalog cannot hold it.
fn catalog_entry(pci_dev: &pci::PciDevice, catalog: &mut DeviceCatalog) -> Option<u64>
{
    if pci_dev.virtio_info.register_layout().is_none()
    {
        return catalog.add_without_info();
    }
    // The startup info is stored opaquely; the driver deserialises it from
    // its `QUERY_DEVICE_INFO` reply after checking its kind and version.
    let mut buf = [0u8; virtio_core::VirtioPciStartupInfo::SIZE];
    pci_dev.virtio_info.to_bytes(&mut buf).and_then(|()| {
        catalog.add(
            ipc::device_info_kind::VIRTIO_PCI,
            virtio_core::VIRTIO_PCI_INFO_VERSION,
            &buf,
        )
    })
}

/// Carve a cap on each MMIO BAR of `pci_dev` the bind delivers into `dev`
/// ([`carve_pci_device`]); `None`, logged, when a BAR the `VirtIO` layout
/// names is not an MMIO BAR or no aperture covers a BAR. I/O BARs are not
/// delivered.
fn carve_bars(
    name: &str,
    pci_dev: &pci::PciDevice,
    caps: &mut caps::DevmgrCaps,
    dev: &mut PciDeviceCaps,
) -> Option<()>
{
    let mut carve_one = |b: usize, bytes: u64| {
        let index = pci_dev.bar_pci_idx[b];
        let phys = pci_dev.bar_phys[b];
        std::os::seraph::log!(
            "{}: BAR {} phys={:#018x} size={:#018x}",
            name,
            index,
            phys,
            bytes
        );
        let Some(cap) = crate::carve_subrange(caps, phys, bytes)
        else
        {
            std::os::seraph::log!(
                "{}: BAR {} not covered by any aperture; not bound",
                name,
                index
            );
            return None;
        };
        dev.push(Resource::Mmio {
            cap,
            bar: Some(index),
            phys,
            bytes,
        });
        Some(())
    };
    let mmio = |b: &usize| pci_dev.bar_is_mmio[*b];
    if let Some(layout) = pci_dev.virtio_info.register_layout()
    {
        for aperture in layout.bars()
        {
            let Some(b) = (0..pci_dev.bar_count)
                .filter(mmio)
                .find(|&b| pci_dev.bar_pci_idx[b] == aperture.bar)
            else
            {
                std::os::seraph::log!(
                    "{}: VirtIO BAR {} is not an MMIO BAR; not bound",
                    name,
                    aperture.bar
                );
                return None;
            };
            // The driver maps the BAR into `aperture.pages` pages of its
            // register window and `mmio_map` maps the whole cap, so the cap
            // covers no more of the BAR than the regions in it reach.
            carve_one(b, pci_dev.bar_size[b].min(aperture.pages * PAGE_SIZE))?;
        }
    }
    else
    {
        for b in (0..pci_dev.bar_count).filter(mmio)
        {
            carve_one(b, pci_dev.bar_size[b])?;
        }
    }
    Some(())
}

/// Give the device `pci_dev`, catalogued as `device_badge`, its DMA grant:
/// first attach it to an IOMMU domain of its own when a remapping unit
/// translates it ([`crate::iommu::Iommu::confine`]), within the DMA address
/// width `dma_width` its driver declares, so it reaches nothing
/// its driver has not mapped but the regions the firmware reserves for it,
/// which the domain maps at their own addresses and no mapping's IOVA
/// overlaps. `None`, logged under `name`, when the device is refused (its
/// unit is not programmed, its reserved regions cannot be mapped, or its
/// `ATTACH` fails) or the grant fails; an attached device is blocked again
/// then.
fn grant_dma(
    name: &str,
    pci_dev: &pci::PciDevice,
    dma_width: Option<u8>,
    caps: &caps::DevmgrCaps,
    device_badge: u64,
) -> Option<dma::DmaGrant>
{
    let (confinement, reserved) = match caps.iommu.as_ref()
    {
        Some(i) => i.confine(name, pci_dev, dma_width).ok()?,
        None => (Confinement::Unconfined, Vec::new()),
    };
    let grant = caps
        .dma
        .as_ref()
        .and_then(|d| d.grant(device_badge, confinement, &reserved));
    if grant.is_none()
    {
        std::os::seraph::log!("{}: no DMA grant; not bound", name);
        if let (Confinement::Domain { handle, .. }, Some(i)) = (confinement, caps.iommu.as_ref())
        {
            i.client().block(handle);
        }
    }
    grant
}

/// A PCI device's own single-line `Interrupt` cap: a derivation of the held
/// cap of its GSI's line ([`IrqRangeAllocator::line_cap`]), so a device whose
/// line another device already holds gets one too. `None`, logged, when the
/// device names no line or no cap can be had for it.
fn acquire_single_irq_cap(
    pci_dev: &pci::PciDevice,
    irq_range: &mut IrqRangeAllocator,
) -> Option<u64>
{
    let gsi = device_gsi(pci_dev)?;
    match irq_range.line_cap(gsi)
    {
        Ok(cap) =>
        {
            std::os::seraph::log!(
                "IRQ cap for GSI {:#x}, mode {:#x}",
                u64::from(gsi),
                irq_range.line_mode(gsi)
            );
            Some(cap)
        }
        Err(LineError::Hold(HoldError::Split(CarveError::NotCovered))) =>
        {
            std::os::seraph::log!(
                "GSI {:#x} not in the held IRQ range (or no range); no IRQ cap",
                u64::from(gsi)
            );
            None
        }
        Err(e) =>
        {
            std::os::seraph::log!("no IRQ cap for GSI {:#x} ({:?})", u64::from(gsi), e);
            None
        }
    }
}

/// The GSI of a PCI device: the firmware-programmed config-space IRQ line
/// when one is set, else the arch `INTx` routing fallback
/// ([`arch::current::intx_fallback_gsi`]).
fn device_gsi(pci_dev: &pci::PciDevice) -> Option<u32>
{
    if pci_dev.irq_line != 0 && pci_dev.irq_line != 0xFF
    {
        return Some(u32::from(pci_dev.irq_line));
    }
    arch::current::intx_fallback_gsi(pci_dev.irq_pin, pci_dev.dev)
}

/// Carve the `Mmio` cap of `pci_dev`'s configuration page out of the kept
/// ECAM windows. Returns `None`, logged under `name`, when no kept window
/// decodes the function or the carve fails.
pub fn carve_function_config(
    name: &str,
    pci_dev: &pci::PciDevice,
    caps: &mut caps::DevmgrCaps,
) -> Option<FunctionConfig>
{
    let carved = firmware::pci::function_config_phys(
        &caps.ecam_windows,
        pci_dev.segment,
        pci_dev.bus,
        pci_dev.dev,
        pci_dev.func,
    )
    .and_then(|phys| {
        caps.config_space
            .carve(
                phys,
                firmware::pci::FUNCTION_CONFIG_BYTES,
                PAGE_SIZE,
                |span: &Span<u64>, at| {
                    syscall::mmio_split(span.slot, at - span.base).map_err(|_| SplitError::Failed)
                },
            )
            .ok()
    });
    let Some(cap) = carved
    else
    {
        std::os::seraph::log!(
            "{}: no configuration-space cap for the device; refused",
            name
        );
        return None;
    };
    Some(FunctionConfig {
        cap,
        aspace: caps.self_aspace,
    })
}

// ── The bound device ────────────────────────────────────────────────────────

/// How devmgr resets a device when it withdraws its driver, from the
/// driver's declaration.
#[derive(Clone, Copy)]
enum StopReset
{
    /// The declaration names no reset, or the device offers none of the kind
    /// it names: the device is never confirmed quiet.
    None,
    /// The `VirtIO` `device_status` reset.
    Virtio(DeviceReset),
    /// A PCI Express Function Level Reset.
    Flr,
}

/// The caps devmgr keeps for a PCI function it bound a driver to: the
/// resources it delivered (each the cap the driver's copy derives from),
/// the device's DMA grant for a DMA declaration, the function's
/// configuration page, the device's reset, its badge and requester ID, and
/// the release token of a driver procmgr holds the memory of.
pub struct PciDeviceCaps
{
    resources: [Resource; MAX_BOUND_RESOURCES],
    count: usize,
    /// The device's DMA capability, kept by devmgr, and its mappings
    /// ([`dma::DmaGrant`]); `None` for a driver that declares no DMA.
    pub dma: Option<dma::DmaGrant>,
    /// The function's configuration page, kept by devmgr alone, through
    /// which it clears Bus Master Enable and sets Interrupt Disable before it
    /// takes the device.
    config: FunctionConfig,
    reset: StopReset,
    pub device_badge: u64,
    /// The function's requester ID (`iommu_labels::requester_id`), which
    /// names it in the IOMMU's fault records.
    pub requester_id: u64,
    /// The release token of the driver devmgr started for the device
    /// ([`spawn::HeldChild`]), on which alone procmgr releases the driver's
    /// held memory once the device is confirmed stopped; 0 for a driver
    /// created with no hold, and before a spawn bootstraps.
    /// [`withdraw_device`] consumes it.
    pub release_token: u64,
}

impl PciDeviceCaps
{
    /// Nothing carved yet.
    fn empty(aspace: u64, requester_id: u64) -> Self
    {
        Self {
            resources: [Resource::IoPort {
                cap: 0,
                base: 0,
                count: 0,
            }; MAX_BOUND_RESOURCES],
            count: 0,
            dma: None,
            config: FunctionConfig { cap: 0, aspace },
            reset: StopReset::None,
            device_badge: 0,
            requester_id,
            release_token: 0,
        }
    }

    /// Record a carved resource. A function has at most six BARs and one
    /// wired line, which [`MAX_BOUND_RESOURCES`] holds.
    fn push(&mut self, resource: Resource)
    {
        if let Some(slot) = self.resources.get_mut(self.count)
        {
            *slot = resource;
            self.count += 1;
        }
        else
        {
            let _ = syscall::cap_delete(resource.cap());
        }
    }

    /// The delivered resources, in delivery order: the BARs, then the
    /// interrupt.
    pub fn resources(&self) -> &[Resource]
    {
        &self.resources[..self.count]
    }

    /// Whether the IOMMU confines the device.
    pub fn confined(&self) -> bool
    {
        self.dma.as_ref().is_some_and(dma::DmaGrant::confined)
    }

    /// Release every cap devmgr keeps for the device: its resources, its DMA
    /// grant, and its configuration page.
    pub fn release(&self)
    {
        for resource in self.resources()
        {
            let _ = syscall::cap_delete(resource.cap());
        }
        if let Some(dma) = &self.dma
        {
            dma.release();
        }
        if self.config.cap != 0
        {
            let _ = syscall::cap_delete(self.config.cap);
        }
    }

    /// Take the device from its driver, live or dead, so its DMA is stopped
    /// before the driver's frames, and the frames its mappings reach, are
    /// freed: withdraw its DMA grant ([`dma::DmaGrant::withdraw`]), so the
    /// driver maps nothing more and an IOMMU, where one confines the device,
    /// blocks it; then stop and reset the device ([`Self::stop_and_reset`]).
    /// Returns whether the device can no longer reach the driver's memory:
    /// an IOMMU blocks it, or it is known to be quiet. Only then does it
    /// delete the Memory caps it kept for the device's mappings
    /// ([`dma::Withdrawal::release`]; `firmware::dma::settle_withdrawal`
    /// decides). `false`, logged, means the device may still be accessing the
    /// driver's memory and the mapped frames, and those caps stay for the
    /// boot ([`dma::Withdrawal::quarantine`]). A device with no DMA grant is
    /// stopped and reset all the same, and its result returned.
    fn take_from_driver(&self) -> bool
    {
        let Some(dma) = &self.dma
        else
        {
            return self.stop_and_reset();
        };
        let withdrawal = dma.withdraw();
        match firmware::dma::settle_withdrawal(withdrawal.block(), || self.stop_and_reset())
        {
            firmware::dma::WithdrawnMappings::Release =>
            {
                withdrawal.release();
                true
            }
            firmware::dma::WithdrawnMappings::Quarantine =>
            {
                withdrawal.quarantine();
                false
            }
        }
    }

    /// Clear the function's Bus Master Enable, revoke every cap derived from
    /// the BAR caps devmgr keeps (the driver's copies, whose mappings the
    /// revocation removes before it returns), set the function's Interrupt
    /// Disable, so it no longer asserts a line it may share, and reset the
    /// device as its driver declared, in that order. Returns whether the
    /// device is confirmed quiet: Bus Master Enable read back clear, every BAR
    /// copy revoked, and the reset confirmed. A device with no declared reset
    /// is never confirmed quiet. Interrupt Disable is logged when it is not
    /// confirmed, and does not decide quiet, which concerns DMA alone.
    fn stop_and_reset(&self) -> bool
    {
        let bus_master_clear = self.config.clear_bus_master();
        let mut revoked = true;
        for resource in self.resources()
        {
            if let Resource::Mmio { cap, .. } = *resource
                && syscall::cap_revoke_all(cap).is_err()
            {
                revoked = false;
            }
        }
        if !revoked
        {
            std::os::seraph::log!("device reset: a BAR copy could not be revoked");
        }
        let _ = self.config.disable_interrupt();
        let reset = match self.reset
        {
            StopReset::Virtio(reset) => reset.reset(),
            StopReset::Flr => self.config.function_level_reset(),
            StopReset::None =>
            {
                std::os::seraph::log!("device reset: the driver declares no reset; not reset");
                false
            }
        };
        bus_master_clear && revoked && reset
    }
}

/// Withdraw the driver `child` names, live or dead, from the device
/// `dev_caps` holds, in the order services/devmgr/docs/responsibilities.md
/// § Responsibilities states: take the device from the driver
/// ([`PciDeviceCaps::take_from_driver`]: Bus Master Enable cleared before the
/// BAR caps are taken, then Interrupt Disable, then the reset), so it neither
/// performs DMA nor holds its line asserted with no driver to clear it; then
/// destroy the driver, a no-op for one procmgr has reaped. For a driver
/// procmgr holds the memory of, its held memory is released on its release
/// token ([`spawn::destroy_and_release`]) only when the device is confirmed
/// quiet; otherwise it stays held for the rest of the boot
/// ([`spawn::destroy_held`]), since the device may still be writing it. One
/// reset per withdrawal; both caps of `child` are consumed.
pub fn withdraw_device(dev_caps: &PciDeviceCaps, child: spawn::HeldChild, ipc_buf: *mut u64)
{
    let quiet = dev_caps.take_from_driver();
    if child.process_handle == 0
    {
        return;
    }
    if child.release_token == 0
    {
        spawn::destroy_child(child.process_handle, ipc_buf);
    }
    else if quiet
    {
        spawn::destroy_and_release(child, ipc_buf);
    }
    else
    {
        std::os::seraph::log!(
            "device {} not confirmed quiet; its driver's memory stays held for the boot",
            dev_caps.device_badge
        );
        spawn::destroy_held(child, ipc_buf);
    }
}

// ── Device stop primitives ──────────────────────────────────────────────────

/// Where devmgr writes a `VirtIO` device's `device_status` byte to reset it:
/// the kept `Mmio` cap of the BAR holding it, the pages that cap spans, the
/// byte's offset in the BAR, and devmgr's own address space to map it in.
#[derive(Clone, Copy)]
struct DeviceReset
{
    bar_cap: u64,
    bar_pages: u64,
    offset: u64,
    aspace: u64,
}

impl DeviceReset
{
    /// The reset of the device `info` describes, through the cap in
    /// `resources` of the BAR holding its `device_status` byte; `None` when
    /// the layout gives no such byte, no delivered BAR holds it, or the byte
    /// lies past the span that BAR's cap was carved to (a device whose common
    /// region reaches past its BAR).
    fn for_device(
        info: &virtio_core::VirtioPciStartupInfo,
        resources: &[Resource],
        aspace: u64,
    ) -> Option<Self>
    {
        let status = info.status_register()?;
        resources.iter().find_map(|r| match *r
        {
            Resource::Mmio {
                cap,
                bar: Some(bar),
                bytes,
                ..
            } if bar == status.bar && status.offset < bytes => Some(Self {
                bar_cap: cap,
                bar_pages: bytes.div_ceil(PAGE_SIZE),
                offset: status.offset,
                aspace,
            }),
            _ => None,
        })
    }

    /// Reset the device: map its status BAR into devmgr, store 0 to
    /// `device_status`, wait for the status to read 0, which completes the
    /// reset (`VirtIO` 1.2 §4.1.4.3.2), bounded by
    /// `virtio_core::pci::RESET_TIMEOUT`, and unmap. A device whose reset
    /// completed has stopped its DMA and dropped its pending interrupt, so a
    /// driver that died while its device asserted a shared level-triggered
    /// line leaves the line's other receivers no assertion to loop on
    /// (docs/device-management.md § Interrupt Delivery). Returns whether the
    /// reset completed; `false`, logged, when the mapping fails or the status
    /// does not read 0 within the bound.
    fn reset(&self) -> bool
    {
        let offset = self.offset;
        let confirmed = crate::with_mmio_mapped(
            self.aspace,
            self.bar_cap,
            self.bar_pages,
            "device reset",
            |va| {
                let status = (va + offset) as *mut u8;
                // SAFETY: `offset` is below the bytes the BAR's cap was carved
                // to (`for_device`), all of which are mapped from `va` for this
                // closure (`with_mmio_mapped`), and `device_status` is a byte
                // register.
                unsafe { core::ptr::write_volatile(status, 0) };
                // The reset completes when the device reads back 0 (`VirtIO`
                // 1.2 §4.1.4.3.2); the status is device-written, so the wait is
                // bounded.
                let start = std::time::Instant::now();
                virtio_core::pci::poll_until(
                    virtio_core::pci::RESET_TIMEOUT,
                    || start.elapsed(),
                    // SAFETY: as for the write above.
                    || unsafe { core::ptr::read_volatile(status) } == 0,
                )
            },
        );
        let Some(confirmed) = confirmed
        else
        {
            std::os::seraph::log!("device reset: its status BAR not mapped; not reset");
            return false;
        };
        if !confirmed
        {
            std::os::seraph::log!("device reset: not confirmed within its bound");
        }
        confirmed
    }
}

/// The `Mmio` cap of one PCI function's configuration page, which devmgr
/// keeps and delegates to no driver, and devmgr's own address space to map
/// it in.
#[derive(Clone, Copy)]
pub struct FunctionConfig
{
    pub cap: u64,
    aspace: u64,
}

impl FunctionConfig
{
    /// Run `access` on the configuration page mapped at its base address,
    /// logged under `what` when the page cannot be mapped. `access` reaches
    /// the page only through raw volatile accesses (`with_mmio_mapped`).
    fn mapped<R>(&self, what: &str, access: impl FnOnce(u64) -> R) -> Option<R>
    {
        crate::with_mmio_mapped(self.aspace, self.cap, 1, what, access)
    }

    /// Write the Command register for a bind
    /// ([`firmware::pci::command_for_bind`]): Memory Space Enable on, Bus
    /// Master Enable on for a driver that performs DMA (`dma`) and off for
    /// one that does not, Interrupt Disable clear for a driver given the
    /// wired line (`wired`) and set for one that is not. Returns whether the
    /// configuration page could be mapped.
    fn prepare_for_bind(&self, dma: bool, wired: bool) -> bool
    {
        self.mapped("bind", |va| {
            let command = (va + u64::from(firmware::pci::COMMAND)) as *mut u16;
            // SAFETY: the Command register lies in the configuration page
            // mapped from `va` for this closure, and is a 16-bit register.
            let current = unsafe { core::ptr::read_volatile(command) };
            // SAFETY: as for the read above.
            unsafe {
                core::ptr::write_volatile(
                    command,
                    firmware::pci::command_for_bind(current, dma, wired),
                );
            }
        })
        .is_some()
    }

    /// Turn on the function's Memory Space Enable and Bus Master Enable, so
    /// it decodes its MMIO BARs and may issue DMA: for the RISC-V IOMMU,
    /// which reads its tables by DMA (`iommu::riscv_round`). Returns whether
    /// the configuration page could be mapped.
    pub fn enable_memory_and_bus_master(&self) -> bool
    {
        self.mapped("bus master", |va| {
            let command = (va + u64::from(firmware::pci::COMMAND)) as *mut u16;
            // SAFETY: the Command register lies in the configuration page
            // mapped from `va` for this closure, and is a 16-bit register.
            let current = unsafe { core::ptr::read_volatile(command) };
            // SAFETY: as for the read above.
            unsafe {
                core::ptr::write_volatile(
                    command,
                    firmware::pci::command_with_memory_and_bus_master(current),
                );
            }
        })
        .is_some()
    }

    /// Clear the function's Bus Master Enable and read the Command register
    /// back: once the bit is clear the function issues no memory request of
    /// its own, so it performs no DMA, and the read-back's completion arrives
    /// only after every write the function posted before it
    /// (docs/device-management.md § DMA-Safe Teardown). Returns whether the
    /// read-back confirms the bit clear; `false`, logged, when the mapping
    /// fails or it does not.
    fn clear_bus_master(&self) -> bool
    {
        let read_back = self.mapped("bus master", |va| {
            let command = (va + u64::from(firmware::pci::COMMAND)) as *mut u16;
            // SAFETY: the Command register lies in the configuration page
            // mapped from `va` for this closure, and is a 16-bit register.
            let current = unsafe { core::ptr::read_volatile(command) };
            // SAFETY: as for the read above.
            unsafe {
                core::ptr::write_volatile(
                    command,
                    firmware::pci::command_without_bus_master(current),
                );
            }
            // SAFETY: as for the read above.
            unsafe { core::ptr::read_volatile(command) }
        });
        let Some(read_back) = read_back
        else
        {
            std::os::seraph::log!("bus master: configuration page not mapped; not cleared");
            return false;
        };
        let cleared = firmware::pci::bus_master_confirmed_clear(read_back);
        if !cleared
        {
            std::os::seraph::log!(
                "bus master: not confirmed clear (command={:#06x})",
                read_back
            );
        }
        cleared
    }

    /// Set the function's Interrupt Disable and read the Command register
    /// back: once the bit is set the function no longer asserts its wired
    /// line (PCI Local Bus Specification r3.0 § 6.2.2), so a withdrawn
    /// device leaves no assertion on a line it shares. Returns whether the
    /// read-back confirms it set; `false`, logged, when the mapping fails or
    /// it does not.
    fn disable_interrupt(&self) -> bool
    {
        let read_back = self.mapped("interrupt disable", |va| {
            let command = (va + u64::from(firmware::pci::COMMAND)) as *mut u16;
            // SAFETY: the Command register lies in the configuration page
            // mapped from `va` for this closure, and is a 16-bit register.
            let current = unsafe { core::ptr::read_volatile(command) };
            // SAFETY: as for the read above.
            unsafe {
                core::ptr::write_volatile(
                    command,
                    firmware::pci::command_with_interrupt_disable(current),
                );
            }
            // SAFETY: as for the read above.
            unsafe { core::ptr::read_volatile(command) }
        });
        let confirmed = read_back.is_some_and(firmware::pci::interrupt_disable_confirmed);
        if !confirmed
        {
            std::os::seraph::log!("interrupt disable: not confirmed set");
        }
        confirmed
    }

    /// Reset the function with a PCI Express Function Level Reset: find its
    /// PCI Express capability, check Device Capabilities for the reset, set
    /// Initiate Function Level Reset in Device Control, wait
    /// [`firmware::pci::FLR_COMPLETION_MS`] (PCI Express Base Specification
    /// r4.0 § 6.6.2), and read the Vendor ID back. A completed reset leaves
    /// the function's Command register clear, so it neither performs DMA nor
    /// asserts its line. Returns whether the function answers after the wait
    /// ([`firmware::pci::flr_completed`]); `false`, logged, when the page
    /// cannot be mapped, the function has no PCI Express capability or does
    /// not support the reset, or it does not answer.
    fn function_level_reset(&self) -> bool
    {
        let initiated = self.mapped("function level reset", |va| {
            let read8 = |at: u16| {
                // SAFETY: `at` is below the 256 bytes of the standard and
                // capability header (`find_capability` reads pointers that a
                // byte holds), inside the page mapped from `va` for this
                // closure.
                unsafe { core::ptr::read_volatile((va + u64::from(at)) as *const u8) }
            };
            // SAFETY: the Status register lies in the configuration page
            // mapped from `va` for this closure, and is a 16-bit register.
            let status = unsafe {
                core::ptr::read_volatile((va + u64::from(firmware::pci::STATUS)) as *const u16)
            };
            let express =
                firmware::pci::find_capability(status, firmware::pci::CAP_ID_PCI_EXPRESS, read8)?;
            let devcap_at = express + firmware::pci::PCIE_DEVICE_CAPABILITIES;
            // SAFETY: the capability's Device Capabilities register lies in
            // the mapped page (a capability starts below byte 256 and the
            // register 4 bytes into it), dword-aligned, a 32-bit register.
            let devcap =
                unsafe { core::ptr::read_volatile((va + u64::from(devcap_at)) as *const u32) };
            if !firmware::pci::flr_capable(devcap)
            {
                return None;
            }
            let control =
                (va + u64::from(express + firmware::pci::PCIE_DEVICE_CONTROL)) as *mut u16;
            // SAFETY: Device Control lies 8 bytes into the capability, in the
            // mapped page, and is a 16-bit register.
            let current = unsafe { core::ptr::read_volatile(control) };
            // SAFETY: as for the read above.
            unsafe {
                core::ptr::write_volatile(
                    control,
                    current | firmware::pci::PCIE_DEVCTL_INITIATE_FLR,
                );
            }
            Some(())
        });
        if !matches!(initiated, Some(Some(())))
        {
            std::os::seraph::log!("function level reset: not supported by the device; not reset");
            return false;
        }
        let _ = syscall::thread_sleep(firmware::pci::FLR_COMPLETION_MS);
        let vendor = self.mapped("function level reset", |va| {
            // SAFETY: the Vendor ID register lies in the configuration page
            // mapped from `va` for this closure, and is a 16-bit register.
            unsafe {
                core::ptr::read_volatile((va + u64::from(firmware::pci::VENDOR_ID)) as *const u16)
            }
        });
        let completed = vendor.is_some_and(firmware::pci::flr_completed);
        if !completed
        {
            std::os::seraph::log!("function level reset: the device does not answer after it");
        }
        completed
    }
}
