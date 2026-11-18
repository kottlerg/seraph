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
//! hands devmgr that directory. A hotplug arrival's batch runs both, the boot
//! pass over the boot images devmgr keeps ([`decls::BootImage`]) and then the
//! drivers-directory pass ([`crate::spawn_hotplug_drivers`]). Each pass
//! collects the declarations that match an unbound record ([`crate::decls`])
//! into a [`MatchTable`], walks the records in record order, and binds each to the
//! declaration the table chooses ([`bind_pci`]). A record is bound at most
//! once a boot: once a driver was started for it, or, for a RISC-V IOMMU's
//! function, once devmgr took it as a unit for the IOMMU driver
//! ([`crate::iommu`]), and, for a hotplug slot's port, once devmgr
//! managed the slot ([`crate::hotplug`]).
//!
//! No step names a driver. What a bound driver is given follows from its
//! declaration (its interrupt need, whether it performs DMA, its reset, its
//! tier, within the bounds of its source) and from the record (its BARs, its
//! wired line, and, for a driver that declares the `VirtIO` status reset,
//! the function's `VirtIO` register layout for the device configuration the
//! declaration states).

use driver_binding::decl::{DriverDecl, InterruptNeed, Reset};
use driver_binding::resources::{InterruptKind, Resource};
use firmware::aml::CrsResource;
use firmware::binding::{
    BoundCounts, Candidate, Choice, MatchTable, PciIdentity, RecordKeys, Source,
};
use firmware::dma::Confinement;
use firmware::lines::{HoldError, LineError};
use firmware::pci::{BarSpan, InterruptPlan, MessagesRefused, Msi, Msix};
use firmware::pci_records::{PciRecords, RecordState};
use firmware::records::{PlatformRecord, PlatformRecords};
use firmware::resource::{CarveError, Span, SpanTable, SplitError};
use firmware::roster::Roster;
use syscall_abi::PAGE_SIZE;

use ipc::procmgr_labels;

use crate::decls::{self, Binary};
use crate::spawn::{self, MAX_BOUND_RESOURCES};
use crate::{
    DeviceCatalog, IrqRangeAllocator, ServedDriver, Serves, SpawnedDriver, arch, caps, dma, pci,
    settle,
};

// ── Records ─────────────────────────────────────────────────────────────────

/// Every device record a bind pass walks, in record order: the PCI records
/// ([`PciRecords`]), then the platform records ([`crate::platform`]), each
/// with its state, and how many devices each driver with an instance limit
/// has been started for over the boot, less the removed ones.
pub struct Records
{
    pub pci: PciRecords,
    platform: PlatformRecords,
    /// The state of each platform record, in the same order.
    platform_states: Vec<RecordState>,
    bound_counts: BoundCounts,
}

impl Records
{
    /// The PCI and platform records, none bound; `None` when the platform
    /// records' states cannot be allocated.
    pub fn new(pci: PciRecords, platform: PlatformRecords) -> Option<Self>
    {
        let mut platform_states = Vec::new();
        platform_states
            .try_reserve_exact(platform.records().len())
            .ok()?;
        platform_states.resize(platform.records().len(), RecordState::Unbound);
        Some(Self {
            pci,
            platform,
            platform_states,
            bound_counts: BoundCounts::new(),
        })
    }

    /// The number of records, PCI and platform, removed ones included: the
    /// most drivers the bind passes can start over them, each record being
    /// bound at most once.
    pub fn count(&self) -> usize
    {
        self.pci
            .devices()
            .len()
            .saturating_add(self.platform_states.len())
    }

    /// Return to its driver's instance limit each limited driver's PCI
    /// record now removed ([`BoundCounts::release_removed`]), so a later
    /// pass may bind the driver to the device that replaces it; returns how
    /// many were returned.
    pub fn release_removed(&mut self) -> usize
    {
        let pci = &self.pci;
        self.bound_counts
            .release_removed(|index| pci.state(index) == Some(RecordState::Removed))
    }

    /// The PCI functions of every record not removed, in record order.
    pub fn live_pci(&self) -> impl Iterator<Item = &pci::PciDevice> + Clone
    {
        let pci = &self.pci;
        pci.devices()
            .iter()
            .enumerate()
            .filter(move |&(index, _)| pci.state(index) != Some(RecordState::Removed))
            .map(|(_, device)| device)
    }

    /// The state of the record not removed that holds the PCI function at
    /// `address` (segment, bus, device, function); `None` when none does.
    pub fn pci_state_at(&self, address: (u16, u8, u8, u8)) -> Option<RecordState>
    {
        self.pci
            .devices()
            .iter()
            .enumerate()
            .filter(|(_, d)| firmware::acpid::address(d) == address)
            .filter_map(|(index, _)| self.pci.state(index))
            .find(|&state| state != RecordState::Removed)
    }

    /// Every memory and I/O range a record not removed holds, bound or not:
    /// each PCI BAR, and each platform record's `Mmio` and `IoPort`.
    pub fn resource_ranges(&self) -> impl Iterator<Item = firmware::acpid::Range> + '_
    {
        let pci = self.live_pci().flat_map(firmware::acpid::pci_ranges);
        let platform = self
            .platform
            .records()
            .iter()
            .zip(&self.platform_states)
            .filter(|(_, state)| **state != RecordState::Removed)
            .flat_map(|(record, _)| record.resources())
            .filter_map(firmware::acpid::platform_range);
        pci.chain(platform)
    }

    /// The platform records a pass may bind, with their indices.
    fn unbound_platform(&self) -> impl Iterator<Item = (usize, &PlatformRecord)>
    {
        self.platform
            .records()
            .iter()
            .zip(&self.platform_states)
            .enumerate()
            .filter(|(_, (_, state))| **state == RecordState::Unbound)
            .map(|(index, (record, _))| (index, record))
    }

    /// Whether `decl`, from `source`, matches a record a pass may bind.
    fn matches_unbound(&self, decl: &DriverDecl, source: Source) -> bool
    {
        self.pci
            .unbound()
            .any(|(_, d)| firmware::binding::decl_rank(decl, source, &keys(d)).is_some())
            || self.unbound_platform().any(|(_, r)| {
                r.with_keys(|k| firmware::binding::decl_rank(decl, source, k))
                    .is_some()
            })
    }

    /// Whether no record is left for a pass to bind: each has a driver or is
    /// removed.
    fn none_unbound(&self) -> bool
    {
        self.pci.unbound().next().is_none() && self.unbound_platform().next().is_none()
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
    /// The watch the pass's drivers' death observers are bound on.
    pub watch: &'a settle::DriverWatch,
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
/// as boot modules, and release every module cap. At boot `modules` are the
/// declared boot modules the IOMMU pass left ([`decls::BootModules`]), whose
/// caps would otherwise pin the pool run init donated them from; in a hotplug
/// batch they are derivations of the boot images devmgr keeps
/// ([`decls::BootImage::module`]).
pub fn boot_pass(
    records: &mut Records,
    modules: Vec<(DriverDecl, Binary)>,
    carve: &mut Carve,
    pass: &mut Pass,
    ipc_buf: *mut u64,
)
{
    let mut table = MatchTable::new();
    for (decl, module) in modules
    {
        collect(&mut table, records, Some(&decl), Source::BootModule, module);
    }
    bind_records(records, &mut table, carve, pass, ipc_buf);
    for binary in table.drain_binaries()
    {
        binary.release();
    }
}

/// The drivers-directory pass: list `dir_cap`, the `/services/drivers/`
/// directory svcmgr handed devmgr, read the declaration of each entry, and
/// bind the records still unbound to them. A declaration `admits` refuses
/// (one of a class a class request marked boot-only,
/// [`firmware::binding::class_admits`]) is not considered, logged. Every file
/// cap is released once the pass ends. `dir_path` is the absolute path of the
/// directory `dir_cap` names; each entry is named `dir_path/entry`, its install
/// path, which procmgr verifies the driver's signature under. An entry whose
/// name exceeds [`procmgr_labels::CREATE_NAME_MAX`] or cannot be allocated is
/// logged and skipped, its file cap released.
pub fn drivers_dir_pass(
    records: &mut Records,
    dir_cap: u64,
    dir_path: &[u8],
    admits: impl Fn(&DriverDecl) -> bool,
    carve: &mut Carve,
    pass: &mut Pass,
    ipc_buf: *mut u64,
)
{
    if records.none_unbound()
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
        let install = install_path(dir_path, name);
        let Some(install) = install
        else
        {
            std::os::seraph::log!(warn: "{}: install path too long or no memory; skipped", label);
            let _ = syscall::cap_delete(walked.file_cap);
            return;
        };
        let mut decl = decls::file_decl(label, walked.file_cap, walked.size, ipc_buf);
        if let Some(d) = decl.filter(|d| !admits(d))
        {
            std::os::seraph::log!(
                warn: "{}: declares boot-only class {}; not considered",
                d.name.as_str(),
                d.class.as_ref().map_or("", |c| c.as_str())
            );
            decl = None;
        }
        let binary = Binary::File {
            cap: walked.file_cap,
            size: walked.size,
            name: install,
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

/// The install path of the drivers-directory entry `entry`: `dir_path`, `/`
/// and `entry`. `None` when it is longer than
/// [`procmgr_labels::CREATE_NAME_MAX`] or cannot be allocated.
fn install_path(dir_path: &[u8], entry: &[u8]) -> Option<Box<[u8]>>
{
    let len = dir_path.len().checked_add(1)?.checked_add(entry.len())?;
    if len > procmgr_labels::CREATE_NAME_MAX
    {
        return None;
    }
    let mut path = Vec::new();
    path.try_reserve_exact(len).ok()?;
    path.extend_from_slice(dir_path);
    path.push(b'/');
    path.extend_from_slice(entry);
    Some(path.into_boxed_slice())
}

/// Add `decl`, read from `binary`, to `table` when it matches a record no
/// driver is bound to; otherwise release `binary`.
fn collect(
    table: &mut MatchTable<Binary>,
    records: &mut Records,
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
    let cap = binary.cap();
    let added = records
        .bound_counts
        .track(&decl)
        .and_then(|bound| table.add(decl, source, binary, bound));
    if added.is_err()
    {
        std::os::seraph::log!(
            warn: "{}: no memory to consider the driver; not bound",
            name.as_str()
        );
        let _ = syscall::cap_delete(cap);
    }
}

/// Bind each unbound record, in record order, to the
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
    bind_pci_records(
        &mut records.pci,
        &mut records.bound_counts,
        table,
        carve,
        pass,
        ipc_buf,
    );
    for (index, state) in records.platform_states.iter_mut().enumerate()
    {
        let Some(record) = records
            .platform
            .records()
            .get(index)
            .filter(|_| *state == RecordState::Unbound)
        else
        {
            continue;
        };
        match record.with_keys(|k| table.choose(k))
        {
            Choice::Unmatched =>
            {}
            Choice::Conflict(first, second) =>
            {
                let candidates = table.candidates();
                if let (Some(a), Some(b)) = (candidates.get(first), candidates.get(second))
                {
                    std::os::seraph::log!(
                        warn: "platform record {}: {} and {} match it equally; neither bound",
                        index,
                        a.decl.name.as_str(),
                        b.decl.name.as_str()
                    );
                }
            }
            Choice::Bind(chosen) =>
            {
                let Some(candidate) = table.candidates().get(chosen)
                else
                {
                    continue;
                };
                if bind_platform(index, record, candidate, carve, pass, ipc_buf)
                {
                    *state = RecordState::Bound;
                    table.note_bound(chosen);
                    if let Some(candidate) = table.candidates().get(chosen)
                    {
                        records.bound_counts.note(&candidate.decl.name);
                    }
                }
            }
        }
    }
}

/// [`bind_records`] over the PCI records.
fn bind_pci_records(
    records: &mut PciRecords,
    bound_counts: &mut BoundCounts,
    table: &mut MatchTable<Binary>,
    carve: &mut Carve,
    pass: &mut Pass,
    ipc_buf: *mut u64,
)
{
    for at in 0..records.devices().len()
    {
        let Some(pci_dev) = records.unbound_at(at)
        else
        {
            continue;
        };
        match table.choose(&keys(pci_dev))
        {
            Choice::Unmatched =>
            {}
            Choice::Conflict(first, second) =>
            {
                let candidates = table.candidates();
                if let (Some(a), Some(b)) = (candidates.get(first), candidates.get(second))
                {
                    std::os::seraph::log!(
                        warn: "PCI {}:{}:{}.{}: {} and {} match it equally; neither bound",
                        pci_dev.segment,
                        pci_dev.bus,
                        pci_dev.dev,
                        pci_dev.func,
                        a.decl.name.as_str(),
                        b.decl.name.as_str()
                    );
                }
            }
            Choice::Bind(index) =>
            {
                let Some(candidate) = table.candidates().get(index)
                else
                {
                    continue;
                };
                if bind_pci(pci_dev, candidate, carve, pass, ipc_buf)
                {
                    records.mark_bound(at);
                    table.note_bound(index);
                    if let Some(candidate) = table.candidates().get(index)
                        && bound_counts.note_pci(&candidate.decl.name, at).is_err()
                    {
                        std::os::seraph::log!(
                            warn: "{}: no memory to keep its instance; its device's removal \
                                   does not return it",
                            candidate.decl.name.as_str()
                        );
                    }
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
        std::os::seraph::log!(warn: "{}: declares no device class; not bound", name);
        return false;
    };
    // No platform record is an IOMMU record, and none has a `Dma` resource:
    // neither physical access nor a DMA capability is granted here.
    let grants = firmware::binding::grants(decl, candidate.source, false);
    if grants.tier_ignored
    {
        std::os::seraph::log!(warn: "{}: boot tier not granted from the drivers directory", name);
    }
    if grants.phys_access_ignored
    {
        std::os::seraph::log!(warn: "{}: physical access not granted", name);
    }
    if decl.dma
    {
        std::os::seraph::log!(warn: "{}: the record has no DMA resource; no DMA granted", name);
    }
    if pass.roster.try_reserve_one().is_err()
    {
        std::os::seraph::log!(warn: "{}: no memory to record the driver; not bound", name);
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
        std::os::seraph::log!(warn: "{}: no service endpoint; not bound", name);
        dev_caps.release();
        return false;
    };
    let Some(source) = candidate.binary.source_copy()
    else
    {
        std::os::seraph::log!(warn: "{}: binary cap not copied; not bound", name);
        let _ = syscall::cap_delete(service_ep);
        dev_caps.release();
        return false;
    };
    let config = spawn::BoundSpawnConfig {
        procmgr_ep: carve.caps.procmgr_ep,
        bootstrap_ep: carve.caps.self_bootstrap_ep,
        source,
        resources: dev_caps.resources(),
        units: &[],
        dma_cap: None,
        held: false,
        phys_access: grants.phys_access,
        service_ep,
        query_ep: pass.batch.driver_ep(),
        watch: pass.watch,
        watch_eq: None,
        device_badge: dev_caps.device_badge,
        priority: spawn::tier_priority(grants.tier),
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
            crate::record_spawned(pass.roster, spawned, &mut carve.caps.slot_bars, ipc_buf);
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
    let Some(mut dev) = PlatformDeviceCaps::empty()
    else
    {
        std::os::seraph::log!(warn: "{}: no memory for the device's resources; not bound", name);
        return None;
    };
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
                    offset: 0,
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
                warn: "{}: a register range of the record not carved; not bound",
                name
            );
            dev.release();
            return None;
        };
        if !dev.push(carved)
        {
            std::os::seraph::log!(
                warn: "{}: more resources than a driver is delivered; not bound",
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
                std::os::seraph::log!(warn: "{}: no room for the interrupt; not bound", name);
                dev.release();
                return None;
            }
        }
        None if decl.interrupt.need == InterruptNeed::Required =>
        {
            std::os::seraph::log!(
                warn: "{}: no interrupt line for the device, which the driver requires; not bound",
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
        std::os::seraph::log!(warn: "{}: catalog entry not added; not bound", name);
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
        CrsResource::Mmio { .. } | CrsResource::IoPort { .. } => None,
    })?;
    let (gsi, mode) = arch::current::platform_line(carve.irq_range, line, mode, isa);
    match carve.irq_range.exclusive_line(gsi, mode)
    {
        Ok(cap) => Some((cap, mode)),
        Err(crate::ExclusiveLineError::Carve(e)) =>
        {
            std::os::seraph::log!(warn: "{}: no IRQ cap for line {:#x} ({:?})", name, gsi, e);
            None
        }
        Err(crate::ExclusiveLineError::Route(e)) =>
        {
            std::os::seraph::log!(warn: "{}: line {:#x} not routed ({})", name, gsi, e);
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
    /// Room for [`MAX_BOUND_RESOURCES`] reserved on the heap at
    /// [`Self::empty`], so a push never allocates and the caps move through
    /// the bind and the registry as a few words.
    resources: Vec<Resource>,
    pub device_badge: u64,
}

impl PlatformDeviceCaps
{
    /// Nothing carved yet; `None` when the room for the resources cannot be
    /// reserved.
    fn empty() -> Option<Self>
    {
        Some(Self {
            resources: bound_resources()?,
            device_badge: 0,
        })
    }

    /// Record a carved resource; `false`, the cap deleted, when
    /// [`MAX_BOUND_RESOURCES`] are already held.
    fn push(&mut self, resource: Resource) -> bool
    {
        push_bound(&mut self.resources, resource)
    }

    /// The delivered resources, in delivery order.
    pub fn resources(&self) -> &[Resource]
    {
        &self.resources
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

/// An empty resource list with room for [`MAX_BOUND_RESOURCES`], the most a
/// bound driver is delivered; `None` when the room cannot be reserved.
fn bound_resources() -> Option<Vec<Resource>>
{
    let mut resources = Vec::new();
    resources.try_reserve_exact(MAX_BOUND_RESOURCES).ok()?;
    Some(resources)
}

/// Append `resource` to `resources`, a list from [`bound_resources`], within
/// its reserved room; `false`, the resource's cap deleted, when
/// [`MAX_BOUND_RESOURCES`] are already held.
fn push_bound(resources: &mut Vec<Resource>, resource: Resource) -> bool
{
    if resources.len() < MAX_BOUND_RESOURCES
    {
        resources.push(resource);
        true
    }
    else
    {
        let _ = syscall::cap_delete(resource.cap());
        false
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
        std::os::seraph::log!(warn: "{}: declares no device class; not bound", name);
        return false;
    };
    // No PCI record is an IOMMU record: physical access is never granted
    // here.
    let grants = firmware::binding::grants(decl, candidate.source, false);
    if grants.tier_ignored
    {
        std::os::seraph::log!(warn: "{}: boot tier not granted from the drivers directory", name);
    }
    if grants.phys_access_ignored
    {
        std::os::seraph::log!(warn: "{}: physical access not granted", name);
    }
    if pass.roster.try_reserve_one().is_err()
    {
        std::os::seraph::log!(warn: "{}: no memory to record the driver; not bound", name);
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
        std::os::seraph::log!(warn: "{}: no service endpoint; not bound", name);
        dev_caps.release(&mut carve.caps.slot_bars);
        return false;
    };
    let Some(source) = candidate.binary.source_copy()
    else
    {
        std::os::seraph::log!(warn: "{}: binary cap not copied; not bound", name);
        let _ = syscall::cap_delete(service_ep);
        dev_caps.release(&mut carve.caps.slot_bars);
        return false;
    };
    let config = spawn::BoundSpawnConfig {
        procmgr_ep: carve.caps.procmgr_ep,
        bootstrap_ep: carve.caps.self_bootstrap_ep,
        source,
        resources: dev_caps.resources(),
        units: &[],
        dma_cap: dev_caps.dma.as_ref().map(dma::DmaGrant::cap),
        held: dev_caps.dma.is_some(),
        phys_access: grants.phys_access,
        service_ep,
        query_ep: pass.batch.driver_ep(),
        watch: pass.watch,
        watch_eq: None,
        // Index-derived, not random like the cross-boundary service badges
        // (#249): it names the device's catalog slot, which the driver
        // enforces per registered device.
        device_badge: dev_caps.device_badge,
        priority: spawn::tier_priority(grants.tier),
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
            crate::record_spawned(pass.roster, spawned, &mut carve.caps.slot_bars, ipc_buf);
        }
        spawn::DriverSpawn::Unbootstrapped(child) =>
        {
            withdraw_device(&dev_caps, child, ipc_buf);
            let _ = syscall::cap_delete(service_ep);
            dev_caps.release(&mut carve.caps.slot_bars);
        }
        spawn::DriverSpawn::Failed =>
        {
            let _ = syscall::cap_delete(service_ep);
            dev_caps.release(&mut carve.caps.slot_bars);
            return false;
        }
    }
    true
}

/// Carve what the driver `decl` declares of the PCI function `pci_dev`, and
/// turn the function on for it: caps on its MMIO BARs (for a driver of the
/// `VirtIO` register layout, the BARs the layout names, each clipped to the
/// pages its regions reach; otherwise every MMIO BAR, whole),
/// less the pages holding the function's MSI-X table and Pending Bit Array
/// where it may be given MSI-X ([`firmware::pci::deliverable_messages`]),
/// which no driver is delivered ([`carve_bars`]); its configuration page, its
/// catalog entry (the `VirtIO` startup info, or none), its DMA grant for a DMA
/// declaration ([`grant_dma`]), its interrupt for a driver that takes one
/// ([`give_interrupt`]: MSI-X or MSI vectors, or the wired line), the target
/// of its declared reset, and the Command register written for the bind
/// ([`FunctionConfig::prepare_for_bind`]). `None`, logged under `name` and
/// with what was carved released, on any failure, a required interrupt the
/// function cannot be given included.
fn carve_pci_device(
    name: &str,
    pci_dev: &pci::PciDevice,
    decl: &DriverDecl,
    carve: &mut Carve,
) -> Option<PciDeviceCaps>
{
    let Ok(virtio) = virtio_layout(name, pci_dev, decl)
    else
    {
        return None;
    };
    let address = (pci_dev.segment, pci_dev.bus, pci_dev.dev, pci_dev.func);
    let Some(mut dev) = PciDeviceCaps::empty(carve.caps.self_aspace, address)
    else
    {
        std::os::seraph::log!(warn: "{}: no memory for the device's resources; not bound", name);
        return None;
    };
    if fill_pci_device(name, pci_dev, decl, virtio.as_ref(), carve, &mut dev).is_none()
    {
        dev.release(&mut carve.caps.slot_bars);
        return None;
    }
    Some(dev)
}

/// The carving of [`carve_pci_device`] into `dev`, from the BARs to the
/// Command register, with the `VirtIO` register layout `virtio` the driver
/// is given; `None`, logged under `name`, on any failure, leaving to the
/// caller the release of what `dev` holds.
fn fill_pci_device(
    name: &str,
    pci_dev: &pci::PciDevice,
    decl: &DriverDecl,
    virtio: Option<&virtio_core::RegisterLayout>,
    carve: &mut Carve,
    dev: &mut PciDeviceCaps,
) -> Option<()>
{
    let (msi, msix) = firmware::pci::deliverable_messages(pci_dev.msi, pci_dev.msix, virtio);
    let spans = msix.map(|m| m.withheld());
    let withheld = spans.as_ref().map_or(&[][..], |w| w.as_slice());
    carve_bars(name, pci_dev, virtio, withheld, carve.caps, dev)?;
    dev.config = carve_function_config(name, pci_dev, carve.caps)?;
    let Some(badge) = catalog_entry(pci_dev, virtio, carve.catalog)
    else
    {
        std::os::seraph::log!(warn: "{}: catalog entry not added; not bound", name);
        return None;
    };
    dev.device_badge = badge;
    if decl.dma
    {
        dev.dma = Some(grant_dma(name, pci_dev, decl.dma_width, carve.caps, badge)?);
    }
    // After the DMA grant: on riscv64 a message-signaled target's interrupt
    // file enters the device's IOMMU domain before its vectors are enabled.
    let Ok(given) = give_interrupt(name, pci_dev, (msi, msix), decl, carve, dev)
    else
    {
        std::os::seraph::log!(
            warn: "{}: interrupt files mapped for vectors not given; not bound",
            name
        );
        return None;
    };
    if given.is_none() && decl.interrupt.need == InterruptNeed::Required
    {
        std::os::seraph::log!(
            warn: "{}: no interrupt for the device, which the driver requires; not bound",
            name
        );
        return None;
    }
    dev.reset = match decl.reset
    {
        Reset::None => StopReset::None,
        Reset::PcieFlr => StopReset::Flr,
        Reset::VirtioStatus { .. } =>
        {
            // The layout is `Some`: a VirtIO status reset without one was
            // refused before the carve ([`virtio_layout`]).
            let reset =
                virtio.and_then(|l| DeviceReset::for_device(l, dev.resources(), dev.config.aspace));
            if reset.is_none()
            {
                std::os::seraph::log!(
                    warn: "{}: the device offers no VirtIO status register to reset it by",
                    name
                );
            }
            reset.map_or(StopReset::None, StopReset::Virtio)
        }
    };
    if !dev
        .config
        .prepare_for_bind(decl.dma, given == Some(InterruptKind::Wired))
    {
        std::os::seraph::log!(warn: "{}: configuration page not mapped; not bound", name);
        return None;
    }
    Some(())
}

/// The `VirtIO` register layout the driver `decl` is given of the PCI
/// function `pci_dev`: `Ok(None)` for a driver that declares no `VirtIO`
/// status reset, which is given none, whatever the function presents. A
/// driver that declares it drives the layout, with the device-specific
/// configuration region its declaration requires or without it; a function
/// that presents no complete layout of those regions (one missing, `VirtIO`
/// 1.2 § 4.1.4, or a common region too short for the registers the transport
/// addresses) could neither be set up by it nor reset when it is withdrawn,
/// and is refused: `Err`, logged under `name`.
fn virtio_layout(
    name: &str,
    pci_dev: &pci::PciDevice,
    decl: &DriverDecl,
) -> Result<Option<virtio_core::RegisterLayout>, ()>
{
    let Some(device_config) = decl.reset.virtio_device_config()
    else
    {
        return Ok(None);
    };
    let layout = pci_dev.virtio_info.register_layout(device_config);
    if layout.is_none()
    {
        std::os::seraph::log!(
            warn: "{}: the device presents no complete VirtIO register layout; not bound",
            name
        );
        return Err(());
    }
    Ok(layout)
}

/// Add `pci_dev`'s catalog entry and return its device badge: the `VirtIO`
/// startup info for a function whose driver is given the `VirtIO` register
/// layout `virtio`, no startup info otherwise. `None` when the catalog
/// cannot hold it.
fn catalog_entry(
    pci_dev: &pci::PciDevice,
    virtio: Option<&virtio_core::RegisterLayout>,
    catalog: &mut DeviceCatalog,
) -> Option<u64>
{
    if virtio.is_none()
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

/// Carve caps on the MMIO BARs of `pci_dev` the bind delivers into `dev`
/// ([`carve_pci_device`]): for a driver given the `VirtIO` register layout
/// `virtio`, each BAR it names, clipped to the pages its regions reach, and
/// otherwise every MMIO BAR, whole; each BAR's first `bytes` less the pages
/// of `withheld` in it: one `Mmio` resource per range left
/// ([`firmware::pci::delivered_ranges`]), at most three for a BAR and two
/// more than the BARs in all, each naming its offset in its BAR. A BAR the
/// withheld pages cover whole is not delivered. `None`, logged, when a BAR
/// the `VirtIO` layout names is not an MMIO BAR or no aperture covers a
/// range. I/O BARs are not delivered.
fn carve_bars(
    name: &str,
    pci_dev: &pci::PciDevice,
    virtio: Option<&virtio_core::RegisterLayout>,
    withheld: &[BarSpan],
    caps: &mut caps::DevmgrCaps,
    dev: &mut PciDeviceCaps,
) -> Option<()>
{
    let mut carve_one = |b: usize, bytes: u64| {
        let (Some(&index), Some(&bar_phys)) = (pci_dev.bar_pci_idx.get(b), pci_dev.bar_phys.get(b))
        else
        {
            return None;
        };
        let (ranges, count) = firmware::pci::delivered_ranges(index, bytes, withheld);
        for &(offset, bytes) in ranges.get(..count).unwrap_or(&[])
        {
            let phys = bar_phys.checked_add(offset)?;
            std::os::seraph::log!(
                debug: "{}: BAR {} +{:#x} phys={:#018x} size={:#018x}",
                name,
                index,
                offset,
                phys,
                bytes
            );
            let Some(span) = crate::carve_bar(caps, phys, bytes)
            else
            {
                std::os::seraph::log!(
                    warn: "{}: BAR {} not covered by any aperture; not bound",
                    name,
                    index
                );
                return None;
            };
            dev.push(Resource::Mmio {
                cap: span.slot,
                bar: Some(index),
                phys,
                bytes,
                offset,
            });
            dev.push_bar(span);
        }
        Some(())
    };
    let mmio = |b: &usize| pci_dev.bar_is_mmio.get(*b).copied().unwrap_or(false);
    if let Some(layout) = virtio
    {
        for aperture in layout.bars()
        {
            let Some(b) = (0..pci_dev.bar_count)
                .filter(mmio)
                .find(|&b| pci_dev.bar_pci_idx.get(b) == Some(&aperture.bar))
            else
            {
                std::os::seraph::log!(
                    warn: "{}: VirtIO BAR {} is not an MMIO BAR; not bound",
                    name,
                    aperture.bar
                );
                return None;
            };
            // The driver maps the BAR into `aperture.pages` pages of its
            // register window and `mmio_map` maps the whole cap, so the cap
            // covers no more of the BAR than the regions in it reach.
            let size = *pci_dev.bar_size.get(b)?;
            carve_one(b, size.min(aperture.pages.saturating_mul(PAGE_SIZE)))?;
        }
    }
    else
    {
        for b in (0..pci_dev.bar_count).filter(mmio)
        {
            let size = *pci_dev.bar_size.get(b)?;
            carve_one(b, size)?;
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
    let grant = caps.dma.as_ref().and_then(|d| {
        d.grant(
            device_badge,
            crate::iommu::requester_id(pci_dev),
            confinement,
            &reserved,
        )
    });
    if grant.is_none()
    {
        std::os::seraph::log!(warn: "{}: no DMA grant; not bound", name);
        if let (Confinement::Domain { handle, .. }, Some(i)) = (confinement, caps.iommu.as_ref())
        {
            i.client().block(handle);
        }
    }
    grant
}

/// Give the driver `decl` of `pci_dev` its device's interrupt, recorded in
/// `dev` as one `Interrupt` resource per vector: the plan
/// [`firmware::pci::interrupt_plan`] chooses from the MSI and MSI-X
/// capabilities the driver may be given
/// ([`firmware::pci::deliverable_messages`]), each step that fails falling
/// back to the next ([`firmware::pci::fallback`]): MSI-X vectors
/// ([`give_msix`]), one MSI vector ([`give_msi`]), the wired line
/// ([`give_wired`]). Returns the kind given; `None` for a driver that takes
/// no interrupt and for a device none can be had for.
///
/// # Errors
/// [`Widened`] when a message-signaled step failed after it mapped an
/// interrupt file into the device's IOMMU domain: the domain keeps the
/// file until it is blocked, so the device would reach a hart's file no
/// target of its own sits on. Nothing further is tried; the caller refuses
/// the bind, whose release blocks the domain.
fn give_interrupt(
    name: &str,
    pci_dev: &pci::PciDevice,
    (msi, msix): (Option<Msi>, Option<Msix>),
    decl: &DriverDecl,
    carve: &mut Carve,
    dev: &mut PciDeviceCaps,
) -> Result<Option<InterruptKind>, Widened>
{
    let mut plan = Some(firmware::pci::interrupt_plan(
        decl.interrupt,
        decl.dma,
        msi,
        msix,
    ));
    while let Some(step) = plan
    {
        let (given, vectors) = match step
        {
            InterruptPlan::None => return Ok(None),
            InterruptPlan::Wired => (
                give_wired(pci_dev, carve.irq_range, dev).then_some(InterruptKind::Wired),
                1,
            ),
            InterruptPlan::Msi => (
                given_messages(give_msi(name, pci_dev, msi, carve.irq_range, dev))?
                    .then_some(InterruptKind::Msi),
                1,
            ),
            InterruptPlan::MsiX(vectors) => (
                given_messages(give_msix(name, pci_dev, msix, vectors, carve, dev))?
                    .then_some(InterruptKind::MsiX),
                vectors,
            ),
        };
        if let Some(kind) = given
        {
            std::os::seraph::log!("{}: {:?} interrupt, {} vector(s)", name, kind, vectors);
            return Ok(given);
        }
        plan = firmware::pci::fallback(step, msi);
        if let Some(next) = plan
        {
            std::os::seraph::log!(warn: "{}: {:?} not given; trying {:?}", name, step, next);
        }
    }
    Ok(None)
}

/// A message-signaled step that failed after it mapped an interrupt file
/// into the device's IOMMU domain ([`give_interrupt`]).
struct Widened;

/// Why a message-signaled step gave no vector.
#[derive(Clone, Copy)]
enum NotGiven
{
    /// The step left the device's IOMMU domain as it found it.
    Clean,
    /// The step mapped an interrupt file the domain keeps ([`Widened`]).
    Widened,
}

/// Whether a message-signaled step's `outcome` gave its vectors; `Err` for
/// one that failed after it widened the device's domain.
fn given_messages(outcome: Result<(), NotGiven>) -> Result<bool, Widened>
{
    match outcome
    {
        Ok(()) => Ok(true),
        Err(NotGiven::Clean) => Ok(false),
        Err(NotGiven::Widened) => Err(Widened),
    }
}

/// The failure of a message-signaled step after its targets were minted,
/// `widened` telling whether the minting mapped an interrupt file.
#[expect(
    clippy::fn_params_excessive_bools,
    reason = "`widened` is the minting outcome the result reports"
)]
fn not_given(widened: bool) -> NotGiven
{
    if widened
    {
        NotGiven::Widened
    }
    else
    {
        NotGiven::Clean
    }
}

/// Give the driver the device's wired line: its own single-line cap
/// ([`acquire_single_irq_cap`]) with the line's mode. Returns whether it was
/// given.
fn give_wired(
    pci_dev: &pci::PciDevice,
    irq_range: &mut IrqRangeAllocator,
    dev: &mut PciDeviceCaps,
) -> bool
{
    let Some(cap) = acquire_single_irq_cap(pci_dev, irq_range)
    else
    {
        return false;
    };
    let mode = device_gsi(pci_dev).map_or(0, |gsi| irq_range.line_mode(gsi));
    dev.push(Resource::Interrupt {
        cap,
        kind: InterruptKind::Wired,
        vector: 0,
        mode,
    });
    true
}

/// One minted message-signaled target: devmgr's cap on it and the message
/// its device writes to signal it (`SYS_CAP_INFO`'s
/// `CAP_INFO_IRQ_MSG_ADDRESS` and `CAP_INFO_IRQ_MSG_DATA`).
#[derive(Clone, Copy)]
struct Message
{
    cap: u64,
    address: u64,
    data: u64,
}

/// Release devmgr's cap `cap` on a message target: clear the target's
/// remapping entry when remapping is on (`remap`), so the function it was
/// given to reaches no later source through it, then delete the cap, which
/// frees the target once no copy remains.
pub fn release_message(remap: Option<&crate::intremap::InterruptRemap>, cap: u64)
{
    if let Some(remap) = remap
    {
        let _ = remap.clear(cap);
    }
    let _ = syscall::cap_delete(cap);
}

/// Release every target in `messages` ([`release_message`]).
fn delete_messages(remap: Option<&crate::intremap::InterruptRemap>, messages: &[Message])
{
    for m in messages
    {
        release_message(remap, m.cap);
    }
}

/// Whether a device's message-signaled writes are translated by its IOMMU
/// domain, so each interrupt file they target must be mapped there first:
/// the RISC-V IOMMU's are (`iommu_labels::MAP_MSI`); VT-d's are not, its
/// interrupt remapping governing them.
fn messages_translated() -> bool
{
    arch::current::IOMMU_FAMILY == crate::iommu::Family::Riscv
}

/// Mint `count` message-signaled targets for the function `rid`
/// ([`IrqRangeAllocator::mint_message`]) and read each one's message; check that every message fits the
/// function's capability (`fits`) and only then, where the device's IOMMU
/// domain translates its messages ([`messages_translated`]), make the
/// interrupt file each one targets reachable by the device through its DMA
/// grant `dma` ([`dma::DmaGrant::reach_interrupt_file`]), in that order by
/// [`firmware::pci::reach_message_files`]. Returns the targets and whether a
/// file was newly mapped for them. On failure, logged under `name`, every
/// target it minted is deleted, and the error tells whether a file was
/// mapped before the failure ([`NotGiven::Widened`]); a message that does not
/// fit maps none.
fn mint_messages(
    name: &str,
    rid: u64,
    count: u8,
    irq_range: &IrqRangeAllocator,
    dma: Option<&dma::DmaGrant>,
    fits: impl Fn(&Message) -> bool,
) -> Result<(Vec<Message>, bool), NotGiven>
{
    let remap = irq_range.remap.as_deref();
    let mut messages: Vec<Message> = Vec::new();
    if messages.try_reserve_exact(usize::from(count)).is_err()
    {
        std::os::seraph::log!(warn: "{}: no memory to mint interrupt targets", name);
        return Err(NotGiven::Clean);
    }
    for _ in 0..count
    {
        let minted =
            irq_range.mint_message(rid).and_then(|cap| {
                let message = syscall::cap_info(cap, syscall_abi::CAP_INFO_IRQ_MSG_ADDRESS)
                    .and_then(|address| {
                        syscall::cap_info(cap, syscall_abi::CAP_INFO_IRQ_MSG_DATA)
                            .map(|data| Message { cap, address, data })
                    });
                if message.is_err()
                {
                    release_message(remap, cap);
                }
                message
            });
        match minted
        {
            Ok(message) => messages.push(message),
            Err(e) =>
            {
                std::os::seraph::log!(
                    warn: "{}: interrupt target {} of {} not minted ({})",
                    name,
                    messages.len().saturating_add(1),
                    count,
                    e
                );
                delete_messages(remap, &messages);
                return Err(NotGiven::Clean);
            }
        }
    }
    let translated = messages_translated();
    let reached = firmware::pci::reach_message_files(&messages, fits, |m| match dma
    {
        Some(dma) if translated => dma.reach_interrupt_file(m.address & !(PAGE_SIZE - 1)),
        _ => Some(false),
    });
    match reached
    {
        Ok(widened) => Ok((messages, widened)),
        Err(refused) =>
        {
            let not = match refused
            {
                MessagesRefused::Unfit(i) =>
                {
                    if let Some(m) = messages.get(i)
                    {
                        std::os::seraph::log!(
                            warn: "{}: message {:#x}/{:#x} does not fit the device's capability",
                            name,
                            m.address,
                            m.data
                        );
                    }
                    NotGiven::Clean
                }
                MessagesRefused::Unreachable { widened } =>
                {
                    std::os::seraph::log!(
                        warn: "{}: an interrupt file its targets sit on is not reachable by the device",
                        name
                    );
                    not_given(widened)
                }
            };
            delete_messages(remap, &messages);
            Err(not)
        }
    }
}

/// Give the driver one MSI vector: mint a target whose message fits the
/// function's MSI capability ([`Msi::fits`], checked before its interrupt
/// file is reached), program the message into the capability and enable it
/// with one vector ([`FunctionConfig::program_msi`]).
///
/// # Errors
/// Logged, with the target deleted, when the function has no MSI
/// capability, the mint fails, the message does not fit the capability
/// (with no interrupt file mapped), or the configuration page cannot be
/// mapped; the [`NotGiven`] tells whether an interrupt file was mapped for
/// it.
fn give_msi(
    name: &str,
    pci_dev: &pci::PciDevice,
    msi: Option<Msi>,
    irq_range: &IrqRangeAllocator,
    dev: &mut PciDeviceCaps,
) -> Result<(), NotGiven>
{
    let msi = msi.ok_or(NotGiven::Clean)?;
    let rid = crate::iommu::requester_id(pci_dev);
    let (messages, widened) = mint_messages(name, rid, 1, irq_range, dev.dma.as_ref(), |m| {
        msi.fits(m.address, m.data)
    })?;
    let Some(m) = messages.first().copied()
    else
    {
        return Err(not_given(widened));
    };
    if !dev.config.program_msi(msi, m.address, m.data)
    {
        delete_messages(irq_range.remap.as_deref(), &[m]);
        return Err(not_given(widened));
    }
    dev.remap = irq_range.remap();
    dev.push(Resource::Interrupt {
        cap: m.cap,
        kind: InterruptKind::Msi,
        vector: 0,
        mode: 0,
    });
    Ok(())
}

/// Give the driver `vectors` MSI-X vectors, table entries 0 onwards, of the
/// function's MSI-X capability `msix`: carve devmgr's own cap on the pages
/// holding the table ([`msix_table`]), which no driver is delivered, mint a
/// target per vector whose message a table entry holds, and program the table
/// and enable MSI-X ([`FunctionConfig::enable_msix`]): each given entry
/// carries its target's message, unmasked, and every other entry is masked.
/// The driver binds its caps and names its vectors in its device's own
/// registers; it writes no table entry.
///
/// # Errors
/// Logged, with the targets and the table's cap deleted, when there is no
/// MSI-X capability, the table's pages cannot be carved, a mint fails, a
/// message does not fit a table entry (with no interrupt file mapped), or the
/// capability or table cannot be mapped; the [`NotGiven`] tells whether an
/// interrupt file was mapped for them.
fn give_msix(
    name: &str,
    pci_dev: &pci::PciDevice,
    msix: Option<Msix>,
    vectors: u8,
    carve: &mut Carve,
    dev: &mut PciDeviceCaps,
) -> Result<(), NotGiven>
{
    let msix = msix.ok_or(NotGiven::Clean)?;
    let table = msix_table(name, pci_dev, msix, carve.caps).ok_or(NotGiven::Clean)?;
    let rid = crate::iommu::requester_id(pci_dev);
    let minted = mint_messages(name, rid, vectors, carve.irq_range, dev.dma.as_ref(), |m| {
        firmware::pci::msix_entry_message(m.address, m.data).is_some()
    });
    let (messages, widened) = match minted
    {
        Ok(minted) => minted,
        Err(e) =>
        {
            return_bar(&mut carve.caps.slot_bars, table.span);
            return Err(e);
        }
    };
    if !dev.config.enable_msix(msix, &table, &messages)
    {
        delete_messages(carve.irq_range.remap.as_deref(), &messages);
        return_bar(&mut carve.caps.slot_bars, table.span);
        return Err(not_given(widened));
    }
    dev.push_bar(table.span);
    dev.remap = carve.irq_range.remap();
    for (vector, m) in (0..=u8::MAX).zip(&messages)
    {
        dev.push(Resource::Interrupt {
            cap: m.cap,
            kind: InterruptKind::MsiX,
            vector,
            mode: 0,
        });
    }
    Ok(())
}

/// devmgr's own cap on the pages holding a function's MSI-X table.
struct MsixTable
{
    cap: u64,
    /// The cap with the range it covers, under which it is given back.
    span: Span<u64>,
    /// Pages the cap spans.
    pages: u64,
    /// The table's byte offset from the cap's first page.
    offset: u64,
}

/// Carve devmgr's cap on the pages of `pci_dev` holding the MSI-X table of
/// `msix` ([`Msix::table_span`]), which [`carve_bars`] left in the aperture.
/// `None`, logged under `name`, when the table's BAR is no MMIO BAR of the
/// function, the table reaches past the BAR, or no aperture covers the
/// pages.
fn msix_table(
    name: &str,
    pci_dev: &pci::PciDevice,
    msix: Msix,
    caps: &mut caps::DevmgrCaps,
) -> Option<MsixTable>
{
    let bar = (0..pci_dev.bar_count)
        .find(|&b| {
            pci_dev.bar_pci_idx.get(b) == Some(&msix.table_bar)
                && pci_dev.bar_is_mmio.get(b) == Some(&true)
        })
        .and_then(|b| {
            let size = *pci_dev.bar_size.get(b)?;
            let phys = *pci_dev.bar_phys.get(b)?;
            (msix.table_end() <= size).then_some((size, phys))
        });
    let Some((bar_size, bar_phys)) = bar
    else
    {
        std::os::seraph::log!(
            warn: "{}: MSI-X table not inside MMIO BAR {}",
            name,
            msix.table_bar
        );
        return None;
    };
    let (span, offset) = msix.table_span();
    // A BAR smaller than a page ends before the table's page does.
    // `table_end() <= bar_size` bounds `span.start`, so the subtraction does
    // not saturate.
    let bytes = span.end.min(bar_size).saturating_sub(span.start);
    let Some(carved) = bar_phys
        .checked_add(span.start)
        .and_then(|at| crate::carve_bar(caps, at, bytes))
    else
    {
        std::os::seraph::log!(
            warn: "{}: MSI-X table of BAR {} not covered by any aperture",
            name,
            msix.table_bar
        );
        return None;
    };
    Some(MsixTable {
        cap: carved.slot,
        span: carved,
        pages: bytes.div_ceil(PAGE_SIZE),
        offset,
    })
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
                debug: "IRQ cap for GSI {:#x}, mode {:#x}",
                u64::from(gsi),
                irq_range.line_mode(gsi)
            );
            Some(cap)
        }
        Err(LineError::Hold(HoldError::Split(CarveError::NotCovered))) =>
        {
            std::os::seraph::log!(
                warn: "GSI {:#x} not in the held IRQ range (or no range); no IRQ cap",
                u64::from(gsi)
            );
            None
        }
        Err(e) =>
        {
            std::os::seraph::log!(warn: "no IRQ cap for GSI {:#x} ({:?})", u64::from(gsi), e);
            None
        }
    }
}

/// The GSI of a PCI device: the firmware-programmed config-space IRQ line
/// when one is set, else the arch `INTx` routing fallback
/// ([`arch::current::intx_fallback_gsi`]) of the pin and device number its
/// interrupt reaches its root bus with (`PciDevice::host_intx`).
pub fn device_gsi(pci_dev: &pci::PciDevice) -> Option<u32>
{
    if pci_dev.irq_line != 0 && pci_dev.irq_line != 0xFF
    {
        return Some(u32::from(pci_dev.irq_line));
    }
    let (pin, dev) = pci_dev.host_intx?;
    arch::current::intx_fallback_gsi(pin, dev)
}

/// The `Mmio` cap of the configuration page of the function at `address`
/// (segment, bus, device, function), which devmgr keeps for the boot in
/// `caps.config_pages`: carved out of the kept ECAM windows the first time
/// a bind or an acpid access asks for it, and found there every later time,
/// so each user is given a derivation and none loses the page to another.
/// Returns `None` when no kept window decodes the function, the carve
/// fails, or the cache cannot grow (nothing is carved then).
pub fn config_page(caps: &mut caps::DevmgrCaps, address: (u16, u8, u8, u8)) -> Option<u64>
{
    if let Some(&(_, cap)) = caps.config_pages.iter().find(|(a, _)| *a == address)
    {
        return Some(cap);
    }
    let (segment, bus, dev, func) = address;
    let phys = firmware::pci::function_config_phys(&caps.ecam_windows, segment, bus, dev, func)?;
    caps.config_pages.try_reserve(1).ok()?;
    let cap = caps
        .config_space
        .carve(
            phys,
            firmware::pci::FUNCTION_CONFIG_BYTES,
            PAGE_SIZE,
            |span: &Span<u64>, at| {
                let offset = at.checked_sub(span.base).ok_or(SplitError::Failed)?;
                syscall::mmio_split(span.slot, offset).map_err(|_| SplitError::Failed)
            },
        )
        .ok()?;
    caps.config_pages.push((address, cap));
    Some(cap)
}

/// A derivation of the `Mmio` cap of `pci_dev`'s configuration page
/// ([`config_page`]), which its holder deletes when done. Returns `None`,
/// logged under `name`, when no kept window decodes the function, the carve
/// fails, or the derivation does.
pub fn carve_function_config(
    name: &str,
    pci_dev: &pci::PciDevice,
    caps: &mut caps::DevmgrCaps,
) -> Option<FunctionConfig>
{
    let address = (pci_dev.segment, pci_dev.bus, pci_dev.dev, pci_dev.func);
    let carved = config_page(caps, address)
        .and_then(|page| syscall::cap_derive(page, syscall::RIGHTS_ALL).ok());
    let Some(cap) = carved
    else
    {
        std::os::seraph::log!(
            warn: "{}: no configuration-space cap for the device; refused",
            name
        );
        return None;
    };
    Some(FunctionConfig {
        cap,
        aspace: caps.self_aspace,
    })
}

/// Make acpid's `width`-byte configuration access (1, 2 or 4) at `offset` of
/// the function at `address`: a read when `write` is `None`, else a write
/// of its low `width` bytes. The caller has checked the access
/// (`firmware::acpid::config_access`). Returns the value read (0 for a
/// write), or `None` when the function's configuration page cannot be
/// carved or mapped, or the width is not 1, 2 or 4.
pub fn acpi_config_access(
    caps: &mut caps::DevmgrCaps,
    address: (u16, u8, u8, u8),
    offset: u16,
    width: u16,
    write: Option<u64>,
) -> Option<u64>
{
    let page = config_page(caps, address)?;
    crate::with_mmio_mapped(
        caps.self_aspace,
        page,
        1,
        "acpid configuration access",
        |va| {
            // SAFETY: `with_mmio_mapped` maps the whole configuration page at
            // `va` for this closure, which reaches it only through `regs`'s raw
            // volatile accesses.
            let regs = unsafe { ConfigRegs::new(va) };
            match (width, write)
            {
                (1, None) => Some(u64::from(regs.read8(offset))),
                (2, None) => Some(u64::from(regs.read16(offset))),
                (4, None) => Some(u64::from(regs.read32(offset))),
                (1, Some(value)) => u8::try_from(value & 0xFF).ok().map(|v| {
                    regs.write8(offset, v);
                    0
                }),
                (2, Some(value)) => u16::try_from(value & 0xFFFF).ok().map(|v| {
                    regs.write16(offset, v);
                    0
                }),
                (4, Some(value)) => u32::try_from(value & 0xFFFF_FFFF).ok().map(|v| {
                    regs.write32(offset, v);
                    0
                }),
                _ => None,
            }
        },
    )
    .flatten()
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
/// the range each of its BAR caps covers, the device's DMA grant for a DMA
/// declaration, the function's configuration page, the pages of its MSI-X
/// table for a function given MSI-X, the device's reset, its address and
/// badge, and the release token of a driver procmgr holds the memory of.
pub struct PciDeviceCaps
{
    /// Room for [`MAX_BOUND_RESOURCES`] reserved on the heap at
    /// [`Self::empty`], so a push never allocates and the caps move through
    /// the bind and the registry as a few words.
    resources: Vec<Resource>,
    /// Each cap devmgr carved on the function's BARs, its `Mmio` resources'
    /// and its MSI-X table's, with the range it covers, which
    /// [`Self::release`] gives back to the held BAR pages; room for one more
    /// than [`MAX_BOUND_RESOURCES`] reserved at [`Self::empty`].
    bars: Vec<Span<u64>>,
    /// The device's DMA capability, kept by devmgr, and its mappings
    /// ([`dma::DmaGrant`]); `None` for a driver that declares no DMA.
    pub dma: Option<dma::DmaGrant>,
    /// The function's configuration page, kept by devmgr alone, through
    /// which it clears Bus Master Enable and sets Interrupt Disable before it
    /// takes the device.
    config: FunctionConfig,
    reset: StopReset,
    /// The function's address: segment, bus, device, function.
    pub address: (u16, u8, u8, u8),
    pub device_badge: u64,
    /// The release token of the driver devmgr started for the device
    /// ([`spawn::HeldChild`]), on which alone procmgr releases the driver's
    /// held memory once the device is confirmed stopped; 0 for a driver
    /// created with no hold, and before a spawn bootstraps.
    /// [`withdraw_device`] consumes it.
    pub release_token: u64,
    /// Interrupt remapping, for a device given message-signaled vectors
    /// while it is on: their entries are cleared at release.
    remap: Option<std::sync::Arc<crate::intremap::InterruptRemap>>,
}

impl PciDeviceCaps
{
    /// Nothing carved yet; `None` when the room for the resources cannot be
    /// reserved.
    fn empty(aspace: u64, address: (u16, u8, u8, u8)) -> Option<Self>
    {
        let mut bars = Vec::new();
        bars.try_reserve_exact(MAX_BOUND_RESOURCES.saturating_add(1))
            .ok()?;
        Some(Self {
            resources: bound_resources()?,
            bars,
            dma: None,
            config: FunctionConfig { cap: 0, aspace },
            reset: StopReset::None,
            address,
            device_badge: 0,
            release_token: 0,
            remap: None,
        })
    }

    /// Record a carved resource. A function's BARs are delivered as at most
    /// `MAX_PCI_RANGES` ranges ([`carve_bars`]) beside either one wired line
    /// or at most `MAX_MSI_VECTORS` message-signaled vectors, which
    /// [`MAX_BOUND_RESOURCES`] holds.
    fn push(&mut self, resource: Resource)
    {
        let _ = push_bound(&mut self.resources, resource);
    }

    /// Record a cap carved on the function's BARs with the range it covers
    /// (`span`), to be given back at [`Self::release`]: at most one per
    /// delivered range and one for the MSI-X table, which the room reserved
    /// at [`Self::empty`] holds.
    fn push_bar(&mut self, span: Span<u64>)
    {
        if self.bars.len() < self.bars.capacity()
        {
            self.bars.push(span);
        }
    }

    /// The delivered resources, in delivery order: the BARs, then the
    /// interrupt's vectors.
    pub fn resources(&self) -> &[Resource]
    {
        &self.resources
    }

    /// Whether the device was given message-signaled vectors.
    fn has_messages(&self) -> bool
    {
        self.resources().iter().any(|r| {
            matches!(
                r,
                Resource::Interrupt {
                    kind: InterruptKind::Msi | InterruptKind::MsiX,
                    ..
                }
            )
        })
    }

    /// Whether the IOMMU confines the device.
    pub fn confined(&self) -> bool
    {
        self.dma.as_ref().is_some_and(dma::DmaGrant::confined)
    }

    /// Release every cap devmgr keeps for the device: its resources, its
    /// MSI-X table's pages, its DMA grant, and its configuration page. A
    /// device given message-signaled vectors first has them disabled
    /// ([`FunctionConfig::disable_messages`]), so it signals none of its
    /// targets once they are freed and minted for another device, and each
    /// target's remapping entry is cleared before its cap is deleted
    /// ([`release_message`]), so a message the device writes all the same
    /// is blocked. The caps on its BARs, its `Mmio` resources' and its MSI-X
    /// table's, are given back to the held BAR pages `held`
    /// ([`return_bar`]), so its pages stay devmgr's: a later bind carves
    /// them again, and a hotplug removal returns them to the apertures.
    pub fn release(&self, held: &mut SpanTable<u64>)
    {
        if self.config.cap != 0 && self.has_messages()
        {
            let _ = self.config.disable_messages();
        }
        for resource in self.resources()
        {
            match resource
            {
                Resource::Interrupt {
                    cap,
                    kind: InterruptKind::Msi | InterruptKind::MsiX,
                    ..
                } => release_message(self.remap.as_deref(), *cap),
                Resource::Interrupt {
                    kind: InterruptKind::Wired,
                    ..
                }
                | Resource::IoPort { .. } =>
                {
                    let _ = syscall::cap_delete(resource.cap());
                }
                // Given back with the other BAR caps below; one not recorded
                // there is deleted.
                Resource::Mmio { cap, .. } =>
                {
                    if !self.bars.iter().any(|s| s.slot == *cap)
                    {
                        let _ = syscall::cap_delete(*cap);
                    }
                }
            }
        }
        for &span in &self.bars
        {
            return_bar(held, span);
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
    /// Disable, so it no longer asserts a line it may share, clear its MSI
    /// Enable and MSI-X Enable, so it signals no message-signaled interrupt,
    /// and reset the device as its driver declared, in that order. Returns
    /// whether the device is confirmed quiet: Bus Master Enable read back
    /// clear, every BAR copy revoked, and the reset confirmed. A device with
    /// no declared reset is never confirmed quiet. Interrupt Disable is logged
    /// when it is not confirmed; neither it nor the message disable decides
    /// quiet, which concerns DMA alone.
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
            std::os::seraph::log!(warn: "device reset: a BAR copy could not be revoked");
        }
        let _ = self.config.disable_interrupt();
        let _ = self.config.disable_messages();
        let reset = match self.reset
        {
            StopReset::Virtio(reset) => reset.reset(),
            StopReset::Flr => self.config.function_level_reset(),
            StopReset::None =>
            {
                std::os::seraph::log!(
                    warn: "device reset: the driver declares no reset; not reset"
                );
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
/// BAR caps are taken, then Interrupt Disable and the message-signaled
/// enables, then the reset), so it neither performs DMA nor signals an
/// interrupt with no driver to take it; then
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
        if spawn::destroy_and_release(child, ipc_buf)
        {
            std::os::seraph::log!(
                "device {}: driver withdrawn, its memory released",
                dev_caps.device_badge
            );
        }
    }
    else
    {
        std::os::seraph::log!(
            warn: "device {} not confirmed quiet; its driver's memory stays held for the boot",
            dev_caps.device_badge
        );
        spawn::destroy_held(child, ipc_buf);
    }
}

/// Give the cap devmgr carved on a function's BARs, covering `span`, back to
/// the held BAR pages `held` (`caps::DevmgrCaps::slot_bars`): every copy
/// derived from it (the driver's, and their mappings) is revoked first, so
/// the pages are devmgr's alone again, and a bind carves them, or a hotplug
/// removal returns them to the apertures, once more. Deleted, logged, when a
/// copy cannot be revoked or the table cannot grow; its pages are then lost
/// for the boot.
pub fn return_bar(held: &mut SpanTable<u64>, span: Span<u64>)
{
    let kept = syscall::cap_revoke_all(span.slot).is_ok()
        && matches!(
            held.insert(span.slot, span.base, span.end.saturating_sub(span.base)),
            Ok(true)
        );
    if !kept
    {
        let _ = syscall::cap_delete(span.slot);
        std::os::seraph::log!(
            warn: "BAR pages {:#x}..{:#x} not given back; lost for the boot",
            span.base,
            span.end
        );
    }
}

// ── Device stop primitives ──────────────────────────────────────────────────

/// Where devmgr writes a `VirtIO` device's `device_status` byte to reset it:
/// the kept `Mmio` cap of the BAR range holding it, the pages that cap spans,
/// the byte's offset in the range, and devmgr's own address space to map it
/// in.
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
    /// The reset of the device whose register layout is `layout`, through
    /// the cap in `resources` of the BAR range holding its `device_status`
    /// byte; `None` when no delivered range of its BAR holds it (a device
    /// whose common region reaches past its BAR).
    fn for_device(
        layout: &virtio_core::RegisterLayout,
        resources: &[Resource],
        aspace: u64,
    ) -> Option<Self>
    {
        let status = layout.status_register();
        resources.iter().find_map(|r| {
            let Resource::Mmio {
                cap,
                bar: Some(bar),
                bytes,
                offset,
                ..
            } = *r
            else
            {
                return None;
            };
            let within = status.offset.checked_sub(offset).filter(|&d| d < bytes)?;
            (bar == status.bar).then(|| Self {
                bar_cap: cap,
                bar_pages: bytes.div_ceil(PAGE_SIZE),
                offset: within,
                aspace,
            })
        })
    }

    /// Reset the device: map its status register's range into devmgr, store 0 to
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
                let status = va.wrapping_add(offset) as *mut u8;
                // SAFETY: `offset` is below the bytes the range's cap was
                // carved to (`for_device`), all of which are mapped from `va`
                // for this closure (`with_mmio_mapped`), and `device_status` is
                // a byte register.
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
            std::os::seraph::log!(warn: "device reset: its status BAR not mapped; not reset");
            return false;
        };
        if !confirmed
        {
            std::os::seraph::log!(warn: "device reset: not confirmed within its bound");
        }
        confirmed
    }
}

/// Volatile access to the registers of one function's configuration page,
/// mapped at a base address for the value's life. Each access is checked to
/// lie within the page and be aligned to its width, so an offset read from
/// the device (a capability pointer) reaches nothing past the page; an access
/// that fails the check reads all ones and writes nothing, as a function that
/// does not answer.
pub struct ConfigRegs
{
    va: u64,
}

impl ConfigRegs
{
    /// The registers of the configuration page mapped at `va`.
    ///
    /// # Safety
    /// `va` is the base of a mapping of the whole configuration page that
    /// outlives the returned value and that nothing reaches but raw volatile
    /// accesses (`FunctionConfig::mapped`).
    pub unsafe fn new(va: u64) -> Self
    {
        Self { va }
    }

    /// The address of the `width`-byte register at `offset`, when it lies
    /// within the page and is aligned to its width.
    fn at(&self, offset: u16, width: u16) -> Option<u64>
    {
        let end = u64::from(offset).saturating_add(u64::from(width));
        (end <= firmware::pci::FUNCTION_CONFIG_BYTES && offset.is_multiple_of(width))
            .then(|| self.va.wrapping_add(u64::from(offset)))
    }

    /// Read the byte at `offset`; all ones outside the page.
    pub fn read8(&self, offset: u16) -> u8
    {
        // SAFETY: `at` checked the byte within the page `new`'s contract maps.
        self.at(offset, 1).map_or(u8::MAX, |a| unsafe {
            core::ptr::read_volatile(a as *const u8)
        })
    }

    fn write8(&self, offset: u16, value: u8)
    {
        if let Some(a) = self.at(offset, 1)
        {
            // SAFETY: as for `read8`.
            unsafe { core::ptr::write_volatile(a as *mut u8, value) };
        }
    }

    /// Read the 16-bit register at `offset`; all ones outside the page or unaligned.
    pub fn read16(&self, offset: u16) -> u16
    {
        // SAFETY: `at` checked the register within the page `new`'s contract
        // maps and aligned to its width.
        self.at(offset, 2).map_or(u16::MAX, |a| unsafe {
            core::ptr::read_volatile(a as *const u16)
        })
    }

    /// Write the 16-bit register at `offset`; nothing outside the page or unaligned.
    pub fn write16(&self, offset: u16, value: u16)
    {
        if let Some(a) = self.at(offset, 2)
        {
            // SAFETY: as for `read16`.
            unsafe { core::ptr::write_volatile(a as *mut u16, value) };
        }
    }

    /// Read the 32-bit register at `offset`; all ones outside the page or unaligned.
    pub fn read32(&self, offset: u16) -> u32
    {
        // SAFETY: as for `read16`, at its own width.
        self.at(offset, 4).map_or(u32::MAX, |a| unsafe {
            core::ptr::read_volatile(a as *const u32)
        })
    }

    /// Write the 32-bit register at `offset`; nothing outside the page or unaligned.
    pub fn write32(&self, offset: u16, value: u32)
    {
        if let Some(a) = self.at(offset, 4)
        {
            // SAFETY: as for `read32`.
            unsafe { core::ptr::write_volatile(a as *mut u32, value) };
        }
    }

    /// Read-modify-write the 16-bit register at `offset` with `change`.
    fn update16(&self, offset: u16, change: impl FnOnce(u16) -> u16)
    {
        self.write16(offset, change(self.read16(offset)));
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
    #[expect(
        clippy::fn_params_excessive_bools,
        reason = "`dma` and `wired` are the Command register's Bus Master Enable and Interrupt \
                  Disable values"
    )]
    fn prepare_for_bind(&self, dma: bool, wired: bool) -> bool
    {
        self.mapped("bind", |va| {
            let command = va.wrapping_add(u64::from(firmware::pci::COMMAND)) as *mut u16;
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

    /// Program the function's MSI capability `msi` with the message
    /// `address`, `data` (which [`Msi::fits`] admits), unmask its first vector
    /// where it has per-vector masking, and enable MSI with one vector
    /// ([`firmware::pci::msi_control_enable_one`]). The function signals
    /// nothing until Bus Master Enable is set. Returns whether the
    /// configuration page could be mapped; `false`, logged, when it could
    /// not, nothing written.
    fn program_msi(&self, msi: Msi, address: u64, data: u64) -> bool
    {
        let [lo0, lo1, lo2, lo3, hi0, hi1, hi2, hi3] = address.to_le_bytes();
        let [d0, d1, ..] = data.to_le_bytes();
        let programmed = self.mapped("MSI", |va| {
            // SAFETY: `va` is the configuration page mapped for this closure.
            let regs = unsafe { ConfigRegs::new(va) };
            regs.write32(
                msi.offset.saturating_add(firmware::pci::MSI_ADDRESS),
                u32::from_le_bytes([lo0, lo1, lo2, lo3]),
            );
            if msi.address_64
            {
                regs.write32(
                    msi.offset.saturating_add(firmware::pci::MSI_ADDRESS_HIGH),
                    u32::from_le_bytes([hi0, hi1, hi2, hi3]),
                );
            }
            regs.write16(msi.data_offset(), u16::from_le_bytes([d0, d1]));
            if let Some(mask) = msi.mask_offset()
            {
                regs.write32(mask, regs.read32(mask) & !1);
            }
            regs.update16(
                msi.offset.saturating_add(firmware::pci::MESSAGE_CONTROL),
                firmware::pci::msi_control_enable_one,
            );
        });
        programmed.is_some()
    }

    /// Program the function's MSI-X capability `msix` through devmgr's cap on
    /// its table's pages `table`, and enable it: set Memory Space Enable
    /// ([`firmware::pci::command_with_memory`]), so the table's BAR decodes,
    /// and MSI-X Enable under Function Mask
    /// ([`firmware::pci::msix_control_enable_masked`]); set every entry's
    /// Mask Bit; write each of `messages` into its entry, the first into
    /// entry 0 ([`firmware::pci::msix_entry_message`]), read it back, and
    /// clear that entry's Mask Bit; then clear Function Mask. Each entry is
    /// masked while its message is written, and every entry past `messages`
    /// stays masked. The function signals nothing until Bus Master Enable is
    /// set. Returns whether every step's mapping succeeded and every message
    /// fit its entry and read back as written; `false`, logged, when not,
    /// MSI-X then disabled again.
    fn enable_msix(&self, msix: Msix, table: &MsixTable, messages: &[Message]) -> bool
    {
        let control = msix.offset.saturating_add(firmware::pci::MESSAGE_CONTROL);
        let enabled = self.mapped("MSI-X", |va| {
            // SAFETY: `va` is the configuration page mapped for this closure.
            let regs = unsafe { ConfigRegs::new(va) };
            // The table is written through its BAR, which the function
            // decodes only under Memory Space Enable; the bind's Command
            // write (`prepare_for_bind`) comes after, and the firmware
            // may have left decoding off.
            regs.update16(firmware::pci::COMMAND, firmware::pci::command_with_memory);
            regs.update16(control, firmware::pci::msix_control_enable_masked);
        });
        if enabled.is_none()
        {
            return false;
        }
        let programmed =
            crate::with_mmio_mapped(self.aspace, table.cap, table.pages, "MSI-X table", |va| {
                let register = |entry: u64, field: u64| {
                    va.wrapping_add(table.offset)
                        .wrapping_add(entry.wrapping_mul(firmware::pci::MSIX_ENTRY_BYTES))
                        .wrapping_add(field) as *mut u32
                };
                // SAFETY (each access below): the table, `table_size` entries
                // from `table.offset`, lies within the pages the cap spans
                // (`msix_table` checked its end against the BAR and carved the
                // pages from the table's first through the BAR's or the
                // table's last), all of which are mapped from `va` for this
                // closure; each field is a dword-aligned 32-bit register (the
                // table offset is QWORD-aligned, its entries 16 bytes).
                for entry in 0..u64::from(msix.table_size)
                {
                    let at = register(entry, firmware::pci::MSIX_ENTRY_VECTOR_CONTROL);
                    // SAFETY: see above.
                    let vector_control = unsafe { core::ptr::read_volatile(at) };
                    // SAFETY: see above.
                    unsafe {
                        core::ptr::write_volatile(
                            at,
                            firmware::pci::msix_vector_control(vector_control, true),
                        );
                    }
                }
                let mut written = true;
                for (entry, m) in (0..u64::from(msix.table_size)).zip(messages)
                {
                    let Some([address, address_high, data]) =
                        firmware::pci::msix_entry_message(m.address, m.data)
                    else
                    {
                        written = false;
                        continue;
                    };
                    for (field, value) in [
                        (firmware::pci::MSIX_ENTRY_ADDRESS, address),
                        (firmware::pci::MSIX_ENTRY_ADDRESS_HIGH, address_high),
                        (firmware::pci::MSIX_ENTRY_DATA, data),
                    ]
                    {
                        // SAFETY: see above.
                        unsafe { core::ptr::write_volatile(register(entry, field), value) };
                        // A table that does not decode its writes reads back
                        // otherwise (all ones), and its entry would carry no
                        // message: the step fails and MSI-X is disabled.
                        // SAFETY: see above.
                        let read = unsafe { core::ptr::read_volatile(register(entry, field)) };
                        if read != value
                        {
                            written = false;
                        }
                    }
                    let at = register(entry, firmware::pci::MSIX_ENTRY_VECTOR_CONTROL);
                    // SAFETY: see above.
                    let vector_control = unsafe { core::ptr::read_volatile(at) };
                    // SAFETY: see above.
                    unsafe {
                        core::ptr::write_volatile(
                            at,
                            firmware::pci::msix_vector_control(vector_control, false),
                        );
                    }
                }
                written && messages.len() <= usize::from(msix.table_size)
            });
        let programmed = programmed == Some(true);
        if !programmed
        {
            std::os::seraph::log!(warn: "MSI-X: table not programmed; MSI-X disabled");
        }
        let finished = self.mapped("MSI-X", |va| {
            // SAFETY: `va` is the configuration page mapped for this closure.
            let regs = unsafe { ConfigRegs::new(va) };
            if programmed
            {
                regs.update16(control, firmware::pci::msix_control_unmask_function);
            }
            else
            {
                regs.update16(control, firmware::pci::msix_control_disable);
            }
        });
        programmed && finished.is_some()
    }

    /// Clear the function's MSI Enable and MSI-X Enable, MSI-X's Function
    /// Mask set ([`firmware::pci::msi_control_disable`],
    /// [`firmware::pci::msix_control_disable`]), each capability found by
    /// walking the function's capability list, so it signals no
    /// message-signaled interrupt. A function with neither capability is left
    /// as it is. Returns whether the configuration page could be mapped.
    fn disable_messages(&self) -> bool
    {
        self.mapped("message disable", |va| {
            // SAFETY: `va` is the configuration page mapped for this closure.
            let regs = unsafe { ConfigRegs::new(va) };
            let status = regs.read16(firmware::pci::STATUS);
            let read8 = |at: u16| regs.read8(at);
            if let Some(at) =
                firmware::pci::find_capability(status, firmware::pci::CAP_ID_MSI, read8)
            {
                regs.update16(
                    at.saturating_add(firmware::pci::MESSAGE_CONTROL),
                    firmware::pci::msi_control_disable,
                );
            }
            if let Some(at) =
                firmware::pci::find_capability(status, firmware::pci::CAP_ID_MSIX, read8)
            {
                regs.update16(
                    at.saturating_add(firmware::pci::MESSAGE_CONTROL),
                    firmware::pci::msix_control_disable,
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
            let command = va.wrapping_add(u64::from(firmware::pci::COMMAND)) as *mut u16;
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
            let command = va.wrapping_add(u64::from(firmware::pci::COMMAND)) as *mut u16;
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
            std::os::seraph::log!(warn: "bus master: configuration page not mapped; not cleared");
            return false;
        };
        let cleared = firmware::pci::bus_master_confirmed_clear(read_back);
        if !cleared
        {
            std::os::seraph::log!(
                warn: "bus master: not confirmed clear (command={:#06x})",
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
            let command = va.wrapping_add(u64::from(firmware::pci::COMMAND)) as *mut u16;
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
            std::os::seraph::log!(warn: "interrupt disable: not confirmed set");
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
                unsafe { core::ptr::read_volatile(va.wrapping_add(u64::from(at)) as *const u8) }
            };
            // SAFETY: the Status register lies in the configuration page
            // mapped from `va` for this closure, and is a 16-bit register.
            let status = unsafe {
                core::ptr::read_volatile(
                    va.wrapping_add(u64::from(firmware::pci::STATUS)) as *const u16
                )
            };
            let express =
                firmware::pci::find_capability(status, firmware::pci::CAP_ID_PCI_EXPRESS, read8)?;
            let devcap_at = express.checked_add(firmware::pci::PCIE_DEVICE_CAPABILITIES)?;
            // SAFETY: the capability's Device Capabilities register lies in
            // the mapped page (a capability starts below byte 256 and the
            // register 4 bytes into it), dword-aligned, a 32-bit register.
            let devcap = unsafe {
                core::ptr::read_volatile(va.wrapping_add(u64::from(devcap_at)) as *const u32)
            };
            if !firmware::pci::flr_capable(devcap)
            {
                return None;
            }
            let control_at = express.checked_add(firmware::pci::PCIE_DEVICE_CONTROL)?;
            let control = va.wrapping_add(u64::from(control_at)) as *mut u16;
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
            std::os::seraph::log!(
                warn: "function level reset: not supported by the device; not reset"
            );
            return false;
        }
        let _ = syscall::thread_sleep(firmware::pci::FLR_COMPLETION_MS);
        let vendor = self.mapped("function level reset", |va| {
            // SAFETY: the Vendor ID register lies in the configuration page
            // mapped from `va` for this closure, and is a 16-bit register.
            unsafe {
                core::ptr::read_volatile(
                    va.wrapping_add(u64::from(firmware::pci::VENDOR_ID)) as *const u16
                )
            }
        });
        let completed = vendor.is_some_and(firmware::pci::flr_completed);
        if !completed
        {
            std::os::seraph::log!(
                warn: "function level reset: the device does not answer after it"
            );
        }
        completed
    }
}
