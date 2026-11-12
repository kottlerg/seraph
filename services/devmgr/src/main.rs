// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/devmgr/src/main.rs

//! Seraph device manager — platform enumeration, hardware discovery, and
//! driver binding.
//!
//! devmgr receives raw firmware access (ACPI RSDP / reclaimable regions,
//! DTB blob), a full-rights derivation of the root Interrupt range cap,
//! and the MMIO aperture list from init. It parses MCFG / DTB to locate
//! every PCI ECAM window, narrows MMIO apertures via `mmio_split`, and splits
//! single-IRQ caps off that range via `irq_split` before delegating to driver processes.
//!
//! See `services/devmgr/docs/responsibilities.md` for devmgr's responsibilities
//! and driver authority, and `docs/device-management.md` for the system-scope
//! design.

mod arch;
mod bind;
mod caps;
mod decls;
mod dma;
mod iommu;
mod pci;
mod phys;
mod platform;
mod settle;
mod spawn;
mod tables;

use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock, PoisonError};

use driver_binding::decl::{ClassName, DriverName};
use firmware::classes::{Classes, MAX_CLASSES, Mismatch};
use firmware::lines::{HeldLines, LineError};
use firmware::resource::{CarveError, Span, SpanTable, SplitError};
use firmware::roster::{DeathPost, DriverState, Roster};
use firmware::served::{Lookup, Served};
use ipc::IpcMessage;
use std::os::seraph::{reserve_pages, startup_info, unreserve_pages};
use syscall_abi::PAGE_SIZE;

fn main() -> !
{
    std::os::seraph::log::register_name(b"devmgr");
    let info = startup_info();

    // IPC buffer is registered by `std::os::seraph::_start` and
    // page-aligned by the boot protocol. It is the control thread's: every
    // registry worker receives on its own page.
    #[allow(clippy::cast_ptr_alignment)]
    let ipc_buf = info.ipc_buffer.cast::<u64>();

    refuse_translatable_aspace(info.self_aspace);

    let Some(mut caps) = caps::bootstrap_caps(info, ipc_buf)
    else
    {
        syscall::thread_exit();
    };

    std::os::seraph::log!(
        "got {} apertures, {} ACPI regions, irq_range={:#x}, rsdp={:#x}, dtb={:#x}",
        caps.apertures.spans().len() as u64,
        caps.firmware.acpi_regions.len() as u64,
        caps.irq_range_cap,
        caps.firmware.rsdp_memory_cap,
        caps.firmware.dtb_memory_cap
    );

    let (mut records, modules) = enumerate_records(&mut caps);

    // IRQ allocator state: single-line caps carved out of devmgr's
    // Interrupt range cap, every remainder kept; each PCI device's line held
    // once carved, every device on it given a derivation, and a platform
    // record's line carved exclusive. The firmware's overrides give each
    // line's mode.
    let mut irq_range = IrqRangeAllocator::new(
        caps.irq_range_cap,
        arch::current::pci_line_overrides(&caps.firmware),
    );

    // Generic device-info catalog: each entry carries a kind discriminant +
    // version + opaque payload bytes, and its index + 1 is the device badge
    // of the driver spawned for it. A PCI function that presents the VirtIO
    // register layout gets an entry of kind VIRTIO_PCI, the framebuffer one
    // of kind FRAMEBUFFER; every other entry carries no startup info.
    let mut catalog = DeviceCatalog::default();

    // Every driver this boot can spawn, each at most once: one per device
    // record (a record is bound at most once), the IOMMU driver, and the
    // test-only fault batch (TODO(#165): drop it with that shim). The watch's
    // death queue is sized to them, so every death observer is funded and no
    // death is dropped.
    let driver_count = records.count() + IOMMU_DRIVERS + ipc::devmgr_labels::TEST_FAULT_DRIVERS;
    let Some(mut watch) = settle::DriverWatch::new(driver_count)
    else
    {
        std::os::seraph::log!(error: "no driver death watch, halting");
        halt_loop();
    };

    if caps.registry_ep == 0
    {
        std::os::seraph::log!(error: "no registry endpoint injected, halting");
        halt_loop();
    }

    // The drivers the registry serves, by class and instance ordinal, each
    // filled when its batch settles, and the state the registry's workers
    // share with this thread. devmgr owns each served driver's service
    // endpoint and mints client SEND caps on query.
    let registry = Arc::new(Registry::new(
        watch.job_note(),
        caps.registry_ep,
        Arc::clone(&caps.firmware),
    ));

    // The DMA endpoint every DMA-capable driver maps its device's buffers
    // through, served on its own thread from before the first spawn: a boot
    // driver maps its rings before it reports ready.
    caps.dma = dma::DmaService::start();
    if caps.dma.is_none()
    {
        std::os::seraph::log!(error: "no DMA service, halting");
        halt_loop();
    }

    // The IOMMU driver, spawned and settled before any DMA-capable driver:
    // once it reports ready every device behind a remapping unit is blocked
    // until devmgr attaches it, which a bind does before each DMA grant.
    // `None` runs every device unconfined, logged once.
    let mut boot_modules = modules.drivers;
    caps.iommu = iommu::bring_up(
        records.pci.devices(),
        &mut boot_modules,
        caps.pooled.take(),
        &mut caps,
        &mut watch,
        &mut catalog,
        &registry,
        ipc_buf,
    )
    .map(Arc::new);
    if let Some(i) = &caps.iommu
    {
        if let Some(d) = &caps.dma
        {
            d.set_iommu(Arc::clone(i.client()));
        }
        let _ = registry.iommu.set(Arc::clone(i));
    }

    // The boot batch: the boot pass over every record, from the boot
    // modules, settled before the registry's workers start.
    spawn_boot_drivers(
        &mut records,
        boot_modules,
        &mut caps,
        &mut irq_range,
        &mut watch,
        &mut catalog,
        &registry,
        ipc_buf,
    );

    // The registry's workers. This thread stays the control thread: it owns
    // the device records, the carve tables, the catalog, and the death
    // watch, and runs the work a request leaves for it (the drivers-directory
    // pass and settle after `SET_DRIVERS_DIR`, and the test-only batches) and
    // every withdrawal of a driver whose death the watch takes.
    start_registry_workers(&registry);
    std::os::seraph::log!("enumeration complete, registry open");

    let mut guard = ipc::recv_guard::RecvGuard::new(recv_diag);
    loop
    {
        run_jobs(
            &registry,
            &mut records,
            &mut caps,
            &mut irq_range,
            &mut watch,
            &mut catalog,
            ipc_buf,
        );
        registry.withdraw_deaths(&watch, ipc_buf);
        match watch.wait()
        {
            Ok(_) => guard.on_success(),
            Err(e) => guard.on_failure(e),
        }
    }
}

/// Locate and scan every PCI ECAM window, then enumerate the platform
/// records, returning the device records and the classified boot modules.
/// Halts, logged, when no window is scanned or the records cannot be held.
fn enumerate_records(caps: &mut caps::DevmgrCaps) -> (bind::Records, decls::BootModules)
{
    // Parse firmware to locate every PCI ECAM window. ACPI wins when RSDP is
    // present; DTB is the fallback; the arch platform default (QEMU virt
    // on riscv64, none on x86-64) is the last resort.
    let ecams = tables::discover_ecams(&caps.firmware);
    let mut devices: Vec<pci::PciDevice> = Vec::new();
    let mut windows_scanned = 0usize;
    for loc in &ecams
    {
        if enumerate_ecam(caps, loc, &mut devices)
        {
            windows_scanned += 1;
        }
    }
    if windows_scanned == 0
    {
        std::os::seraph::log!(
            error: "no PCI ECAM window located or enumerated via ACPI or DTB, halting"
        );
        halt_loop();
    }
    std::os::seraph::log!(
        "PCI functions found: {} in {} ECAM windows",
        devices.len() as u64,
        windows_scanned as u64
    );
    // Firmware lists windows in any segment order; the records are bound, and
    // the instance ordinals the registry serves counted, in segment, bus,
    // device, function order, then the platform records in firmware table
    // order.
    let modules = decls::classify_modules(caps);
    let platform_records = platform::enumerate(caps, &modules.tables);
    let records =
        bind::PciRecords::new(devices).and_then(|pci| bind::Records::new(pci, platform_records));
    let Some(records) = records
    else
    {
        std::os::seraph::log!(error: "no memory for the device records, halting");
        halt_loop();
    };
    (records, modules)
}

/// Start the registry's workers and let them receive: the
/// [`REGISTRY_WORKERS`] threads of a [`recv_pool::RecvPool`] on the registry
/// endpoint, each serving its requests with [`Registry::handle`]. Halts,
/// logged, when none can be started; fewer serve, logged, when some cannot.
fn start_registry_workers(registry: &Arc<Registry>)
{
    let pool = {
        let shared = Arc::clone(registry);
        recv_pool::RecvPool::new(registry.endpoint, recv_diag, move |msg, buf| {
            shared.handle(msg, buf.as_ptr());
        })
    };
    match pool.spawn("devmgr-registry", REGISTRY_WORKERS)
    {
        Ok(_) =>
        {}
        Err(e) if e.running > 0 => std::os::seraph::log!(
            warn: "{} of {} registry workers started ({}); serving on those",
            e.running as u64,
            REGISTRY_WORKERS as u64,
            e.error
        ),
        Err(e) =>
        {
            std::os::seraph::log!(error: "no registry worker started ({}), halting", e.error);
            halt_loop();
        }
    }
    pool.open();
}

/// The registry's worker count: a concurrency setting, which bounds no
/// capacity (callers beyond it queue on the registry endpoint).
const REGISTRY_WORKERS: usize = 4;

/// Run the work registry requests left for the control thread, in this
/// order: the drivers-directory pass and settle, the test-only fault batch,
/// and the test-only orphan spawn. Each job, once done, is counted settled
/// ([`Registry::finish_job`]), which releases the queries waiting for it.
// too_many_arguments: the jobs consume every table a bind and its settle
// batch carve from or record into, as the passes they run do.
#[allow(clippy::too_many_arguments)]
fn run_jobs(
    registry: &Registry,
    records: &mut bind::Records,
    caps: &mut caps::DevmgrCaps,
    irq_range: &mut IrqRangeAllocator,
    watch: &mut settle::DriverWatch,
    catalog: &mut DeviceCatalog,
    ipc_buf: *mut u64,
)
{
    let (jobs, drivers_dir_cap) = {
        let mut state = registry.lock();
        (core::mem::take(&mut state.jobs), state.drivers_dir_cap)
    };
    if jobs.drivers_dir
    {
        spawn_on_disk_drivers(
            records,
            caps,
            irq_range,
            drivers_dir_cap,
            watch,
            catalog,
            registry,
            ipc_buf,
        );
        registry.finish_job(|_| ());
    }
    if jobs.fault_batch
    {
        spawn_test_fault_drivers(caps, drivers_dir_cap, watch, catalog, registry, ipc_buf);
        registry.finish_job(|_| ());
    }
    if jobs.orphan
    {
        let result = match test_spawn_orphan(caps, drivers_dir_cap, ipc_buf)
        {
            Some(false) => 1,
            Some(true) => 2,
            None => 3,
        };
        registry.finish_job(|state| state.orphan_test_result = result);
    }
}

/// Work a registry request leaves for the control thread, each due at most
/// once at a time.
#[derive(Default)]
struct Jobs
{
    /// The drivers-directory pass and the on-disk batch's settle.
    drivers_dir: bool,
    /// TODO(#165): remove with the test labels. The test-only fault batch.
    fault_batch: bool,
    /// TODO(#165): remove with the test labels. The test-only orphan spawn.
    orphan: bool,
}

/// What the registry's workers and the control thread share, under
/// [`Registry::state`].
struct RegistryState
{
    served: ServedDrivers,
    jobs: Jobs,
    /// Jobs posted and not yet done. While it is not 0, a query whose
    /// answer a job could still change waits for it ([`Registry::lock_settled`]).
    unsettled: usize,
    /// The `LOOKUP | READ | READDIR`-attenuated `/services/drivers/` subtree
    /// cap svcmgr delivers with `SET_DRIVERS_DIR`; 0 until then.
    drivers_dir_cap: u64,
    /// Whether the drivers-directory pass has been posted: at most once per
    /// boot, so a driver not served by it replies `NO_DEVICE` thereafter and
    /// timed degrades gracefully to its no-RTC path. A boot-only class mark
    /// is refused once it is set.
    pass_begun: bool,
    /// TODO(#165): remove with the test labels. Whether the test-only fault
    /// batch has been posted: at most once per boot, so the death queue's
    /// reservation for it holds.
    fault_spawn_attempted: bool,
    /// TODO(#165): remove with the devmgr enumeration redesign. Outcome of
    /// the last `TEST_SPAWN_ORPHAN` trigger, reported by
    /// `TEST_ORPHAN_RESULT`. 0=not run, 1=spawn failed as expected (#176
    /// unwind fired), 2=unexpected success, 3=shim setup error.
    orphan_test_result: u64,
}

/// The device registry: the state the registry's workers serve queries
/// from and the control thread fills, and the read-only authority the
/// workers serve from beside it.
///
/// Lock order: the state lock is a leaf. While it is held a thread makes no
/// IPC call, logs nothing (a log line is a call to logd, which may itself be
/// waiting on a registry query), spawns no thread, and takes no other lock;
/// it runs only table operations and syscalls that do not block. A worker
/// replies with a SEND derived from a served driver's endpoint before it
/// releases the lock (a reply does not block), so a withdrawal's revocation
/// cannot delete the derived cap, and the slot be reused, between the
/// derivation and the reply. A withdrawal takes its driver out of the table
/// under the lock, leaving its tombstone, and makes its IPC once the lock is
/// released; no query reaches the driver from then on.
struct Registry
{
    state: Mutex<RegistryState>,
    /// Signalled whenever a job is done ([`Self::finish_job`]).
    settled: Condvar,
    /// The control thread's job notification ([`settle::DriverWatch::job_note`]).
    job_note: u64,
    /// RECV on the registry endpoint, from which class SENDs are derived.
    endpoint: u64,
    /// The firmware tables and arch authority `QUERY_ACPI_TABLE` and
    /// `QUERY_SHUTDOWN_DEVICE` serve from.
    firmware: Arc<caps::Firmware>,
    /// The IOMMU devmgr calls, once its driver is ready; `TEST_DMA_FAULTS`
    /// takes its faults.
    iommu: OnceLock<Arc<iommu::Iommu>>,
}

impl Registry
{
    fn new(job_note: u64, endpoint: u64, firmware: Arc<caps::Firmware>) -> Self
    {
        Self {
            state: Mutex::new(RegistryState {
                served: ServedDrivers::default(),
                jobs: Jobs::default(),
                unsettled: 0,
                drivers_dir_cap: 0,
                pass_begun: false,
                fault_spawn_attempted: false,
                orphan_test_result: 0,
            }),
            settled: Condvar::new(),
            job_note,
            endpoint,
            firmware,
            iommu: OnceLock::new(),
        }
    }

    /// Lock the state. devmgr panics with `panic = "abort"`, so no holder
    /// unwinds and a poisoned lock is never seen; the guard is taken either
    /// way.
    fn lock(&self) -> MutexGuard<'_, RegistryState>
    {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Lock the state once no posted job could change what `absent` reads:
    /// while jobs are posted and not done and `absent` holds (the query would
    /// answer that nothing is there), wait for a job to be done. A query
    /// received after the request that posted a job sees that job's
    /// drivers, as a single receive loop that ran the job before its next
    /// receive gave it. An answer naming a driver, live or withdrawn, is
    /// final once given, since a class's ordinals only grow, so it does not
    /// wait.
    fn lock_settled(&self, absent: impl Fn(&RegistryState) -> bool)
    -> MutexGuard<'_, RegistryState>
    {
        let mut state = self.lock();
        while state.unsettled > 0 && absent(&state)
        {
            state = self
                .settled
                .wait(state)
                .unwrap_or_else(PoisonError::into_inner);
        }
        state
    }

    /// Post a job, counted unsettled, when `due` (its flag in [`Jobs`]) is
    /// not already set; returns whether it was posted. The caller signals
    /// the control thread ([`Self::signal_jobs`]) once it has released the
    /// lock.
    fn post(state: &mut RegistryState, due: impl FnOnce(&mut Jobs) -> &mut bool) -> bool
    {
        let flag = due(&mut state.jobs);
        if *flag
        {
            return false;
        }
        *flag = true;
        state.unsettled += 1;
        true
    }

    /// Wake the control thread to run the jobs posted.
    fn signal_jobs(&self)
    {
        let _ = syscall::notification_send(self.job_note, 1);
    }

    /// Count one job done, applying `record` to the state in the same hold,
    /// and release every query waiting for the jobs.
    fn finish_job(&self, record: impl FnOnce(&mut RegistryState))
    {
        let mut state = self.lock();
        record(&mut state);
        state.unsettled = state.unsettled.saturating_sub(1);
        drop(state);
        self.settled.notify_all();
    }

    /// Whether `decl` may be considered by the drivers-directory pass: a
    /// declaration of a class a class request marked boot-only is not
    /// ([`firmware::binding::class_admits`]). The boot-only marks are fixed
    /// once the pass is posted.
    fn class_admits(&self, decl: &driver_binding::decl::DriverDecl) -> bool
    {
        firmware::binding::class_admits(
            &self.lock().served.classes,
            decl,
            firmware::binding::Source::DriversDir,
        )
    }

    /// Record the client the ready IOMMU driver is called through, so its
    /// death fails the client closed.
    fn set_iommu(&self, client: Arc<iommu::IommuClient>)
    {
        self.lock().served.iommu_client = Some(client);
    }

    /// Whether the IOMMU driver's batch served it: it reported ready.
    fn iommu_served(&self) -> bool
    {
        self.lock().served.iommu.first_live().is_some()
    }

    /// Serve a settled batch: append every driver that reported its device
    /// ready to its class, in spawn order, the order the registry's instance
    /// ordinals count, releasing its process handle unless it drives a PCI
    /// device; withdraw every other driver ([`ServedDriver::withdraw`]),
    /// which destroys one still pending (the settle's bound elapsed before it
    /// reported ready or died). Each driver is appended in a hold of its own;
    /// a query meanwhile sees the batch's drivers appended so far, and one
    /// that finds none waits for the batch's job to be done.
    fn serve(&self, roster: Roster<SpawnedDriver>, ipc_buf: *mut u64)
    {
        for (state, spawned) in roster.into_outcomes()
        {
            let name = spawned.name;
            if spawned.serves == Serves::Iommu && state != DriverState::Ready
            {
                // Destroyed but not released: its service endpoint is the
                // IOMMU client's, which is never deleted.
                std::os::seraph::log!(
                    warn: "{}: driver not ready when its batch settled; destroyed",
                    name.as_str()
                );
                spawn::destroy_child(spawned.driver.process_handle, ipc_buf);
                continue;
            }
            let (driver, why) = match state
            {
                DriverState::Ready => match self.serve_ready(spawned)
                {
                    None => continue,
                    Some(refused) => refused,
                },
                DriverState::Dead => (
                    spawned.driver,
                    "driver died before its batch settled; not served",
                ),
                DriverState::Pending => (
                    spawned.driver,
                    "driver reported neither ready nor death before the settle ended; destroyed",
                ),
            };
            std::os::seraph::log!(warn: "{}: {}", name.as_str(), why);
            driver.withdraw(ipc_buf);
        }
    }

    /// Append the ready driver `spawned` to what it is served as, in one
    /// hold of the lock. Returns the driver and why it is not served when it
    /// is not: the IOMMU confining its device has failed, or there is no room
    /// for it.
    fn serve_ready(&self, mut spawned: SpawnedDriver) -> Option<(ServedDriver, &'static str)>
    {
        let mut state = self.lock();
        let served = &mut state.served;
        let confined = spawned
            .driver
            .dev_caps
            .as_ref()
            .is_some_and(bind::PciDeviceCaps::confined);
        if confined && served.iommu_failed()
        {
            return Some((spawned.driver, "its device's IOMMU is gone; withdrawn"));
        }
        let list = match spawned.serves
        {
            Serves::Class(class) => served.classes.intern(&class),
            Serves::Iommu => Some(&mut served.iommu),
        };
        let Some(list) = list
        else
        {
            return Some((spawned.driver, "no room for the driver's class; destroyed"));
        };
        if list.try_reserve(1).is_err()
        {
            return Some((spawned.driver, "no room to serve the driver; destroyed"));
        }
        if spawned.driver.dev_caps.is_none()
        {
            let _ = syscall::cap_delete(spawned.driver.process_handle);
            spawned.driver.process_handle = 0;
        }
        // Room was reserved just above, so the push holds.
        let _ = list.push(spawned.badge, spawned.driver);
        None
    }

    /// Withdraw the served driver the death `post` names, if any: one a batch
    /// served that has since died. A post for a driver no class serves (one
    /// already withdrawn, or one destroyed when its batch timed out) changes
    /// nothing.
    fn withdraw_dead(&self, post: DeathPost, ipc_buf: *mut u64)
    {
        let taken = self.lock().served.take_dead(post.badge);
        match taken
        {
            // The IOMMU driver's record is dropped, not released.
            Some((None, _record)) =>
            {
                std::os::seraph::log!(
                    warn: "iommu: served driver of device {} died (reason={:#x})",
                    post.badge,
                    post.reason
                );
                self.fail_iommu(ipc_buf);
            }
            Some((Some(class), driver)) =>
            {
                std::os::seraph::log!(
                    warn: "{}: served driver of device {} died (reason={:#x}); withdrawn",
                    class.as_str(),
                    post.badge,
                    post.reason
                );
                driver.withdraw(ipc_buf);
            }
            None =>
            {}
        }
    }

    /// The IOMMU driver died after it enabled translation: fail its client
    /// closed ([`iommu::IommuClient::fail`]; its death watch usually has
    /// already) and, once, withdraw every served driver of a device it
    /// confines, whose mappings can no longer change, one per hold of the
    /// lock.
    fn fail_iommu(&self, ipc_buf: *mut u64)
    {
        let (client, first) = {
            let mut state = self.lock();
            let Some(client) = state.served.iommu_client.clone()
            else
            {
                return;
            };
            let first = !core::mem::replace(&mut state.served.iommu_dependants_withdrawn, true);
            (client, first)
        };
        // Outside the lock: a first failure starts a drain thread.
        client.fail();
        if !first
        {
            return;
        }
        loop
        {
            let taken = self.lock().served.take_confined();
            let Some((class, driver)) = taken
            else
            {
                break;
            };
            std::os::seraph::log!(
                warn: "{}: its device's IOMMU is gone; withdrawn",
                class.as_str()
            );
            driver.withdraw(ipc_buf);
        }
    }

    /// Withdraw every served driver whose death the watch's queue holds.
    fn withdraw_deaths(&self, watch: &settle::DriverWatch, ipc_buf: *mut u64)
    {
        while let Some(post) = watch.take_death()
        {
            self.withdraw_dead(post, ipc_buf);
        }
    }

    /// Log each class configured with no served driver and each served
    /// class no class request configured, read in one hold and logged after.
    fn log_mismatches(&self)
    {
        let mut found: [Option<(ClassName, Mismatch)>; MAX_CLASSES] = [None; MAX_CLASSES];
        {
            let state = self.lock();
            for (slot, (class, mismatch)) in found.iter_mut().zip(state.served.classes.mismatches())
            {
                *slot = Some((*class, mismatch));
            }
        }
        for (class, mismatch) in found.into_iter().flatten()
        {
            match mismatch
            {
                Mismatch::NoDriver => std::os::seraph::log!(
                    warn: "class {}: configured; no driver of it is served",
                    class.as_str()
                ),
                Mismatch::NotConfigured => std::os::seraph::log!(
                    warn: "class {}: a driver of it is served; no class file configures it",
                    class.as_str()
                ),
            }
        }
    }
}

impl Registry
{
    /// Serve one registry request on a worker whose IPC buffer page is
    /// `ipc_buf`, replying before it returns.
    // One match over every label, each arm carrying its own reply handling;
    // splitting it would scatter the dispatch table.
    #[allow(clippy::too_many_lines)]
    fn handle(&self, msg: &IpcMessage, ipc_buf: *mut u64)
    {
        let badge = msg.badge;
        match msg.label
        {
            ipc::devmgr_labels::QUERY_DEVICE =>
            {
                // Do not `seraph::log!` here: logd is a caller, blocked in
                // this call outside its log loop, so a log line would
                // deadlock (devmgr → log_ep → logd waiting on this reply).
                // The class and the reply's verb bits are the badge's, so a
                // SEND not minted by MINT_CLASS_SEND reaches no driver. A
                // class slot, once interned, stays for the boot.
                let class = ipc::devmgr_labels::class_badge::decode(badge)
                    .filter(|&(slot, _)| self.lock().served.classes.get_slot(slot).is_some());
                let Some((slot, verbs)) = class
                else
                {
                    reply_status(ipc::devmgr_errors::UNAUTHORIZED, ipc_buf);
                    return;
                };
                if msg.word(0) != u64::from(ipc::DEVMGR_LABELS_VERSION)
                {
                    reply_status(ipc::devmgr_errors::LABEL_VERSION_MISMATCH, ipc_buf);
                    return;
                }
                let ordinal = instance_ordinal(msg);
                let state = self.lock_settled(|s| {
                    matches!(s.served.slot_lookup(slot, ordinal), Lookup::Absent)
                });
                reply_served(
                    state.served.slot_lookup(slot, ordinal),
                    verbs,
                    ipc::devmgr_errors::NO_DEVICE,
                    ipc_buf,
                );
            }
            ipc::devmgr_labels::MINT_CLASS_SEND =>
            {
                // Logs nothing, as QUERY_DEVICE does not.
                if badge & ipc::devmgr_labels::CLASS_AUTHORITY == 0
                {
                    reply_status(ipc::devmgr_errors::UNAUTHORIZED, ipc_buf);
                    return;
                }
                if msg.word(0) != u64::from(ipc::DEVMGR_LABELS_VERSION)
                {
                    reply_status(ipc::devmgr_errors::LABEL_VERSION_MISMATCH, ipc_buf);
                    return;
                }
                let minted = {
                    let mut state = self.lock();
                    let state = &mut *state;
                    mint_class_send(
                        &mut state.served.classes,
                        self.endpoint,
                        msg,
                        state.pass_begun,
                    )
                };
                match minted
                {
                    Ok(send) =>
                    {
                        let reply = IpcMessage::builder(ipc::devmgr_errors::SUCCESS)
                            .cap(send)
                            .build();
                        // SAFETY: ipc_buf is this worker's registered IPC buffer.
                        let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
                    }
                    Err(code) => reply_status(code, ipc_buf),
                }
            }
            ipc::devmgr_labels::SET_DRIVERS_DIR => self.set_drivers_dir(msg, ipc_buf),
            ipc::devmgr_labels::QUERY_ACPI_TABLE =>
            {
                handle_query_acpi_table(&self.firmware, msg, badge, ipc_buf);
            }
            ipc::devmgr_labels::QUERY_SHUTDOWN_DEVICE =>
            {
                handle_query_shutdown_device(&self.firmware, msg, badge, ipc_buf);
            }
            // TODO(#165): remove with the devmgr enumeration redesign.
            // Test-only fault injection for #176, gated on
            // TEST_LABEL_AUTHORITY: ack, and leave the forced-failure spawn
            // to the control thread, which stashes its outcome for
            // TEST_ORPHAN_RESULT.
            ipc::devmgr_labels::TEST_SPAWN_ORPHAN =>
            {
                if !test_label_admitted(msg, badge, ipc_buf)
                {
                    return;
                }
                let posted = Self::post(&mut self.lock(), |j| &mut j.orphan);
                reply_status(ipc::devmgr_errors::SUCCESS, ipc_buf);
                if posted
                {
                    self.signal_jobs();
                }
            }
            // TODO(#165): report the stashed test-orphan outcome, once every
            // job posted before it is done.
            ipc::devmgr_labels::TEST_ORPHAN_RESULT =>
            {
                if !test_label_admitted(msg, badge, ipc_buf)
                {
                    return;
                }
                let result = self.lock_settled(|_| true).orphan_test_result;
                let reply = IpcMessage::builder(ipc::devmgr_errors::SUCCESS)
                    .word(0, result)
                    .build();
                // SAFETY: ipc_buf is this worker's registered IPC buffer.
                let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
            }
            // TODO(#165): remove with the test labels. Ack, and leave the
            // spawn and settle of the fault batch to the control thread, as
            // SET_DRIVERS_DIR does; a query on the fixtures waits until the
            // settle has ended.
            ipc::devmgr_labels::TEST_SPAWN_FAULT_DRIVERS =>
            {
                if !test_label_admitted(msg, badge, ipc_buf)
                {
                    return;
                }
                let posted = {
                    let mut state = self.lock();
                    if state.fault_spawn_attempted || state.drivers_dir_cap == 0
                    {
                        None
                    }
                    else
                    {
                        state.fault_spawn_attempted = true;
                        Some(Self::post(&mut state, |j| &mut j.fault_batch))
                    }
                };
                let Some(posted) = posted
                else
                {
                    reply_status(ipc::devmgr_errors::INVALID_REQUEST, ipc_buf);
                    return;
                };
                reply_status(ipc::devmgr_errors::SUCCESS, ipc_buf);
                if posted
                {
                    self.signal_jobs();
                }
            }
            // TODO(#165): remove with the test labels. Do not `seraph::log!`
            // here, as in the device queries it mirrors.
            ipc::devmgr_labels::TEST_QUERY_FAULT_DEVICE =>
            {
                if !test_label_admitted(msg, badge, ipc_buf)
                {
                    return;
                }
                let ordinal = instance_ordinal(msg);
                let state = self.lock_settled(|s| {
                    matches!(s.served.lookup(class::TEST_FAULT, ordinal), Lookup::Absent)
                });
                reply_served(
                    state.served.lookup(class::TEST_FAULT, ordinal),
                    ipc::devmgr_labels::TEST_DENY_BADGE,
                    ipc::devmgr_errors::NO_DEVICE,
                    ipc_buf,
                );
            }
            // TODO(#165): remove with the test labels. Do not `seraph::log!`
            // here, as in the device queries it mirrors.
            ipc::devmgr_labels::TEST_QUERY_DENY_DEVICE =>
            {
                if !test_label_admitted(msg, badge, ipc_buf)
                {
                    return;
                }
                let Some(class) =
                    ipc::class_name_of(msg, 1).and_then(|name| core::str::from_utf8(name).ok())
                else
                {
                    reply_status(ipc::devmgr_errors::INVALID_REQUEST, ipc_buf);
                    return;
                };
                let state = self.lock_settled(|s| s.served.first_live(class).is_none());
                let driver = state.served.first_live(class);
                reply_deny_send(driver.map_or(0, |d| d.ep), ipc_buf);
            }
            // TODO(#165): remove with the test labels. Do not `seraph::log!`
            // here, as in the device queries it mirrors.
            ipc::devmgr_labels::TEST_QUERY_DMA_DEVICE =>
            {
                if !test_label_admitted(msg, badge, ipc_buf)
                {
                    return;
                }
                // The fixture is bound by the drivers-directory pass like any
                // driver whose declaration matches; the reply says whether an
                // IOMMU confines its device.
                let state = self.lock_settled(|s| {
                    matches!(s.served.lookup(class::TEST_DMA, Some(0)), Lookup::Absent)
                });
                let fixture = state.served.lookup(class::TEST_DMA, Some(0));
                let confined = matches!(
                    fixture,
                    Lookup::Live(d) if d.dev_caps.as_ref().is_some_and(bind::PciDeviceCaps::confined)
                );
                let mode = if confined
                {
                    ipc::devmgr_labels::TEST_DMA_CONFINED
                }
                else
                {
                    ipc::devmgr_labels::TEST_DMA_UNCONFINED
                };
                reply_served_words(
                    fixture,
                    ipc::devmgr_labels::TEST_DENY_BADGE,
                    ipc::devmgr_errors::NO_DEVICE,
                    &[mode],
                    ipc_buf,
                );
            }
            // TODO(#165): remove with the test labels.
            ipc::devmgr_labels::TEST_DMA_FAULTS =>
            {
                if !test_label_admitted(msg, badge, ipc_buf)
                {
                    return;
                }
                let rid = self
                    .lock_settled(|s| s.served.first_live(class::TEST_DMA).is_none())
                    .served
                    .first_live(class::TEST_DMA)
                    .and_then(|d| d.dev_caps.as_ref())
                    .map(|c| c.requester_id);
                let Some(rid) = rid
                else
                {
                    reply_status(ipc::devmgr_errors::NO_DEVICE, ipc_buf);
                    return;
                };
                // Outside the lock: the take calls the IOMMU driver.
                let (count, last) = self.iommu.get().map_or((0, 0), |i| i.log_faults(rid));
                let reply = IpcMessage::builder(ipc::devmgr_errors::SUCCESS)
                    .word(0, count)
                    .word(1, last)
                    .build();
                // SAFETY: ipc_buf is this worker's registered IPC buffer.
                let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
            }
            // QUERY_DEVICE_INFO and DRIVER_READY included: drivers send both
            // on their settle batch's private endpoint, never here.
            _ => reply_status(ipc::devmgr_errors::UNKNOWN_OPCODE, ipc_buf),
        }
    }

    /// `SET_DRIVERS_DIR`, svcmgr's handshake: keep the subtree cap it
    /// carries, reply, and post the drivers-directory pass, which the control
    /// thread runs, so svcmgr never waits on driver work. Every rejection
    /// releases the cap the kernel transferred into devmgr's `CSpace` before
    /// it replies, and a re-send keeps the first cap and releases the new
    /// one; the pass is posted at most once per boot.
    fn set_drivers_dir(&self, msg: &IpcMessage, ipc_buf: *mut u64)
    {
        let delivered_cap = msg.caps().first().copied();
        let release = || {
            if let Some(c) = delivered_cap
            {
                let _ = syscall::cap_delete(c);
            }
        };
        if msg.badge & ipc::devmgr_labels::DRIVERS_DIR_AUTHORITY == 0
        {
            std::os::seraph::log!(
                warn: "SET_DRIVERS_DIR rejected: badge lacks DRIVERS_DIR_AUTHORITY"
            );
            release();
            reply_status(ipc::devmgr_errors::UNAUTHORIZED, ipc_buf);
            return;
        }
        if msg.word(0) != u64::from(ipc::DEVMGR_LABELS_VERSION)
        {
            release();
            reply_status(ipc::devmgr_errors::LABEL_VERSION_MISMATCH, ipc_buf);
            return;
        }
        let Some(new_cap) = delivered_cap
        else
        {
            reply_status(ipc::devmgr_errors::INVALID_REQUEST, ipc_buf);
            return;
        };
        let installed = {
            let mut state = self.lock();
            if state.drivers_dir_cap == 0
            {
                state.drivers_dir_cap = new_cap;
                state.pass_begun = true;
                Self::post(&mut state, |j| &mut j.drivers_dir)
            }
            else
            {
                false
            }
        };
        if installed
        {
            std::os::seraph::log!("devmgr: SET_DRIVERS_DIR cap installed");
        }
        else
        {
            // Idempotent re-send: keep the original, drop the new.
            let _ = syscall::cap_delete(new_cap);
        }
        reply_status(ipc::devmgr_errors::SUCCESS, ipc_buf);
        if installed
        {
            self.signal_jobs();
        }
    }
}

/// The IOMMU drivers a boot can spawn: one, of the architecture's family.
const IOMMU_DRIVERS: usize = 1;

/// The class names devmgr itself names: those its test labels look up. A driver bound
/// by declaration is served under the class its declaration names, which
/// devmgr does not interpret (docs/driver-binding.md § Device Classes).
mod class
{
    /// TODO(#165): remove with the test labels.
    pub const TEST_FAULT: &str = "test-fault";
    /// TODO(#165): remove with the test labels.
    pub const TEST_DMA: &str = "test-dma";
}

/// The driver devmgr starts on a fixed path, by name and the class it is
/// served under: the test-only fault fixture until P5 of #165 binds it by
/// declaration (docs/driver-binding.md § Status).
mod fixed
{
    use driver_binding::decl::{ClassName, DriverName};

    /// TODO(#165): remove with the test labels.
    pub const TEST_FAULT: (DriverName, ClassName) = (
        DriverName::literal_key("test-fault"),
        ClassName::literal_class(super::class::TEST_FAULT),
    );
}

/// Reply to a device query with a `SEND_GRANT` badged `verb_bits` on the
/// service endpoint of the served driver `lookup` names; `WITHDRAWN` when
/// that driver was withdrawn, `absent` when no driver is served there, and
/// `INVALID_REQUEST` when the derivation fails.
fn reply_served(lookup: Lookup<'_, ServedDriver>, verb_bits: u64, absent: u64, ipc_buf: *mut u64)
{
    reply_served_words(lookup, verb_bits, absent, &[], ipc_buf);
}

/// [`reply_served`], the success reply also carrying `words`.
fn reply_served_words(
    lookup: Lookup<'_, ServedDriver>,
    verb_bits: u64,
    absent: u64,
    words: &[u64],
    ipc_buf: *mut u64,
)
{
    let driver = match lookup
    {
        Lookup::Live(driver) => driver,
        Lookup::Withdrawn => return reply_status(ipc::devmgr_errors::WITHDRAWN, ipc_buf),
        Lookup::Absent => return reply_status(absent, ipc_buf),
    };
    let Ok(derived) =
        syscall::cap_derive_badge(driver.ep, syscall::RIGHTS_EP_SEND_GRANT, verb_bits)
    else
    {
        return reply_status(ipc::devmgr_errors::INVALID_REQUEST, ipc_buf);
    };
    let reply = IpcMessage::builder(ipc::devmgr_errors::SUCCESS)
        .words(0, words)
        .cap(derived)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer.
    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
}

// A class name a `MINT_CLASS_SEND` request can carry is one a declaration
// can name: devmgr interns both into the same `ClassName`.
const _: () =
    assert!(ipc::devmgr_labels::MAX_CLASS_NAME_BYTES == driver_binding::decl::MAX_CLASS_BYTES);

/// `MINT_CLASS_SEND` handler, past its gate and version check: intern the
/// class `msg` names in `classes` and mark it configured, and boot-only when
/// asked and `pass_begun` is not set, the drivers-directory pass not having
/// begun; then derive from `registry_ep` the SEND badged with the class's
/// slot and the request's verb bits. `Err` with the reply label otherwise:
/// `INVALID_REQUEST` for a bad verb mask, flag, or name, a late boot-only
/// mark, a full class table, or a failed derivation.
fn mint_class_send(
    classes: &mut Classes<ServedDriver>,
    registry_ep: u64,
    msg: &IpcMessage,
    pass_begun: bool,
) -> Result<u64, u64>
{
    let invalid = ipc::devmgr_errors::INVALID_REQUEST;
    let verbs = msg.word(1);
    let flags = msg.word(2);
    // Checked before the class is interned, so a refused request leaves the
    // table as it was.
    if verbs == 0
        || verbs & !ipc::VERB_BIT_MASK != 0
        || flags & !ipc::devmgr_labels::CLASS_BOOT_ONLY != 0
    {
        return Err(invalid);
    }
    let name = ipc::class_name_of(msg, 3)
        .and_then(ClassName::class)
        .ok_or(invalid)?;
    let boot_only = flags & ipc::devmgr_labels::CLASS_BOOT_ONLY != 0;
    let slot = classes
        .configure(&name, boot_only, pass_begun)
        .map_err(|_| invalid)?;
    let badge = ipc::devmgr_labels::class_badge::encode(slot, verbs).ok_or(invalid)?;
    syscall::cap_derive_badge(registry_ep, syscall::RIGHTS_EP_SEND, badge).map_err(|_| invalid)
}

/// TODO(#165): remove with the test labels. Admit a request on a test label
/// (`TEST_SPAWN_ORPHAN`, `TEST_ORPHAN_RESULT`, `TEST_QUERY_DENY_DEVICE`,
/// `TEST_SPAWN_FAULT_DRIVERS`, `TEST_QUERY_FAULT_DEVICE`,
/// `TEST_QUERY_DMA_DEVICE`, `TEST_DMA_FAULTS`): the badge
/// carries `TEST_LABEL_AUTHORITY` and `data[0]` is `DEVMGR_LABELS_VERSION`.
/// Otherwise reply the rejection and return `false`.
fn test_label_admitted(msg: &IpcMessage, badge: u64, ipc_buf: *mut u64) -> bool
{
    if badge & ipc::devmgr_labels::TEST_LABEL_AUTHORITY == 0
    {
        reply_status(ipc::devmgr_errors::UNAUTHORIZED, ipc_buf);
        return false;
    }
    if msg.word(0) != u64::from(ipc::DEVMGR_LABELS_VERSION)
    {
        reply_status(ipc::devmgr_errors::LABEL_VERSION_MISMATCH, ipc_buf);
        return false;
    }
    true
}

/// The instance ordinal a `QUERY_DEVICE` or `TEST_QUERY_FAULT_DEVICE`
/// request selects: `data[1]` when sent, else 0, the first instance.
/// `None` for an ordinal no `usize` holds, which no instance has.
fn instance_ordinal(msg: &IpcMessage) -> Option<usize>
{
    usize::try_from(msg.words().get(1).copied().unwrap_or(0)).ok()
}

/// `QUERY_DEVICE_INFO` handler, on a settle batch's driver endpoint: reply
/// the catalog entry the caller's badge names (badge == entry index + 1), or
/// `INVALID_REQUEST` when it names none or one that carries no startup info.
fn reply_device_info(catalog: &DeviceCatalog, msg: &IpcMessage, ipc_buf: *mut u64)
{
    let dev_idx = usize::try_from(msg.badge.wrapping_sub(1)).unwrap_or(usize::MAX);
    if msg.word(0) != u64::from(ipc::DEVMGR_LABELS_VERSION)
    {
        reply_status(ipc::devmgr_errors::LABEL_VERSION_MISMATCH, ipc_buf);
    }
    else if let Some(entry) = catalog
        .entries
        .get(dev_idx)
        .filter(|e| e.kind != NO_INFO_KIND)
    {
        // Reply schema: word[0] = kind, word[1] = version, word[2] =
        // byte_len, word[3..] = payload bytes packed contiguously as u64.
        // Devmgr does not interpret the payload — driver-side deserialise.
        let byte_len = entry.byte_len as usize;
        let word_count = byte_len.div_ceil(8);
        let mut words = [0u64; 3 + MAX_DEVICE_INFO_PAYLOAD / 8];
        words[0] = u64::from(entry.kind);
        words[1] = u64::from(entry.version);
        words[2] = u64::from(entry.byte_len);
        for (i, chunk) in entry.payload[..byte_len].chunks(8).enumerate()
        {
            let mut buf = [0u8; 8];
            buf[..chunk.len()].copy_from_slice(chunk);
            words[3 + i] = u64::from_le_bytes(buf);
        }
        let reply = IpcMessage::builder(ipc::devmgr_errors::SUCCESS)
            .words(0, &words[..3 + word_count])
            .build();
        // SAFETY: ipc_buf is the registered IPC buffer.
        let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
    }
    else
    {
        reply_status(ipc::devmgr_errors::INVALID_REQUEST, ipc_buf);
    }
}

/// `RecvGuard` diagnostic hook: one line at the start of a failure streak,
/// one more before the fatal exit.
fn recv_diag(stage: ipc::recv_guard::RecvFailureStage, err: i64)
{
    match stage
    {
        ipc::recv_guard::RecvFailureStage::First =>
        {
            std::os::seraph::log!(warn: "ipc_recv failing (err={err}); backing off");
        }
        ipc::recv_guard::RecvFailureStage::Fatal =>
        {
            std::os::seraph::log!(error: "ipc_recv wedged (err={err}); exiting");
        }
    }
}

/// TODO(#165): remove with `TEST_QUERY_DENY_DEVICE`. Reply with a SEND on
/// `driver_ep` badged `TEST_DENY_BADGE`, which carries none of the driver's
/// verb bits; `NO_DEVICE` when the driver is not running (`driver_ep == 0`)
/// and `INVALID_REQUEST` when the derive fails.
fn reply_deny_send(driver_ep: u64, ipc_buf: *mut u64)
{
    if driver_ep == 0
    {
        reply_status(ipc::devmgr_errors::NO_DEVICE, ipc_buf);
        return;
    }
    let Ok(derived) = syscall::cap_derive_badge(
        driver_ep,
        syscall::RIGHTS_EP_SEND,
        ipc::devmgr_labels::TEST_DENY_BADGE,
    )
    else
    {
        reply_status(ipc::devmgr_errors::INVALID_REQUEST, ipc_buf);
        return;
    };
    let reply = IpcMessage::builder(ipc::devmgr_errors::SUCCESS)
        .cap(derived)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer.
    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
}

/// Send a bodyless status reply (no caps) on the current request.
fn reply_status(code: u64, ipc_buf: *mut u64)
{
    let reply = IpcMessage::new(code);
    // SAFETY: ipc_buf is the registered IPC buffer.
    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
}

/// `QUERY_ACPI_TABLE` handler: locate the requested ACPI table and reply
/// with a read-only Memory cap on its region plus the `(region_base,
/// region_size, table_phys)` the caller needs to map and read it. devmgr
/// is the sole ACPI owner; consumers hold no ACPI memory caps of their own.
fn handle_query_acpi_table(
    firmware: &caps::Firmware,
    msg: &IpcMessage,
    badge: u64,
    ipc_buf: *mut u64,
)
{
    if badge & ipc::devmgr_labels::REGISTRY_QUERY_AUTHORITY == 0
    {
        reply_status(ipc::devmgr_errors::UNAUTHORIZED, ipc_buf);
        return;
    }
    if msg.word(0) != u64::from(ipc::DEVMGR_LABELS_VERSION)
    {
        reply_status(ipc::devmgr_errors::LABEL_VERSION_MISMATCH, ipc_buf);
        return;
    }
    let Some((region, table_phys)) = tables::locate_acpi_table(firmware, msg.word(1), msg.word(2))
    else
    {
        reply_status(ipc::devmgr_errors::NO_DEVICE, ipc_buf);
        return;
    };
    let Ok(memory_cap) = syscall::cap_derive(region.slot, syscall::RIGHTS_ALL)
    else
    {
        reply_status(ipc::devmgr_errors::INVALID_REQUEST, ipc_buf);
        return;
    };
    let reply = IpcMessage::builder(ipc::devmgr_errors::SUCCESS)
        .word(0, region.base)
        .word(1, region.size)
        .word(2, table_phys)
        .cap(memory_cap)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer.
    if unsafe { ipc::ipc_reply(&reply, ipc_buf) }.is_err()
    {
        let _ = syscall::cap_delete(memory_cap);
    }
}

/// `QUERY_SHUTDOWN_DEVICE` handler: serve pwrmgr the platform shutdown
/// actuator caps, gated on `SHUTDOWN_DEVICE_AUTHORITY`. devmgr runs no
/// shutdown logic. x86-64: a narrow `IoPort` over the caller-supplied
/// `PM1a` control port, served only when it is the FADT's `PM1a_CNT_BLK`,
/// plus the 8042 reset port. RISC-V: a Reset-only `SbiControl` derivation.
/// The caps are re-derived from devmgr's held caps on every call, so a
/// pwrmgr restart re-acquires them cleanly.
fn handle_query_shutdown_device(
    firmware: &caps::Firmware,
    msg: &IpcMessage,
    badge: u64,
    ipc_buf: *mut u64,
)
{
    if badge & ipc::devmgr_labels::SHUTDOWN_DEVICE_AUTHORITY == 0
    {
        reply_status(ipc::devmgr_errors::UNAUTHORIZED, ipc_buf);
        return;
    }
    if msg.word(0) != u64::from(ipc::DEVMGR_LABELS_VERSION)
    {
        reply_status(ipc::devmgr_errors::LABEL_VERSION_MISMATCH, ipc_buf);
        return;
    }

    arch::current::reply_shutdown_device(firmware, msg, ipc_buf);
}

// ── ECAM enumeration ────────────────────────────────────────────────────────

/// Carve, map, and scan one ECAM window, appending its functions to
/// `devices`. Returns `false`, logging why, when no aperture covers the
/// window, the VA reservation, page-table funding, or mapping fails, or the
/// scan stops for lack of memory before recording any function; a scan that
/// stops after recording some keeps them and counts as scanned.
fn enumerate_ecam(
    caps: &mut caps::DevmgrCaps,
    loc: &firmware::EcamLocation,
    devices: &mut Vec<pci::PciDevice>,
) -> bool
{
    std::os::seraph::log!(
        debug: "devmgr: ECAM segment {} phys={:#x} size={:#x} buses {}..={}",
        loc.segment,
        loc.phys_base,
        loc.size,
        loc.start_bus,
        loc.end_bus
    );
    // The ECAM cap stays held: no driver is delegated configuration space.
    // Once the window is scanned it is kept in `config_space` (`keep_ecam`).
    let Some(ecam_cap) = carve_subrange(caps, loc.phys_base, loc.size)
    else
    {
        std::os::seraph::log!(
            warn: "no aperture covers ECAM segment {}; not scanned",
            loc.segment
        );
        return false;
    };
    let ecam_pages = loc.size.div_ceil(PAGE_SIZE);
    let found_before = devices.len();
    let scanned = with_mmio_mapped(
        caps.self_aspace,
        ecam_cap,
        ecam_pages,
        "ECAM window",
        |va| {
            // SAFETY: `va` maps `loc.size` = (end_bus - start_bus + 1) MiB from
            // `loc.phys_base`, the configuration space of `start_bus`, until this
            // closure returns, and the scan reaches it only through `pci::Ecam`'s
            // raw volatile accessors ([`with_mmio_mapped`]).
            let ecam = unsafe { pci::Ecam::new(va, loc.start_bus, loc.end_bus) };
            firmware::scan::scan(&ecam, loc.segment, loc.start_bus, loc.end_bus, devices)
        },
    );
    let Some(scanned) = scanned
    else
    {
        std::os::seraph::log!(warn: "ECAM segment {} not scanned", loc.segment);
        return false;
    };
    keep_ecam(caps, loc, ecam_cap);
    if let Err(stop) = scanned
    {
        let (seg, bus, dev, func) = stop.bdf;
        std::os::seraph::log!(
            warn: "PCI scan stopped at {}:{}:{}.{}: no memory for the device list",
            seg,
            bus,
            dev,
            func
        );
        return devices.len() > found_before;
    }
    true
}

/// Map the `Mmio` cap `cap`, `pages` pages, into devmgr's own address space
/// `aspace` at fresh VA, run `access` on the mapping's base address, then
/// unmap it and return what `access` returned. Returns `None`, logged under
/// `what`, when the VA reservation, the page-table funding, or the mapping
/// fails; `access` then does not run.
///
/// The VA is a fresh reservation from the per-process arena that no Rust
/// object or IPC page occupies, mapped for exactly the call to `access`:
/// `access` may reach the `pages` pages from its base only through raw
/// volatile accesses, never a reference, and must not keep the address.
fn with_mmio_mapped<R>(
    aspace: u64,
    cap: u64,
    pages: u64,
    what: &str,
    access: impl FnOnce(u64) -> R,
) -> Option<R>
{
    let Ok(range) = reserve_pages(pages)
    else
    {
        std::os::seraph::log!(warn: "{}: no VA to map it", what);
        return None;
    };
    let va = range.va_start();
    if !std::os::seraph::fund_aspace_pt_budget(aspace, pages)
    {
        std::os::seraph::log!(warn: "{}: page-table budget not funded", what);
        unreserve_pages(range);
        return None;
    }
    // SAFETY: `va` starts `range`, a fresh reservation of `pages` pages from
    // the per-process arena, owned here: VA no Rust object or IPC page
    // occupies. `access` reaches the mapping only through raw volatile
    // accesses, never a reference, and `range` is unreserved only after the
    // unmap below (`mmio_map` § Safety).
    if unsafe { syscall::mmio_map(aspace, cap, va, 0) }.is_err()
    {
        std::os::seraph::log!(warn: "{}: mapping failed", what);
        unreserve_pages(range);
        return None;
    }
    let result = access(va);
    // SAFETY: `access` has returned, and was the mapping's only use; the span
    // is `range`, owned here.
    let _ = unsafe { syscall::mem_unmap(aspace, va, pages) };
    unreserve_pages(range);
    Some(result)
}

/// Keep a scanned ECAM window's cap and location in `caps.config_space` and
/// `caps.ecam_windows`, from which the configuration page of each function
/// devmgr binds is carved ([`bind::carve_function_config`]). A window the
/// tables cannot hold is logged; its cap stays held, and its functions get
/// no driver, since devmgr could not clear their Bus Master Enable.
fn keep_ecam(caps: &mut caps::DevmgrCaps, loc: &firmware::EcamLocation, ecam_cap: u64)
{
    let kept = caps.ecam_windows.try_reserve(1).is_ok()
        && matches!(
            caps.config_space.insert(ecam_cap, loc.phys_base, loc.size),
            Ok(true)
        );
    if kept
    {
        caps.ecam_windows.push(*loc);
    }
    else
    {
        std::os::seraph::log!(
            warn: "ECAM segment {}: configuration space not kept; its devices get no driver",
            loc.segment
        );
    }
}

// ── Aperture splitting helper ───────────────────────────────────────────────

/// Carve a narrow `Mmio` cap of `(phys, size)`, its end rounded up to a
/// page, out of whichever aperture covers it. The lower remainder
/// `[ap_base, phys)` and the upper remainder stay in the aperture table as
/// caps of their own: the surrounding range may host other useful MMIO
/// (e.g. the framebuffer lives below the ECAM in the same parent aperture on
/// x86-64 QEMU+OVMF). Returns `None` when no aperture covers the range, the
/// table cannot grow, or a split fails.
pub fn carve_subrange(caps: &mut caps::DevmgrCaps, phys: u64, size: u64) -> Option<u64>
{
    let carved = caps
        .apertures
        .carve(phys, size, PAGE_SIZE, |span: &Span<u64>, at| {
            // `mmio_split` takes the split point as an offset into the cap; the
            // table records each aperture's exact range, so no split it asks for
            // falls outside its cap.
            syscall::mmio_split(span.slot, at - span.base).map_err(|_| SplitError::Failed)
        });
    match carved
    {
        Ok(cap) => Some(cap),
        Err(CarveError::NotCovered) => None,
        Err(e) =>
        {
            std::os::seraph::log!(
                warn: "MMIO carve of {:#x}+{:#x} failed ({}); remainders kept",
                phys,
                size,
                if e == CarveError::NoMemory
                {
                    "no memory"
                }
                else
                {
                    "split"
                }
            );
            None
        }
    }
}

// ── Interrupt range allocator ───────────────────────────────────────────────

/// `SYS_IRQ_SPLIT`'s error for a split point outside the cap's range.
const IRQ_SPLIT_OUT_OF_RANGE: i64 = syscall_abi::SyscallError::InvalidArgument as i64;

/// devmgr's interrupt lines: single-line `Interrupt` caps carved out of its
/// Interrupt range cap, in any order (every line not yet carved stays in the
/// range table, so a device whose GSI lies below one already carved still
/// gets its line). A PCI device's line is held for the boot once carved
/// ([`firmware::lines::HeldLines`], [`line_cap`](Self::line_cap)), and every
/// device on it, the first included, gets a derivation of the held cap, so
/// devices that share an `INTx` line each bind their own receiver on it
/// (docs/device-management.md § Interrupt Delivery). The UART line is carved
/// exclusive instead ([`exclusive_line`](Self::exclusive_line)): nothing is
/// held, and its cap itself goes to the serial driver.
struct IrqRangeAllocator
{
    ranges: SpanTable<u64>,
    held: HeldLines<u64>,
    /// The firmware's Interrupt Source Overrides, from which each PCI line's
    /// `SYS_IRQ_REGISTER` mode is derived ([`Self::line_mode`]).
    overrides: Vec<firmware::acpi::SourceOverride>,
}

impl IrqRangeAllocator
{
    /// Exclusive upper bound recorded for the range cap: its true end is not
    /// queryable, and `SYS_IRQ_SPLIT` reports a split past it as out of
    /// range, which [`SpanTable::carve`] reads as the cap ending there.
    const RANGE_END_BOUND: u64 = 1 << 32;

    fn new(range_slot: u64, overrides: Vec<firmware::acpi::SourceOverride>) -> Self
    {
        let mut ranges = SpanTable::new();
        // A range cap starts at line 0 (init derives it from the root range).
        if range_slot != 0 && ranges.insert(range_slot, 0, Self::RANGE_END_BOUND) != Ok(true)
        {
            std::os::seraph::log!(warn: "IRQ range not recorded (no memory); no device IRQs");
        }
        Self {
            ranges,
            held: HeldLines::new(),
            overrides,
        }
    }

    /// The `SYS_IRQ_REGISTER` mode of PCI `INTx` line `gsi`, which every
    /// driver bound on the line passes (`arch::current::pci_line_mode`).
    fn line_mode(&self, gsi: u32) -> u64
    {
        arch::current::pci_line_mode(&self.overrides, gsi)
    }

    /// A device's own single-line cap on line `id`: a derivation of the
    /// line's held cap, the line carved off the range the first time any
    /// device asks for it. The caller owns the derivation and releases it
    /// with its device; the held cap stays with devmgr.
    ///
    /// # Errors
    /// [`LineError::Hold`] with [`HoldError::Split`]`(`[`CarveError::NotCovered`]`)`
    /// when no held range contains the line (it lies outside the range cap,
    /// or devmgr holds no range), another carve error when the split fails,
    /// or [`HoldError::NoMemory`]; [`LineError::Derive`] with the
    /// `SYS_CAP_DERIVE` error, the line staying held.
    fn line_cap(&mut self, id: u32) -> Result<u64, LineError<i64>>
    {
        let ranges = &mut self.ranges;
        self.held.derive(
            id,
            |id| Self::isolate_one(ranges, id),
            |held| syscall::cap_derive(held, syscall::RIGHTS_IRQ_NOTIFY),
        )
    }

    /// Carve the single-line cap for line `id` off the range for one device
    /// alone, holding nothing: no later device gets a cap on the line, which
    /// [`line_cap`](Self::line_cap) then finds not covered. For a line whose
    /// driver does not acknowledge each delivery promptly (the UART's).
    ///
    /// # Errors
    /// [`CarveError::NotCovered`] when no held range contains the line, any
    /// other carve error when the split fails.
    fn exclusive_line(&mut self, id: u32) -> Result<u64, CarveError>
    {
        Self::isolate_one(&mut self.ranges, id)
    }

    /// Carve the single-line cap for line `id` off the range table;
    /// [`CarveError::NotCovered`] when no held range contains it.
    fn isolate_one(ranges: &mut SpanTable<u64>, id: u32) -> Result<u64, CarveError>
    {
        ranges.carve(u64::from(id), 1, 1, |span: &Span<u64>, at| {
            let at = u32::try_from(at).map_err(|_| SplitError::OutOfRange)?;
            syscall::irq_split(span.slot, at).map_err(|e| {
                if e == IRQ_SPLIT_OUT_OF_RANGE
                {
                    SplitError::OutOfRange
                }
                else
                {
                    SplitError::Failed
                }
            })
        })
    }
}

/// Maximum payload byte length stored per [`DeviceInfoEntry`]. Sized to
/// fit the current driver-class payloads with headroom:
/// `VirtioPciStartupInfo::SIZE = 56` and `FramebufferInfo::SIZE = 24`.
pub const MAX_DEVICE_INFO_PAYLOAD: usize = 64;

/// Opaque catalog entry: devmgr stores payload bytes against a kind
/// discriminant and schema version, with no per-class interpretation.
/// The driver class deserialises via its own `from_bytes` after
/// verifying `kind` and `version`.
#[derive(Clone, Copy)]
pub struct DeviceInfoEntry
{
    pub kind: u32,
    pub version: u32,
    pub byte_len: u32,
    pub payload: [u8; MAX_DEVICE_INFO_PAYLOAD],
}

impl DeviceInfoEntry
{
    #[must_use]
    pub const fn empty() -> Self
    {
        Self {
            kind: 0,
            version: 0,
            byte_len: 0,
            payload: [0u8; MAX_DEVICE_INFO_PAYLOAD],
        }
    }

    /// Insert a serialised payload of the given kind/version. Returns
    /// `false` if the source bytes do not fit in [`MAX_DEVICE_INFO_PAYLOAD`].
    pub fn fill(&mut self, kind: u32, version: u32, bytes: &[u8]) -> bool
    {
        if bytes.len() > MAX_DEVICE_INFO_PAYLOAD
        {
            return false;
        }
        let Ok(byte_len) = u32::try_from(bytes.len())
        else
        {
            return false;
        };
        self.kind = kind;
        self.version = version;
        self.byte_len = byte_len;
        self.payload[..bytes.len()].copy_from_slice(bytes);
        for b in &mut self.payload[bytes.len()..]
        {
            *b = 0;
        }
        true
    }
}

/// Growable registry of spawned-device startup-info entries, populated as
/// drivers are spawned. Devmgr does not interpret payload bytes; the
/// per-class shape lives in the driver crate (e.g.
/// `virtio_core::VirtioPciStartupInfo::from_bytes`). An entry's badge is
/// its index + 1. Entries are never removed, a failed or withdrawn driver's
/// included, so a badge is never recycled.
#[derive(Default)]
pub struct DeviceCatalog
{
    pub entries: Vec<DeviceInfoEntry>,
}

impl DeviceCatalog
{
    /// Append an entry of `kind`/`version` holding `bytes` and return its
    /// badge, or `None` when the payload exceeds [`MAX_DEVICE_INFO_PAYLOAD`]
    /// or the catalog cannot grow.
    pub fn add(&mut self, kind: u32, version: u32, bytes: &[u8]) -> Option<u64>
    {
        let mut entry = DeviceInfoEntry::empty();
        if !entry.fill(kind, version, bytes)
        {
            return None;
        }
        self.entries.try_reserve(1).ok()?;
        self.entries.push(entry);
        u64::try_from(self.entries.len()).ok()
    }

    /// Append an entry that carries no startup info and return its badge,
    /// or `None` when the catalog cannot grow: the device badge of a driver
    /// that fetches no runtime metadata (serial, RTC, the test-only
    /// `test-fault` fixtures), so its ready report
    /// and death post name it like every other driver's.
    pub fn add_without_info(&mut self) -> Option<u64>
    {
        self.add(NO_INFO_KIND, 0, &[])
    }
}

/// The kind of a catalog entry that carries no startup info
/// ([`DeviceCatalog::add_without_info`]); `QUERY_DEVICE_INFO` on it replies
/// `INVALID_REQUEST`. No `ipc::device_info_kind` value is 0.
const NO_INFO_KIND: u32 = 0;

// No startup-info kind may collide with the no-info kind.
const _: () = assert!(
    ipc::device_info_kind::VIRTIO_PCI != NO_INFO_KIND
        && ipc::device_info_kind::FRAMEBUFFER != NO_INFO_KIND
);

/// What a spawned driver is served as: a device class, by the name its
/// declaration gives, or the IOMMU driver, which no registry query serves
/// (devmgr alone calls it, through its `iommu::IommuClient`).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Serves
{
    Class(ClassName),
    Iommu,
}

/// A driver the registry serves: its service endpoint, which devmgr owns,
/// for a driver bound to a PCI record the device caps devmgr carved for it,
/// and the driver's process handle while devmgr keeps it.
struct ServedDriver
{
    ep: u64,
    dev_caps: Option<bind::PciDeviceCaps>,
    /// For a driver bound to a platform record, the caps devmgr carved for
    /// it.
    platform_caps: Option<bind::PlatformDeviceCaps>,
    /// The driver's badged procmgr process handle: kept until its batch
    /// settles, and for the rest of the boot for a driver bound to a PCI
    /// record, which devmgr destroys when it withdraws it, and whose memory
    /// procmgr holds after its death until devmgr releases it when the
    /// driver performs DMA (`CREATE_DMA_HOLD`); 0 once released.
    process_handle: u64,
}

impl ServedDriver
{
    /// Withdraw the driver, live or dead: take its PCI device from it and
    /// destroy it ([`bind::withdraw_device`]), or destroy a driver with no
    /// such device through its process handle when devmgr still keeps one (a
    /// no-op for one procmgr has reaped); then [`Self::release`].
    fn withdraw(&self, ipc_buf: *mut u64)
    {
        if let Some(dev_caps) = &self.dev_caps
        {
            bind::withdraw_device(
                dev_caps,
                spawn::HeldChild {
                    process_handle: self.process_handle,
                    release_token: dev_caps.release_token,
                },
                ipc_buf,
            );
        }
        else
        {
            if let Some(platform) = &self.platform_caps
            {
                platform.take_from_driver();
            }
            if self.process_handle != 0
            {
                spawn::destroy_child(self.process_handle, ipc_buf);
            }
        }
        self.release();
    }

    /// Release what the registry holds for the driver: revoke its service
    /// endpoint (every copy derived from it: the driver's receive copy and
    /// every client SEND) and delete it, so callers queued on it return, and
    /// release the device's caps. The device's catalog entry stays, so its
    /// badge is never recycled.
    fn release(&self)
    {
        let _ = syscall::cap_revoke(self.ep);
        let _ = syscall::cap_delete(self.ep);
        if let Some(dev_caps) = &self.dev_caps
        {
            dev_caps.release();
        }
        if let Some(platform) = &self.platform_caps
        {
            platform.release();
        }
    }
}

/// A spawned driver its settle batch's roster records: its name, what it is
/// served as, its device badge, and what the registry serves once it
/// reports ready, its process handle included.
struct SpawnedDriver
{
    name: DriverName,
    serves: Serves,
    badge: u64,
    driver: ServedDriver,
}

/// Record a spawned driver in its batch's roster, withdrawing it
/// ([`ServedDriver::withdraw`]) when the roster cannot hold it (its room is
/// reserved before each spawn, so only a repeated device badge, which the
/// catalog never issues, reaches that).
fn record_spawned(roster: &mut Roster<SpawnedDriver>, spawned: SpawnedDriver, ipc_buf: *mut u64)
{
    if let Err(spawned) = roster.add(spawned.badge, spawned)
    {
        std::os::seraph::log!(
            warn: "{}: driver not recorded; device not served",
            spawned.name.as_str()
        );
        spawned.driver.withdraw(ipc_buf);
    }
}

/// The drivers the registry serves, one [`Served`] list per class, by the
/// class name each driver's declaration gives
/// ([`firmware::classes::Classes`]), held in [`RegistryState`]. A class's
/// list is filled as its drivers' batches settle; a served driver that dies
/// later is withdrawn and leaves a tombstone at its ordinal.
#[derive(Default)]
struct ServedDrivers
{
    classes: Classes<ServedDriver>,
    /// The IOMMU driver once its batch settles, at ordinal 0. Its service
    /// endpoint is the one the IOMMU client calls, so its record is never
    /// released: a death fails the client closed instead
    /// ([`Registry::withdraw_dead`]).
    iommu: Served<ServedDriver>,
    /// The client the IOMMU driver is called through, once it is ready.
    iommu_client: Option<Arc<iommu::IommuClient>>,
    /// Whether the IOMMU driver's death has withdrawn the confined
    /// devices' drivers.
    iommu_dependants_withdrawn: bool,
}

impl ServedDrivers
{
    /// The driver at `ordinal` of `class`; [`Lookup::Absent`] when no driver
    /// of the class is served there or `ordinal` is `None`.
    fn lookup(&self, class: &str, ordinal: Option<usize>) -> Lookup<'_, ServedDriver>
    {
        match (self.classes.get(class), ordinal)
        {
            (Some(served), Some(i)) => served.get(i),
            _ => Lookup::Absent,
        }
    }

    /// The driver at `ordinal` of the class in table slot `slot`;
    /// [`Lookup::Absent`] when there is none.
    fn slot_lookup(&self, slot: usize, ordinal: Option<usize>) -> Lookup<'_, ServedDriver>
    {
        match (self.classes.get_slot(slot), ordinal)
        {
            (Some(served), Some(i)) => served.get(i),
            _ => Lookup::Absent,
        }
    }

    /// The first live driver of `class`.
    fn first_live(&self, class: &str) -> Option<&ServedDriver>
    {
        self.classes.get(class).and_then(Served::first_live)
    }

    /// Whether the IOMMU driver has failed, so a confined device's driver
    /// can no longer be served.
    fn iommu_failed(&self) -> bool
    {
        self.iommu_client.as_ref().is_some_and(|c| c.failed())
    }

    /// Take out the served driver whose device badge is `badge`, leaving a
    /// tombstone at its ordinal, with its class: `None` for the IOMMU driver,
    /// whose record the caller drops, not releases, since its endpoint stays
    /// the client's and no thread calls a reused slot; a class's driver the
    /// caller withdraws. `None` when no driver is served under `badge`.
    fn take_dead(&mut self, badge: u64) -> Option<(Option<ClassName>, ServedDriver)>
    {
        if let Some(record) = self.iommu.withdraw(badge)
        {
            return Some((None, record));
        }
        self.classes
            .iter_mut()
            .find_map(|(class, served)| served.withdraw(badge).map(|d| (Some(*class), d)))
    }

    /// Take out the first served driver of a device the IOMMU confines,
    /// leaving its tombstone, for the caller to withdraw.
    fn take_confined(&mut self) -> Option<(ClassName, ServedDriver)>
    {
        let confined = |d: &ServedDriver| {
            d.dev_caps
                .as_ref()
                .is_some_and(bind::PciDeviceCaps::confined)
        };
        for (class, served) in self.classes.iter_mut()
        {
            let found = core::cell::Cell::new(false);
            let mut taken = None;
            served.withdraw_matching(
                |d| !found.get() && confined(d),
                |d| {
                    found.set(true);
                    taken = Some(d);
                },
            );
            if let Some(driver) = taken
            {
                return Some((*class, driver));
            }
        }
        None
    }
}

/// Settle `batch` against `watch` and serve its drivers: withdraw, in the
/// served classes, every driver whose death the settle takes outside the
/// batch, then revoke the batch's private endpoint and serve the batch
/// ([`Registry::serve`]).
fn settle_batch(
    batch: settle::SettleBatch,
    mut roster: Roster<SpawnedDriver>,
    watch: &mut settle::DriverWatch,
    catalog: &DeviceCatalog,
    registry: &Registry,
    bound: core::time::Duration,
    ipc_buf: *mut u64,
)
{
    let mut on_other_death = |post| registry.withdraw_dead(post, ipc_buf);
    let end = batch.settle(
        watch,
        &mut roster,
        catalog,
        ipc_buf,
        &mut on_other_death,
        bound,
    );
    if end == firmware::roster::SettleEnd::TimedOut
    {
        std::os::seraph::log!(
            warn: "settle: bound of {} ms elapsed with drivers pending",
            u64::try_from(bound.as_millis()).unwrap_or(u64::MAX)
        );
    }
    drop(batch);
    registry.serve(roster, ipc_buf);
}

/// Spawn and settle the boot batch: the boot pass over every record
/// ([`bind::boot_pass`]), from the declared boot modules `modules`. The
/// registry's workers start only after it, so every client sees the settled
/// drivers.
// too_many_arguments: the boot pass takes the records, the boot modules, and
// every table a bind and its settle batch carve from or record into.
#[allow(clippy::too_many_arguments)]
fn spawn_boot_drivers(
    records: &mut bind::Records,
    modules: Vec<(driver_binding::decl::DriverDecl, u64)>,
    caps: &mut caps::DevmgrCaps,
    irq_range: &mut IrqRangeAllocator,
    watch: &mut settle::DriverWatch,
    catalog: &mut DeviceCatalog,
    registry: &Registry,
    ipc_buf: *mut u64,
)
{
    let Some(batch) = settle::SettleBatch::new()
    else
    {
        std::os::seraph::log!(warn: "boot batch: no settle batch; no driver spawned");
        // A retained module cap pins the pool run init donated it from.
        for (_, module) in modules
        {
            drop(spawn::ModuleCapGuard::new(module));
        }
        return;
    };
    let mut roster = Roster::new();
    let death_eq = watch.death_eq();
    bind::boot_pass(
        records,
        modules,
        &mut bind::Carve {
            caps,
            irq_range,
            catalog,
        },
        &mut bind::Pass {
            batch: &batch,
            death_eq,
            roster: &mut roster,
        },
        ipc_buf,
    );
    settle_batch(
        batch,
        roster,
        watch,
        catalog,
        registry,
        settle::SETTLE_TIMEOUT,
        ipc_buf,
    );
}

/// Create a driver service endpoint devmgr owns; `None` when it cannot be
/// created.
fn create_service_endpoint() -> Option<u64>
{
    std::os::seraph::object_slab_retype(std::os::seraph::ENDPOINT_RETYPE_BYTES, |slab| {
        syscall::cap_create_endpoint(slab).ok()
    })
}

/// Spawn and settle the on-disk batch, on the control thread, as the job
/// `SET_DRIVERS_DIR` posts: the drivers-directory pass over the records no
/// boot driver was bound to ([`bind::drivers_dir_pass`]), each binary read
/// through `drivers_dir_cap`, the `LOOKUP | READ | READDIR`-attenuated
/// `/services/drivers/` subtree cap svcmgr delivered (namespace-protocol
/// rights, not kernel cap rights). A driver not spawned, or not ready when
/// the batch settles, is never served, and its device's carved caps are
/// released.
// too_many_arguments: the batch spans every bind of the pass; each argument
// is state one of its spawns consumes.
#[allow(clippy::too_many_arguments)]
fn spawn_on_disk_drivers(
    records: &mut bind::Records,
    caps: &mut caps::DevmgrCaps,
    irq_range: &mut IrqRangeAllocator,
    drivers_dir_cap: u64,
    watch: &mut settle::DriverWatch,
    catalog: &mut DeviceCatalog,
    registry: &Registry,
    ipc_buf: *mut u64,
)
{
    let Some(batch) = settle::SettleBatch::new()
    else
    {
        std::os::seraph::log!(warn: "on-disk batch: no settle batch; no driver spawned");
        return;
    };
    let mut roster = Roster::new();
    let death_eq = watch.death_eq();
    bind::drivers_dir_pass(
        records,
        drivers_dir_cap,
        |decl| registry.class_admits(decl),
        &mut bind::Carve {
            caps,
            irq_range,
            catalog,
        },
        &mut bind::Pass {
            batch: &batch,
            death_eq,
            roster: &mut roster,
        },
        ipc_buf,
    );
    settle_batch(
        batch,
        roster,
        watch,
        catalog,
        registry,
        settle::SETTLE_TIMEOUT,
        ipc_buf,
    );
    registry.log_mismatches();
}

// ── Test-only simple-device spawns ──────────────────────────────────────────

/// The per-driver objects of one simple-device spawn: the device badge of
/// its catalog entry, the service endpoint devmgr owns, and the driver's
/// devmgr query cap (a SEND badged with the device badge on the batch's
/// private endpoint).
struct SimpleDeviceSlots
{
    device_badge: u64,
    service_ep: u64,
    query_ep: u64,
}

impl SimpleDeviceSlots
{
    /// Create the service endpoint and the query cap for the catalog entry
    /// under `device_badge`. Returns `None`, logged under `name` and with
    /// what it created released, when either cannot be created.
    fn new(name: &str, device_badge: u64, batch: &settle::SettleBatch) -> Option<Self>
    {
        let Some(service_ep) = create_service_endpoint()
        else
        {
            std::os::seraph::log!(warn: "{}: failed to create service endpoint", name);
            return None;
        };
        let Ok(query_ep) =
            syscall::cap_derive_badge(batch.driver_ep(), syscall::RIGHTS_EP_SEND, device_badge)
        else
        {
            std::os::seraph::log!(warn: "{}: failed to derive the badged query cap", name);
            let _ = syscall::cap_delete(service_ep);
            return None;
        };
        Some(Self {
            device_badge,
            service_ep,
            query_ep,
        })
    }

    /// Release both caps of a spawn that never reached
    /// [`spawn::spawn_simple_device`].
    fn release(&self)
    {
        let _ = syscall::cap_delete(self.query_ep);
        let _ = syscall::cap_delete(self.service_ep);
    }
}

/// Spawn one simple-device driver through `config` (whose service endpoint,
/// query cap, and device badge are `slots`') and record it in `roster` as
/// `driver`, a name and the class it is served under. On a failed spawn the
/// service endpoint is released; the spawn path released the rest.
fn spawn_simple_into(
    driver: (DriverName, ClassName),
    config: &spawn::SimpleSpawnConfig,
    slots: &SimpleDeviceSlots,
    roster: &mut Roster<SpawnedDriver>,
    ipc_buf: *mut u64,
)
{
    let (name, class) = driver;
    if let Some(process_handle) = spawn::spawn_simple_device(config, ipc_buf)
    {
        std::os::seraph::log!("devmgr: {} driver spawned", name.as_str());
        let spawned = SpawnedDriver {
            name,
            serves: Serves::Class(class),
            badge: slots.device_badge,
            driver: ServedDriver {
                ep: slots.service_ep,
                dev_caps: None,
                platform_caps: None,
                process_handle,
            },
        };
        record_spawned(roster, spawned, ipc_buf);
    }
    else
    {
        let _ = syscall::cap_delete(slots.service_ep);
    }
}

/// TODO(#165): remove with the devmgr enumeration redesign.
///
/// Spawn and settle the test-only fault batch: three `test-fault` fixtures
/// from `/services/drivers/`, two that report ready and one that never does,
/// in one settle batch bounded by `TEST_FAULT_SETTLE_TIMEOUT_MS`, served as
/// the `test-fault` class. svctest observes the never-ready fixture withdrawn
/// and destroyed at the bound, then makes a served one die and observes its
/// withdrawal and tombstone.
fn spawn_test_fault_drivers(
    caps: &mut caps::DevmgrCaps,
    drivers_dir_cap: u64,
    watch: &mut settle::DriverWatch,
    catalog: &mut DeviceCatalog,
    registry: &Registry,
    ipc_buf: *mut u64,
)
{
    use ipc::test_fault_labels::{MODE_NEVER_READY, MODE_READY};

    let Some(batch) = settle::SettleBatch::new()
    else
    {
        std::os::seraph::log!(warn: "test-fault: no settle batch; no fixture spawned");
        return;
    };
    let mut roster = Roster::new();
    let death_eq = watch.death_eq();
    for mode in [MODE_READY, MODE_READY, MODE_NEVER_READY]
    {
        spawn_one_test_fault(
            caps,
            drivers_dir_cap,
            mode,
            &batch,
            death_eq,
            &mut roster,
            catalog,
            ipc_buf,
        );
    }
    let bound = core::time::Duration::from_millis(ipc::devmgr_labels::TEST_FAULT_SETTLE_TIMEOUT_MS);
    settle_batch(batch, roster, watch, catalog, registry, bound, ipc_buf);
}

/// TODO(#165): remove with [`spawn_test_fault_drivers`]. Spawn one
/// `test-fault` fixture in `mode` into the settle `batch`, recording it in
/// `roster`; its hardware cap is a throwaway endpoint, since the fixture
/// drives no device.
// too_many_arguments: the fixture's mode, the batch's objects, and the
// roster are each consumed per spawn, as for the production spawns.
#[allow(clippy::too_many_arguments)]
fn spawn_one_test_fault(
    caps: &caps::DevmgrCaps,
    drivers_dir_cap: u64,
    mode: u64,
    batch: &settle::SettleBatch,
    death_eq: u64,
    roster: &mut Roster<SpawnedDriver>,
    catalog: &mut DeviceCatalog,
    ipc_buf: *mut u64,
)
{
    if roster.try_reserve_one().is_err()
    {
        std::os::seraph::log!(warn: "test-fault: no memory to record a fixture; not spawned");
        return;
    }
    let Some(device_badge) = catalog.add_without_info()
    else
    {
        std::os::seraph::log!(warn: "test-fault: catalog entry not added; not spawned");
        return;
    };
    let requested_rights = u64::from(namespace_protocol::rights::READ);
    // SAFETY: `ipc_buf` is the control thread's IPC buffer (`info.ipc_buffer`,
    // registered at startup), passed down unchanged.
    let Some(walked) = (unsafe {
        ns_client::walk_to_file(drivers_dir_cap, b"test-fault", requested_rights, ipc_buf)
    })
    else
    {
        std::os::seraph::log!(warn: "test-fault: walk_to_file failed (binary missing on rootfs)");
        return;
    };
    let Some(slots) = SimpleDeviceSlots::new("test-fault", device_badge, batch)
    else
    {
        let _ = syscall::cap_delete(walked.file_cap);
        return;
    };
    let Some(hw_cap) = create_service_endpoint()
    else
    {
        std::os::seraph::log!(warn: "test-fault: no placeholder hardware cap");
        let _ = syscall::cap_delete(walked.file_cap);
        slots.release();
        return;
    };
    let words = [mode];
    let config = spawn::SimpleSpawnConfig {
        procmgr_ep: caps.procmgr_ep,
        bootstrap_ep: caps.self_bootstrap_ep,
        source: spawn::CreateSource::File {
            file_cap: walked.file_cap,
            size: walked.size,
        },
        service_ep: slots.service_ep,
        hw_cap,
        irq_cap: 0,
        query_ep: slots.query_ep,
        death_eq: Some(death_eq),
        device_badge,
        round1_words: &words,
        priority: ipc::sched_policy::AUX_DRIVER_PRIORITY,
    };
    spawn_simple_into(fixed::TEST_FAULT, &config, &slots, roster, ipc_buf);
}

/// TODO(#165): remove with the devmgr enumeration redesign.
///
/// Fault-injection shim for #176: spawn the on-disk `test-orphan` driver via
/// the normal [`spawn::spawn_simple_device`] path, where the driver
/// deliberately fails its round-2 request. The spawn helper's
/// orphan-teardown then destroys the child, returning its pages to memmgr.
///
/// Returns `Some(false)` when the spawn failed as designed (the unwind ran),
/// `Some(true)` if it unexpectedly succeeded, and `None` if the shim could not
/// be set up (driver binary absent, or endpoint/cap minting failed).
fn test_spawn_orphan(
    caps: &mut caps::DevmgrCaps,
    drivers_dir_cap: u64,
    ipc_buf: *mut u64,
) -> Option<bool>
{
    /// Arbitrary non-zero badge for the round-2 query cap; the round-2
    /// failure means it is never delivered.
    const QUERY_BADGE: u64 = 0x7E57;

    let requested_rights = u64::from(namespace_protocol::rights::READ);
    // SAFETY: `ipc_buf` is the control thread's IPC buffer (`info.ipc_buffer`,
    // registered at startup), passed down unchanged.
    let walked = unsafe {
        ns_client::walk_to_file(drivers_dir_cap, b"test-orphan", requested_rights, ipc_buf)
    }?;

    // Throwaway service + hw endpoints handed to the child in round 1. Ownership
    // of `hw_cap` transfers to `spawn_simple_device` (moved into the child or
    // deleted on failure); `service_ep` is retained here and released below.
    let service_ep = create_service_endpoint().unwrap_or(0);
    let hw_cap = create_service_endpoint().unwrap_or(0);
    let query_ep =
        syscall::cap_derive_badge(caps.registry_ep, syscall::RIGHTS_EP_SEND, QUERY_BADGE)
            .unwrap_or(0);
    if service_ep == 0 || hw_cap == 0 || query_ep == 0
    {
        std::os::seraph::log!(warn: "test-orphan: failed to mint shim caps");
        let _ = syscall::cap_delete(walked.file_cap);
        for cap in [service_ep, hw_cap, query_ep]
        {
            if cap != 0
            {
                let _ = syscall::cap_delete(cap);
            }
        }
        return None;
    }

    let config = spawn::SimpleSpawnConfig {
        procmgr_ep: caps.procmgr_ep,
        bootstrap_ep: caps.self_bootstrap_ep,
        source: spawn::CreateSource::File {
            file_cap: walked.file_cap,
            size: walked.size,
        },
        service_ep,
        hw_cap,
        irq_cap: 0,
        query_ep,
        // The child never runs past its bootstrap: no death observer.
        death_eq: None,
        device_badge: QUERY_BADGE,
        round1_words: &[],
        // Scheduling unspecified: procmgr defaults; the child is torn down anyway.
        priority: 0,
    };
    let spawned = spawn::spawn_simple_device(&config, ipc_buf);

    // `spawn_simple_device` owns `hw_cap` and `query_ep` (moved into the child
    // or released on failure). devmgr still holds the original `service_ep` —
    // there is no live driver to keep it for, so release it. An unexpected
    // success leaves a running child; destroy it.
    let _ = syscall::cap_delete(service_ep);
    if let Some(process_handle) = spawned
    {
        spawn::destroy_child(process_handle, ipc_buf);
    }
    Some(spawned.is_some())
}

/// Halt when devmgr's own address space cap carries `RIGHTS_AS_READ`, or
/// its rights cannot be read: procmgr mints every child's address space
/// without the right, a phys-class child's included, so no process translates
/// a child's pages (services/devmgr/docs/responsibilities.md § Capabilities
/// Received). devmgr is the phys-class child every boot creates, and no other
/// process checks its address space, so a mint that kept the right stops the
/// boot here instead of passing unseen.
fn refuse_translatable_aspace(self_aspace: u64)
{
    match syscall::cap_info(self_aspace, syscall::CAP_INFO_TAG_RIGHTS)
    {
        Ok(rights) if rights & syscall::RIGHTS_AS_READ == 0 =>
        {}
        Ok(_) =>
        {
            std::os::seraph::log!(error: "own address space carries RIGHTS_AS_READ, halting");
            halt_loop();
        }
        Err(e) =>
        {
            std::os::seraph::log!(error: "own address space rights unreadable ({e}), halting");
            halt_loop();
        }
    }
}

fn halt_loop() -> !
{
    loop
    {
        let _ = syscall::thread_yield();
    }
}
