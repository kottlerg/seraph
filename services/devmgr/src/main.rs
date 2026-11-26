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

mod acpi;
mod arch;
mod bind;
mod caps;
mod decls;
mod dma;
mod headroom;
mod hotplug;
mod intremap;
mod iommu;
mod pci;
mod phys;
mod platform;
mod settle;
mod spawn;
mod tables;

use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};

use driver_binding::decl::{ClassName, DriverName};
use firmware::classes::{Classes, MAX_CLASSES, Mismatch};
use firmware::hotplug::Slot;
use firmware::lines::{HeldLines, LineError};
use firmware::resource::{CarveError, Span, SpanTable, SplitError};
use firmware::restart::{Decline, Teardown};
use firmware::roster::{DeathPost, DriverState, Roster};
use firmware::served::{Lookup, Served};
use ipc::IpcMessage;
use ipc::serve::Reply;
use std::os::seraph::{reserve_pages, startup_info, unreserve_pages};
use syscall_abi::PAGE_SIZE;

/// Declare devmgr on the core path before it serves
/// (`procmgr_labels::DECLARE_NO_CORE`): it maps every block transfer's
/// buffer on its DMA endpoint, so a core written while it is held would wait
/// on it. A refusal leaves its core to the crash service's dump bound.
fn declare_no_core(procmgr: u64, ipc_buf: *mut u64)
{
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let _ = unsafe {
        ipc::ipc_call(
            procmgr,
            &IpcMessage::new(ipc::procmgr_labels::DECLARE_NO_CORE),
            ipc_buf,
        )
    };
}

#[expect(
    clippy::too_many_lines,
    reason = "devmgr's boot sequence in order (caps, enumeration, IOMMU, hotplug slots, boot \
              batch, registry) and its control loop; each step is one call holding state the \
              later steps and the loop consume, so a split threads that state through helpers \
              of seven or more arguments"
)]
fn main() -> !
{
    std::os::seraph::log::register_name(b"devmgr");
    let info = startup_info();

    // The IPC buffer is registered by `std::os::seraph::_start` and
    // page-aligned by the boot protocol. It is the control thread's: every
    // registry worker receives on its own page.
    #[expect(clippy::cast_ptr_alignment, reason = "the IPC buffer is page-aligned")]
    let ipc_buf = info.ipc_buffer.cast::<u64>();

    declare_no_core(info.procmgr_endpoint, ipc_buf);
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

    // acpid's requests, which the registry's workers post to this thread
    // (`acpi`), checked against the apertures as init gave them.
    let (acpi_jobs, acpi_queue) = std::sync::mpsc::channel();
    let mut acpi = acpi::AcpiService::new(&caps, acpi_queue);

    let (mut records, modules, slots, platform_grant) = enumerate_records(&mut caps);

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
    // of the driver spawned for it. A PCI function whose driver declares the
    // VirtIO status reset, and so is given the VirtIO register layout, gets an
    // entry of kind VIRTIO_PCI, the framebuffer one of kind FRAMEBUFFER;
    // every other entry carries no startup info.
    let mut catalog = DeviceCatalog::default();

    let mut watch = driver_watch(&records);

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
        acpi_jobs,
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
    // `None` runs every device unconfined, logged once, or, when the boot
    // policy requires DMA confinement, refuses every DMA-capable device
    // (`bind`'s DMA grant).
    let mut boot_modules = modules.drivers;
    caps.iommu = iommu::bring_up(
        &mut records.pci,
        &mut boot_modules,
        caps.pooled.take(),
        &mut caps,
        &mut watch,
        &mut catalog,
        &registry,
        ipc_buf,
    )
    .map(Arc::new);
    if let (Some(i), Some(d)) = (&caps.iommu, &caps.dma)
    {
        d.set_iommu(Arc::clone(i));
    }

    // The PCI Express hotplug slots the scan found, taken while the IOMMU
    // pass's records are the only ones bound, none managed until its grant
    // comes (`hotplug::Hotplug::grant`). The platform description tables
    // are known here only when a boot module's table matched; otherwise the
    // drivers-directory job reads them (`run_jobs`).
    let mut hotplug = hotplug::Hotplug::new(
        slots,
        &records,
        platform_grant,
        acpi.boot_apertures(),
        watch.job_note(),
        caps.self_aspace,
    );

    // VT-d interrupt remapping, turned on before any line is routed or any
    // message target minted, which the kernel's switch requires; each
    // source's entry is written as the source is given to a device.
    if let Some(i) = &caps.iommu
    {
        irq_range.remap = intremap::enable(i, &caps.firmware, irq_range.mint).map(Arc::new);
    }

    // The boot batch: the boot pass over every record, from the boot
    // modules, settled before the registry's workers start.
    spawn_boot_drivers(
        &mut records,
        boot_modules,
        &mut caps,
        &mut irq_range,
        acpi.bridges(),
        &mut watch,
        &mut catalog,
        &registry,
        ipc_buf,
    );

    // The registry's workers. This thread stays the control thread: it owns
    // the device records, the carve tables, the catalog, and the death
    // watch, and runs the work a request leaves for it (the drivers-directory
    // pass and settle after `SET_DRIVERS_DIR`, the on-demand pass and settle
    // after `BIND_DRIVERS`, and acpid's requests), every withdrawal of a
    // driver whose death the watch takes, and each create retry once due.
    start_registry_workers(&registry);
    std::os::seraph::log!("enumeration complete, registry open");

    let mut guard = ipc::recv_guard::RecvGuard::new(recv_diag);
    loop
    {
        headroom::hold_and_report();
        run_jobs(
            &registry,
            &mut records,
            &mut hotplug,
            &mut bind::Carve {
                caps: &mut caps,
                irq_range: &mut irq_range,
                catalog: &mut catalog,
                bridges: acpi.bridges(),
            },
            &mut watch,
            ipc_buf,
        );
        acpi.run(&records, &mut caps, &mut irq_range, &hotplug);
        hotplug.grant(acpi.bridges(), &mut records, &mut caps);
        hotplug.run(
            &registry,
            &mut records,
            &mut bind::Carve {
                caps: &mut caps,
                irq_range: &mut irq_range,
                catalog: &mut catalog,
                bridges: acpi.bridges(),
            },
            &mut watch,
            ipc_buf,
        );
        registry.withdraw_deaths(&watch, &mut caps.slot_bars, ipc_buf);
        // No longer than the earliest create retry is due, so it runs then
        // whatever else wakes the thread meanwhile.
        match watch.wait(registry.retry_wait_ms(now_ns()))
        {
            Ok(_) => guard.on_success(),
            Err(e) => guard.on_failure(e),
        }
    }
}

/// The death watch of the drivers the boot's records can be given: one per
/// device record (a record is bound at most once, by whichever pass binds
/// it) and the IOMMU driver. The watch's first death queue is sized to both
/// death observers of each; a driver past them, as a record appended later
/// gets, binds on a further queue (`settle::DriverWatch::new`). Halts,
/// logged, when the watch cannot be made.
fn driver_watch(records: &bind::Records) -> settle::DriverWatch
{
    let driver_count = records.count().saturating_add(IOMMU_DRIVERS);
    let Some(watch) = settle::DriverWatch::new(driver_count)
    else
    {
        std::os::seraph::log!(error: "no driver death watch, halting");
        halt_loop();
    };
    watch
}

/// Locate and scan every PCI ECAM window, then enumerate the platform
/// records, returning the device records, the classified boot modules, the
/// PCI Express hotplug slots the scan found, and whether the platform
/// description table grants native control of them: `None` when no boot
/// module's table matched, the tables then being read from the root
/// filesystem. Halts, logged, when no window is scanned or the records
/// cannot be held.
fn enumerate_records(
    caps: &mut caps::DevmgrCaps,
) -> (bind::Records, decls::BootModules, Vec<Slot>, Option<bool>)
{
    // Parse firmware to locate every PCI ECAM window. ACPI wins when RSDP is
    // present; DTB is the fallback; the arch platform default (QEMU virt
    // on riscv64, none on x86-64) is the last resort.
    let ecams = tables::discover_ecams(&caps.firmware);
    let mut devices: Vec<pci::PciDevice> = Vec::new();
    let mut slots: Vec<Slot> = Vec::new();
    let mut windows_scanned = 0usize;
    for loc in &ecams
    {
        if enumerate_ecam(caps, loc, &mut devices, &mut slots)
        {
            windows_scanned = windows_scanned.saturating_add(1);
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
    let (platform_records, platform_grant) = platform::enumerate(caps, &modules.tables);
    let records = firmware::pci_records::PciRecords::new(devices)
        .and_then(|pci| bind::Records::new(pci, platform_records));
    let Some(records) = records
    else
    {
        std::os::seraph::log!(error: "no memory for the device records, halting");
        halt_loop();
    };
    (records, modules, slots, platform_grant)
}

/// Monotonic time since the first call, in nanoseconds, for the restart
/// budgets. Saturates rather than wraps.
fn now_ns() -> u64
{
    static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    let start = START.get_or_init(std::time::Instant::now);
    u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

/// Start the registry's workers and let them receive: the
/// [`REGISTRY_WORKERS`] threads of a [`recv_pool::RecvPool`] on the registry
/// endpoint, each serving its requests with [`Registry::handle`], which first
/// holds devmgr's `CSpace` headroom ([`headroom::hold`]). Halts,
/// logged, when none can be started; fewer serve, logged, when some cannot.
fn start_registry_workers(registry: &Arc<Registry>)
{
    let pool = {
        let shared = Arc::clone(registry);
        recv_pool::RecvPool::new(registry.endpoint, recv_diag, move |msg, buf, reply| {
            shared.handle(msg, buf.as_ptr(), reply);
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
/// order: the drivers-directory job, the restarts of drivers that died, each
/// in a settle batch of its own, the create retries due
/// ([`RegistryState::retries`]), each in a batch of its own, then the
/// on-demand pass and settle. The
/// drivers-directory job reads the platform description tables from the
/// root filesystem and appends the matching one's records, unless a boot
/// module's table matched ([`platform::read_tables`]), settles the hotplug
/// slots' grants now that the tables are known (`hotplug`), and runs the
/// drivers-directory pass and settle, which binds the tables' devices too.
/// Each job, once done, is counted settled ([`Registry::finish_job`]),
/// which releases the queries waiting for it.
fn run_jobs(
    registry: &Registry,
    records: &mut bind::Records,
    hotplug: &mut hotplug::Hotplug,
    tables: &mut bind::Carve,
    watch: &mut settle::DriverWatch,
    ipc_buf: *mut u64,
)
{
    let (jobs, restarts, drivers_dir_cap, drivers_dir_path, bind_dir_cap, bind_dir_path) = {
        let mut state = registry.lock();
        (
            core::mem::take(&mut state.jobs),
            core::mem::take(&mut state.restarts),
            state.drivers_dir_cap,
            state.drivers_dir_path,
            state.bind_dir_cap,
            state.bind_dir_path,
        )
    };
    if jobs.iommu
    {
        restart_iommu(registry, tables, watch, ipc_buf);
        registry.finish_job(|_| ());
    }
    if jobs.drivers_dir
    {
        restart_iommu_if_due(registry, tables, watch, ipc_buf);
        let tables_dir_cap = core::mem::take(&mut registry.lock().tables_dir_cap);
        if hotplug.tables_known()
        {
            if tables_dir_cap != 0
            {
                let _ = syscall::cap_delete(tables_dir_cap);
            }
        }
        else
        {
            let grant =
                platform::read_tables(&tables.caps.firmware, tables_dir_cap, records, ipc_buf);
            hotplug.set_tables(grant);
        }
        hotplug.grant(tables.bridges, records, tables.caps);
        spawn_dir_drivers(
            "on-disk batch",
            records,
            tables,
            drivers_dir_cap,
            drivers_dir_path.as_bytes(),
            watch,
            registry,
            ipc_buf,
        );
        registry.log_mismatches();
        registry.finish_job(|_| ());
    }
    if jobs.restart
    {
        for source in restarts
        {
            restart_iommu_if_due(registry, tables, watch, ipc_buf);
            restart_driver(
                source,
                records,
                tables,
                drivers_dir_cap,
                drivers_dir_path.as_bytes(),
                watch,
                registry,
                ipc_buf,
            );
        }
        registry.finish_job(|_| ());
    }
    // Every create retry due by now, each in a batch of its own; one a
    // retry queues again falls due a delay later, at a later pass.
    let now = now_ns();
    while let Some(retry) = registry.take_due_retry(now)
    {
        restart_iommu_if_due(registry, tables, watch, ipc_buf);
        retry_driver(retry, records, tables, watch, registry, ipc_buf);
    }
    if jobs.bind
    {
        restart_iommu_if_due(registry, tables, watch, ipc_buf);
        spawn_dir_drivers(
            "on-demand batch",
            records,
            tables,
            bind_dir_cap,
            bind_dir_path.as_bytes(),
            watch,
            registry,
            ipc_buf,
        );
        let _ = syscall::cap_delete(bind_dir_cap);
        registry.finish_job(|state| {
            state.bind_dir_cap = 0;
            state.bind_dir_path = DirPath::EMPTY;
        });
    }
}

/// Run the IOMMU driver's restart when its serving instance's death has
/// posted it ([`Jobs::iommu`]) since the pass began: a settle takes the deaths
/// outside its batch, the IOMMU driver's among them, so a death can post the
/// restart mid-pass. Called before each step that binds or withdraws, each
/// hotplug job among them ([`hotplug::Hotplug::run`]), each of which calls
/// the driver, so none runs while the driver restarts.
fn restart_iommu_if_due(
    registry: &Registry,
    tables: &mut bind::Carve,
    watch: &mut settle::DriverWatch,
    ipc_buf: *mut u64,
)
{
    let due = core::mem::take(&mut registry.lock().jobs.iommu);
    if due
    {
        restart_iommu(registry, tables, watch, ipc_buf);
        registry.finish_job(|_| ());
    }
}

/// Restart the IOMMU driver ([`iommu::Iommu::restart`]), and withdraw,
/// without a restart, the driver of each device whose domain the restarted
/// instance did not rebuild, which it now blocks. A refused or failed restart
/// fails the driver closed ([`Registry::fail_iommu`]).
fn restart_iommu(
    registry: &Registry,
    tables: &mut bind::Carve,
    watch: &mut settle::DriverWatch,
    ipc_buf: *mut u64,
)
{
    let Some(iommu) = tables.caps.iommu.clone()
    else
    {
        return;
    };
    match iommu.restart(tables.caps, watch, tables.catalog, registry, ipc_buf)
    {
        Ok(replayed) =>
        {
            for badge in replayed.failed
            {
                registry.withdraw_unconfined(badge, &mut tables.caps.slot_bars, ipc_buf);
            }
        }
        Err(why) =>
        {
            std::os::seraph::log!(warn: "IOMMU driver not restarted: {}", why);
            registry.fail_iommu(&mut tables.caps.slot_bars, ipc_buf);
        }
    }
}

/// Work a registry request leaves for the control thread, each due at most
/// once at a time.
#[derive(Default)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "each flag is one job's due state, posted and taken on its own; no two combine into \
              a state"
)]
struct Jobs
{
    /// The drivers-directory pass and the on-disk batch's settle.
    drivers_dir: bool,
    /// The on-demand pass `BIND_DRIVERS` posts and its batch's settle.
    bind: bool,
    /// The restarts of served drivers that died
    /// ([`RegistryState::restarts`]) and their batches' settles; posted in
    /// the hold that takes each death.
    restart: bool,
    /// The restart of the IOMMU driver, whose serving instance died
    /// ([`Registry::iommu_died`]); run before every other job, whose binds
    /// and withdrawals call the driver, and, when a death posts it mid-pass,
    /// before the next step that binds ([`restart_iommu_if_due`]).
    iommu: bool,
}

/// The absolute path of a directory a request names, as a name block of the
/// request ([`ipc::name_block`]), copied out so it can be held beside the
/// directory's cap and read without the registry lock.
#[derive(Clone, Copy)]
struct DirPath
{
    bytes: [u8; ipc::devmgr_labels::DRIVERS_DIR_PATH_MAX],
    len: usize,
}

impl DirPath
{
    /// No path: the value before a request sets one.
    const EMPTY: Self = Self {
        bytes: [0; ipc::devmgr_labels::DRIVERS_DIR_PATH_MAX],
        len: 0,
    };

    /// The path `msg` carries from data word
    /// [`ipc::devmgr_labels::DRIVERS_DIR_PATH_WORD`]; `None` when the
    /// message carries none that fits.
    fn of(msg: &IpcMessage) -> Option<Self>
    {
        let path = ipc::name_block(
            msg,
            ipc::devmgr_labels::DRIVERS_DIR_PATH_WORD,
            ipc::devmgr_labels::DRIVERS_DIR_PATH_MAX,
        )?;
        let mut out = Self::EMPTY;
        out.bytes.get_mut(..path.len())?.copy_from_slice(path);
        out.len = path.len();
        Some(out)
    }

    /// The path's bytes.
    fn as_bytes(&self) -> &[u8]
    {
        self.bytes.get(..self.len).unwrap_or(&[])
    }
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
    /// cap svcmgr delivers with `SET_DRIVERS_DIR`; 0 until then. Kept once,
    /// so the drivers-directory pass it posts runs at most once per boot, and
    /// a driver not served by it replies `NO_DEVICE` thereafter (timed so
    /// degrades to its no-RTC path).
    drivers_dir_cap: u64,
    /// The absolute path of the directory `drivers_dir_cap` names, from the
    /// same request; empty until then.
    drivers_dir_path: DirPath,
    /// The `LOOKUP | READ | READDIR` cap of the platform description tables'
    /// directory (`devmgr_labels::PLATFORM_TABLES_PATH`) the same request
    /// carried, which the drivers-directory job takes, reads once and
    /// deletes; 0 when the request carried none, and once taken.
    tables_dir_cap: u64,
    /// The directory cap of the `BIND_DRIVERS` request whose pass is posted
    /// and not yet done, which the control thread deletes once the pass
    /// ends; 0 when none is, so a request is admitted only then.
    bind_dir_cap: u64,
    /// The absolute path of the directory `bind_dir_cap` names; empty when
    /// `bind_dir_cap` is 0.
    bind_dir_path: DirPath,
    /// The drivers whose restart is admitted and charged, for the restart
    /// job to start, in death order.
    restarts: Vec<bind::RestartSource>,
    /// The driver starts whose create, or read of the driver's entry, procmgr
    /// refused with an error a later one can outlive, each held until its
    /// retry is due ([`bind::Retry`]); the control thread runs each once due
    /// (`run_jobs`) and waits no longer than the earliest is due.
    retries: firmware::restart::Retries<bind::Retry>,
}

// A class name a `MINT_CLASS_SEND` request can carry is one a declaration
// can name: devmgr interns both into the same `ClassName`.
const _: () =
    assert!(ipc::devmgr_labels::MAX_CLASS_NAME_BYTES == driver_binding::decl::MAX_CLASS_BYTES);

impl RegistryState
{
    /// `MINT_CLASS_SEND` handler, past its gate and version check: intern the
    /// class `msg` names and mark it configured; then derive from
    /// `registry_ep` the SEND badged with the class's slot and the request's
    /// verb bits. `Err` with the reply label otherwise: `INVALID_REQUEST` for
    /// a bad verb mask or name, a full class table, or a failed derivation.
    fn mint_class_send(&mut self, registry_ep: u64, msg: &IpcMessage) -> Result<u64, u64>
    {
        let invalid = ipc::devmgr_errors::INVALID_REQUEST;
        let verbs = msg.word(1);
        // Checked before the class is interned, so a refused request leaves the
        // table as it was.
        if verbs == 0 || verbs & !ipc::VERB_BIT_MASK != 0
        {
            return Err(invalid);
        }
        let name = ipc::class_name_of(msg, 2)
            .and_then(ClassName::class)
            .ok_or(invalid)?;
        let slot = self.served.classes.configure(&name).map_err(|_| invalid)?;
        let badge = ipc::devmgr_labels::class_badge::encode(slot, verbs).ok_or(invalid)?;
        syscall::cap_derive_badge(registry_ep, syscall::RIGHTS_EP_SEND, badge).map_err(|_| invalid)
    }

    /// `SET_DRIVERS_DIR`'s state change: keep `cap` as the drivers-directory
    /// cap, with `path` its absolute path, and `tables` as the platform
    /// tables' directory cap (0 for none), and post the drivers-directory
    /// job, when no cap is kept yet. Returns whether it did; on `false` the
    /// caller releases `cap` and `tables`.
    fn install_drivers_dir(&mut self, cap: u64, tables: u64, path: &DirPath) -> bool
    {
        if self.drivers_dir_cap != 0
        {
            return false;
        }
        self.drivers_dir_cap = cap;
        self.drivers_dir_path = *path;
        self.tables_dir_cap = tables;
        Registry::post(self, |j| &mut j.drivers_dir)
    }

    /// The drivers directory's path once `SET_DRIVERS_DIR` has installed it;
    /// `None` before.
    fn drivers_dir(&self) -> Option<&[u8]>
    {
        (self.drivers_dir_cap != 0).then(|| self.drivers_dir_path.as_bytes())
    }

    /// `BIND_DRIVERS`'s state change: keep `cap`, with `path` its absolute
    /// path, as the directory of an on-demand pass and post it, when the
    /// drivers directory is installed and no earlier request's pass is posted.
    /// Returns whether it did; on `false` the caller releases `cap`.
    fn post_bind(&mut self, cap: u64, path: &DirPath) -> bool
    {
        if self.drivers_dir_cap == 0 || self.bind_dir_cap != 0
        {
            return false;
        }
        self.bind_dir_cap = cap;
        self.bind_dir_path = *path;
        Registry::post(self, |j| &mut j.bind)
    }
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
    /// The firmware tables and arch authority `QUERY_ACPI_TABLE`,
    /// `QUERY_SHUTDOWN_DEVICE` and `QUERY_ACPI_RESOURCES` serve from.
    firmware: Arc<caps::Firmware>,
    /// The control thread's acpid job channel ([`acpi::run_on_control`]).
    acpi: acpi::Jobs,
}

impl Registry
{
    fn new(job_note: u64, endpoint: u64, firmware: Arc<caps::Firmware>, acpi: acpi::Jobs) -> Self
    {
        Self {
            state: Mutex::new(RegistryState {
                served: ServedDrivers::default(),
                jobs: Jobs::default(),
                unsettled: 0,
                drivers_dir_cap: 0,
                drivers_dir_path: DirPath::EMPTY,
                tables_dir_cap: 0,
                bind_dir_cap: 0,
                bind_dir_path: DirPath::EMPTY,
                restarts: Vec::new(),
                retries: firmware::restart::Retries::new(),
            }),
            settled: Condvar::new(),
            job_note,
            endpoint,
            firmware,
            acpi,
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
        state.unsettled = state.unsettled.saturating_add(1);
        true
    }

    /// Wake the control thread to run the jobs posted.
    fn signal_jobs(&self)
    {
        let _ = syscall::notification_send(self.job_note, 1);
    }

    /// Count a job the control thread starts of its own unsettled, as
    /// [`Self::post`] counts a posted one: a create retry, which no request
    /// posts. [`Self::finish_job`] counts it done.
    fn begin_job(&self)
    {
        let mut state = self.lock();
        state.unsettled = state.unsettled.saturating_add(1);
    }

    /// Hold the create retries a batch queued, `batch` left empty, until
    /// each is due; each is released, logged, when the list cannot hold them.
    fn hold_retries(&self, batch: &mut firmware::restart::Retries<bind::Retry>)
    {
        if batch.is_empty()
        {
            return;
        }
        let held = self.lock().retries.append(batch);
        if held.is_err()
        {
            for retry in batch.drain()
            {
                std::os::seraph::log!(
                    warn: "{}: no memory to hold its create retry; given up",
                    retry.name()
                );
                retry.release();
            }
        }
    }

    /// Take the create retry due earliest, when it is due at `now_ns`.
    fn take_due_retry(&self, now_ns: u64) -> Option<bind::Retry>
    {
        self.lock().retries.take_due(now_ns)
    }

    /// How long the control thread may wait from `now_ns` before a create
    /// retry falls due, in milliseconds; `None` with none pending.
    fn retry_wait_ms(&self, now_ns: u64) -> Option<u64>
    {
        self.lock().retries.wait_ms(now_ns)
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

    /// Record the client the ready IOMMU driver is called through, so its
    /// death fails the client closed.
    fn set_iommu(&self, client: Arc<iommu::IommuClient>)
    {
        self.lock().served.iommu_client = Some(client);
    }

    /// Whether the IOMMU driver instance of device badge `badge` is served:
    /// its batch settled with it ready, and it has not died since.
    fn iommu_serves(&self, badge: u64) -> bool
    {
        self.lock().served.iommu.serves(badge)
    }

    /// Stop serving the IOMMU driver instance of device badge `badge`, a
    /// restart's candidate that failed its replay or commit and is being
    /// destroyed, so its death is not taken for the serving instance's. Its
    /// record's copy of the process handle is deleted; the caller destroys
    /// the instance through its own.
    fn forget_iommu_instance(&self, badge: u64)
    {
        let record = self.lock().served.iommu.withdraw(badge);
        if let Some(record) = record
        {
            let _ = syscall::cap_delete(record.process_handle);
        }
    }

    /// Serve a settled batch: append every driver that reported its device
    /// ready to its class, in spawn order, the order the registry's instance
    /// ordinals count, with its process handle; withdraw every other driver
    /// ([`ServedDriver::withdraw`]), which destroys one still pending (the
    /// settle's bound elapsed before it reported ready or died). Each driver is appended in a hold of its own;
    /// a query meanwhile sees the batch's drivers appended so far, and one
    /// that finds none waits for the batch's job to be done.
    fn serve(&self, roster: Roster<SpawnedDriver>, held: &mut SpanTable<u64>, ipc_buf: *mut u64)
    {
        for (state, spawned) in roster.into_outcomes()
        {
            let name = spawned.name;
            let (driver, why) = match state
            {
                DriverState::Ready =>
                {
                    let refused = self.lock().served.serve_ready(spawned);
                    match refused
                    {
                        None => continue,
                        Some(refused) => refused,
                    }
                }
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
            driver.withdraw(held, ipc_buf);
        }
    }

    /// Withdraw the served driver the death `post` names, if any: one a batch
    /// served that has since died. A post for a driver no class serves (one
    /// already withdrawn, or one destroyed when its batch timed out) changes
    /// nothing. A class's driver is then restarted when
    /// [`firmware::restart`] admits it: what the death and the registry say
    /// is read in the hold that takes the driver out, which posts the restart
    /// job, so a query from then on that would find no driver waits for the
    /// restart; what the withdrawal left is read once it is done
    /// ([`Self::admit_restart`]).
    ///
    /// The restart is decided on the reason procmgr gives the driver's
    /// process (`QUERY_PROCESS` on its process handle,
    /// [`firmware::restart::Death::reason`]), since the post can be the end
    /// of its main thread alone. The handle is read in a hold and the call is
    /// made outside it, since it blocks until procmgr answers; the handle
    /// stays valid between the holds, since only this thread, the control
    /// thread, withdraws a served driver and deletes its handle.
    fn withdraw_dead(&self, post: DeathPost, held: &mut SpanTable<u64>, ipc_buf: *mut u64)
    {
        let handle = self.lock().served.process_handle(post.badge);
        let death = firmware::restart::Death {
            posted: post.reason,
            answer: handle.and_then(|h| spawn::query_process(h, ipc_buf)),
        };
        let reason = death.reason();
        let (taken, entry) = {
            let mut state = self.lock();
            let taken = state.served.take_dead(post.badge);
            let entry = match &taken
            {
                Some((Some(_), driver)) =>
                {
                    let path = driver.restart.as_ref().map_or(&[][..], |r| &r.path[..]);
                    firmware::restart::restart_entry(
                        death,
                        driver.declined,
                        state.drivers_dir(),
                        path,
                    )
                    .map(|_| ())
                }
                _ => Err(firmware::restart::Refusal::Exited),
            };
            if entry.is_ok()
            {
                Self::post(&mut state, |j| &mut j.restart);
            }
            (taken, entry)
        };
        match taken
        {
            // The IOMMU driver's record holds nothing to release but its
            // copy of the process handle; the IOMMU driver's restart destroys
            // the instance through devmgr's own (`iommu::Iommu`).
            Some((None, record)) =>
            {
                let _ = syscall::cap_delete(record.process_handle);
                std::os::seraph::log!(
                    warn: "iommu: served driver of device {} died (reason={:#x})",
                    post.badge,
                    reason
                );
                self.iommu_died(post.badge, death, held, ipc_buf);
            }
            Some((Some(class), mut driver)) =>
            {
                std::os::seraph::log!(
                    warn: "{}: served driver of device {} died (reason={:#x}); withdrawn",
                    class.as_str(),
                    post.badge,
                    reason
                );
                // A platform record's caps cannot be carved again once
                // released, so a restart keeps them, taken from the dead
                // instance, for the next one.
                let kept = entry.ok().and_then(|()| driver.platform_caps.take());
                if let Some(kept) = &kept
                {
                    kept.take_from_driver();
                }
                let teardown = driver.withdraw(held, ipc_buf);
                let restarted = entry.and_then(|()| self.admit_restart(driver, teardown, kept));
                match restarted
                {
                    Ok(()) => std::os::seraph::log!(
                        "{}: device {}'s driver restarts",
                        class.as_str(),
                        post.badge
                    ),
                    Err(why) => std::os::seraph::log!(
                        warn: "{}: device {}'s driver not restarted: {}",
                        class.as_str(),
                        post.badge,
                        why
                    ),
                }
                if entry.is_ok()
                {
                    self.signal_jobs();
                }
            }
            None =>
            {}
        }
    }

    /// The second step of a restart [`Self::withdraw_dead`] admitted on the
    /// death: once `driver` is withdrawn, `teardown` saying what the
    /// withdrawal left of its device, charge its record's restart budget
    /// ([`firmware::restart::after_withdrawal`]) and queue it for the
    /// restart job, with `kept`, a platform record's caps taken from the
    /// dead instance, which a refusal releases.
    ///
    /// # Errors
    /// The [`firmware::restart::Refusal`].
    fn admit_restart(
        &self,
        driver: ServedDriver,
        teardown: Teardown,
        kept: Option<bind::PlatformDeviceCaps>,
    ) -> Result<(), firmware::restart::Refusal>
    {
        let Some(mut source) = driver.restart
        else
        {
            if let Some(kept) = kept
            {
                kept.release();
            }
            return Err(firmware::restart::Refusal::NotInstalled);
        };
        source.platform = kept;
        if let Err(why) =
            firmware::restart::after_withdrawal(teardown, || source.budget.try_charge(now_ns()))
        {
            source.release();
            return Err(why);
        }
        let mut state = self.lock();
        if state.restarts.try_reserve(1).is_ok()
        {
            state.restarts.push(source);
            return Ok(());
        }
        drop(state);
        source.release();
        Err(firmware::restart::Refusal::NoMemory)
    }

    /// The served IOMMU driver instance of device badge `badge` died, its end
    /// `death`: post the restart job ([`Jobs::iommu`]) when the client takes
    /// it for the instance it serves ([`iommu::IommuClient::begin_restart`])
    /// and the death admits one ([`firmware::iommu_restart::after_death`]),
    /// else, for an exit of its own, fail the driver closed. A restart candidate's
    /// death is the restart's own to handle.
    fn iommu_died(
        &self,
        badge: u64,
        death: firmware::restart::Death,
        held: &mut SpanTable<u64>,
        ipc_buf: *mut u64,
    )
    {
        let client = self.lock().served.iommu_client.clone();
        let Some(client) = client.filter(|c| c.is_instance(badge))
        else
        {
            return;
        };
        if let Err(why) = firmware::iommu_restart::after_death(death)
        {
            std::os::seraph::log!(warn: "IOMMU driver not restarted: {}", why);
            self.fail_iommu(held, ipc_buf);
            return;
        }
        if client.begin_restart(badge)
        {
            let posted = Self::post(&mut self.lock(), |j| &mut j.iommu);
            if posted
            {
                self.signal_jobs();
            }
        }
    }

    /// Withdraw, without a restart, the served driver of the device `badge`,
    /// whose domain a restarted IOMMU driver did not rebuild, so the device
    /// is blocked.
    fn withdraw_unconfined(&self, badge: u64, held: &mut SpanTable<u64>, ipc_buf: *mut u64)
    {
        let taken = self.lock().served.take_dead(badge);
        if let Some((Some(class), driver)) = taken
        {
            std::os::seraph::log!(
                warn: "{}: device {}'s domain not rebuilt by the restarted IOMMU driver; \
                       its driver withdrawn",
                class.as_str(),
                badge
            );
            driver.withdraw(held, ipc_buf);
        }
    }

    /// The IOMMU driver is not served with translation on (its death admits
    /// no restart, or its restart failed): fail its client closed
    /// ([`iommu::IommuClient::fail`]) and, once, withdraw every served
    /// driver of a device it confines, whose mappings can no longer change,
    /// one per hold of the lock.
    fn fail_iommu(&self, held: &mut SpanTable<u64>, ipc_buf: *mut u64)
    {
        let failed = self.lock().served.note_iommu_failed();
        let Some((client, first)) = failed
        else
        {
            return;
        };
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
            driver.withdraw(held, ipc_buf);
        }
    }

    /// Withdraw the served driver of the PCI function at `address`, if a
    /// class serves one: its device is being removed from a hotplug slot.
    /// Taken out of its class in one hold of the lock, leaving its tombstone,
    /// and withdrawn ([`ServedDriver::withdraw`]) once the lock is released,
    /// the caps on its device's BARs given back to the held BAR pages
    /// `held`. Returns whether a driver was withdrawn.
    fn withdraw_at(
        &self,
        address: (u16, u8, u8, u8),
        held: &mut SpanTable<u64>,
        ipc_buf: *mut u64,
    ) -> bool
    {
        let taken = self.lock().served.take_at(address);
        let Some((class, driver)) = taken
        else
        {
            return false;
        };
        let (segment, bus, dev, func) = address;
        std::os::seraph::log!(
            "{}: its device {}:{}:{}.{} is removed; withdrawn",
            class.as_str(),
            segment,
            bus,
            dev,
            func
        );
        driver.withdraw(held, ipc_buf);
        true
    }

    /// Withdraw every served driver whose death the watch's queue holds.
    fn withdraw_deaths(
        &self,
        watch: &settle::DriverWatch,
        held: &mut SpanTable<u64>,
        ipc_buf: *mut u64,
    )
    {
        while let Some(post) = watch.take_death()
        {
            self.withdraw_dead(post, held, ipc_buf);
        }
    }

    /// Log each class configured with no served driver and each served
    /// class no class request configured, read in one hold and logged after.
    #[expect(
        clippy::large_stack_frames,
        reason = "the `found` table (64 entries of about 34 B, about 2.2 KiB) and its `into_iter` \
                  copy; on the 32 KiB main-thread stack of devmgr"
    )]
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
    /// `ipc_buf`, replying before it returns. It first holds devmgr's
    /// `CSpace` headroom ([`headroom::hold`]); when that is refused, a
    /// request that would keep slots is refused
    /// (`firmware::headroom::registry_refusal`).
    fn handle(&self, msg: &IpcMessage, ipc_buf: *mut u64, reply: &mut Reply)
    {
        let held = headroom::hold();
        let badge = msg.badge;
        // A client whose SEND carries GRANT (`devmgr.bind`, svcmgr, init) can
        // move caps here with any label. `SET_DRIVERS_DIR` takes `caps[0]`
        // and `caps[1]`, `BIND_DRIVERS` `caps[0]`, and each owns their
        // release; every other cap a request carries is released here, so
        // none stays in devmgr's CSpace.
        let kept = match msg.label
        {
            ipc::devmgr_labels::SET_DRIVERS_DIR => 2,
            ipc::devmgr_labels::BIND_DRIVERS => 1,
            _ => 0,
        };
        for &cap in msg.caps().iter().skip(kept)
        {
            let _ = syscall::cap_delete(cap);
        }
        // A refused label keeps no cap it was sent (`kept` is 0 for it).
        if !held && let Some(code) = firmware::headroom::registry_refusal(msg.label)
        {
            reply.set_status(code);
            return;
        }
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
                    reply.set_status(ipc::devmgr_errors::UNAUTHORIZED);
                    return;
                };
                if msg.word(0) != u64::from(ipc::DEVMGR_LABELS_VERSION)
                {
                    reply.set_status(ipc::devmgr_errors::LABEL_VERSION_MISMATCH);
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
                    reply,
                );
            }
            ipc::devmgr_labels::MINT_CLASS_SEND => self.mint_class_send(msg, reply),
            ipc::devmgr_labels::SET_DRIVERS_DIR => self.set_drivers_dir(msg, ipc_buf, reply),
            ipc::devmgr_labels::QUERY_ACPI_TABLE =>
            {
                handle_query_acpi_table(&self.firmware, msg, badge, reply);
            }
            ipc::devmgr_labels::QUERY_SHUTDOWN_DEVICE =>
            {
                handle_query_shutdown_device(&self.firmware, msg, badge, reply);
            }
            ipc::devmgr_labels::QUERY_ACPI_RESOURCES if !acpi::on_control(msg.word(1)) =>
            {
                if Self::admits(msg, ipc::devmgr_labels::ACPI_AUTHORITY, reply)
                {
                    acpi::query_resources(&self.firmware, msg, reply);
                }
            }
            // The `QUERY_ACPI_RESOURCES` of the SCI, of `RESET_REG` and of
            // the sleep registers goes to the control thread, which owns the
            // interrupt lines and the kept memory grants.
            ipc::devmgr_labels::QUERY_ACPI_RESOURCES
            | ipc::devmgr_labels::ACPI_REGION_GRANT
            | ipc::devmgr_labels::ACPI_PCI_CONFIG
            | ipc::devmgr_labels::OSC_RESULT
            | ipc::devmgr_labels::BRIDGE_WINDOWS
            | ipc::devmgr_labels::PRT_TABLE
            | ipc::devmgr_labels::ACPI_HOTPLUG =>
            {
                self.acpi_request(msg, ipc::devmgr_labels::ACPI_AUTHORITY, reply);
            }
            ipc::devmgr_labels::QUERY_HOST_BRIDGE =>
            {
                self.acpi_request(msg, ipc::devmgr_labels::REGISTRY_QUERY_AUTHORITY, reply);
            }
            ipc::devmgr_labels::BIND_DRIVERS => self.bind_drivers(msg, ipc_buf, reply),
            ipc::devmgr_labels::WATCH_CLASS => self.watch_class(msg, reply),
            ipc::devmgr_labels::DECLINE_RESTART => self.decline_restart(msg, reply),
            ipc::devmgr_labels::QUERY_DEVICE_LOCATION => self.query_device_location(msg, reply),
            // QUERY_DEVICE_INFO and DRIVER_READY included: drivers send both
            // on their settle batch's private endpoint, never here.
            _ => reply.set_status(ipc::devmgr_errors::UNKNOWN_OPCODE),
        }
    }

    /// Whether `msg`'s badge carries `authority` and `msg` the compiled
    /// labels version; replies `UNAUTHORIZED` or `LABEL_VERSION_MISMATCH`
    /// otherwise.
    fn admits(msg: &IpcMessage, authority: u64, reply: &mut Reply) -> bool
    {
        if msg.badge & authority == 0
        {
            reply.set_status(ipc::devmgr_errors::UNAUTHORIZED);
            return false;
        }
        if msg.word(0) != u64::from(ipc::DEVMGR_LABELS_VERSION)
        {
            reply.set_status(ipc::devmgr_errors::LABEL_VERSION_MISMATCH);
            return false;
        }
        true
    }

    /// An acpid request the control thread runs, gated on `authority`:
    /// decoded here, run there ([`acpi::run_on_control`]), and replied to
    /// from here.
    fn acpi_request(&self, msg: &IpcMessage, authority: u64, reply: &mut Reply)
    {
        if !Self::admits(msg, authority, reply)
        {
            return;
        }
        match acpi::decode(msg)
        {
            Ok(request) =>
            {
                acpi::run_on_control(&self.acpi, || self.signal_jobs(), request, reply);
            }
            Err(code) => reply.set_status(code),
        }
    }

    /// `SET_DRIVERS_DIR`, svcmgr's handshake: keep the subtree cap it
    /// carries, the directory's absolute path (a name block from data word
    /// `DRIVERS_DIR_PATH_WORD`) and the platform tables' directory cap it may
    /// carry second, reply, and post the drivers-directory job, which the
    /// control thread runs, so svcmgr never waits on driver work. Every
    /// rejection releases the caps the kernel transferred into devmgr's
    /// `CSpace` before it replies, and a re-send keeps the first caps and
    /// releases the new ones; a request with no path is refused with
    /// `INVALID_REQUEST`; the job is posted at most once per boot.
    fn set_drivers_dir(&self, msg: &IpcMessage, ipc_buf: *mut u64, reply: &mut Reply)
    {
        let delivered_cap = msg.caps().first().copied();
        let tables_cap = msg.caps().get(1).copied().unwrap_or(0);
        let release = || {
            for &c in msg.caps().iter().take(2)
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
            reply.set_status(ipc::devmgr_errors::UNAUTHORIZED);
            return;
        }
        if msg.word(0) != u64::from(ipc::DEVMGR_LABELS_VERSION)
        {
            release();
            reply.set_status(ipc::devmgr_errors::LABEL_VERSION_MISMATCH);
            return;
        }
        let Some(new_cap) = delivered_cap
        else
        {
            reply.set_status(ipc::devmgr_errors::INVALID_REQUEST);
            return;
        };
        let Some(path) = DirPath::of(msg)
        else
        {
            release();
            reply.set_status(ipc::devmgr_errors::INVALID_REQUEST);
            return;
        };
        let installed = self.lock().install_drivers_dir(new_cap, tables_cap, &path);
        if installed
        {
            std::os::seraph::log!("devmgr: SET_DRIVERS_DIR cap installed");
        }
        else
        {
            // Idempotent re-send: keep the originals, drop the new ones.
            release();
        }
        reply_status(ipc::devmgr_errors::SUCCESS, ipc_buf);
        if installed
        {
            self.signal_jobs();
        }
    }

    /// `WATCH_CLASS`: create a Notification, add it to the watchers of the
    /// class the caller's class badge names, and reply with a wait-only copy
    /// and the ordinals the class has served, read in the hold that adds
    /// the watcher, so a change after it signals the watch. The
    /// Notification is created before the lock is taken, since the slab can
    /// call memmgr. A reply that fails deletes the copy, so the watch is
    /// found gone and dropped at the next sweep ([`release_if_gone`]).
    /// Logs nothing, as `QUERY_DEVICE` does not.
    fn watch_class(&self, msg: &IpcMessage, reply: &mut Reply)
    {
        let class = ipc::devmgr_labels::class_badge::decode(msg.badge)
            .map(|(slot, _)| slot)
            .filter(|&slot| self.lock().served.classes.get_slot(slot).is_some());
        let Some(slot) = class
        else
        {
            reply.set_status(ipc::devmgr_errors::UNAUTHORIZED);
            return;
        };
        if msg.word(0) != u64::from(ipc::DEVMGR_LABELS_VERSION)
        {
            reply.set_status(ipc::devmgr_errors::LABEL_VERSION_MISMATCH);
            return;
        }
        let Some(note) = std::os::seraph::object_slab_retype(
            std::os::seraph::NOTIFICATION_RETYPE_BYTES,
            |slab| syscall::cap_create_notification(slab).ok(),
        )
        else
        {
            reply.set_status(ipc::devmgr_errors::OUT_OF_RESOURCES);
            return;
        };
        let Ok(copy) = syscall::cap_derive(note, syscall::RIGHTS_NTF_WAIT)
        else
        {
            let _ = syscall::cap_delete(note);
            reply.set_status(ipc::devmgr_errors::INVALID_REQUEST);
            return;
        };
        let watched = self
            .lock()
            .served
            .classes
            .watch(slot, note, release_if_gone);
        let Ok(ordinals) = watched
        else
        {
            let _ = syscall::cap_delete(copy);
            let _ = syscall::cap_delete(note);
            reply.set_status(ipc::devmgr_errors::WATCHERS_FULL);
            return;
        };
        let answer = IpcMessage::builder(ipc::devmgr_errors::SUCCESS)
            .word(0, u64::try_from(ordinals).unwrap_or(u64::MAX))
            .cap(copy)
            .build();
        reply.set_or_delete_caps(answer);
    }

    /// `MINT_CLASS_SEND`: past its gate (`CLASS_AUTHORITY`) and version
    /// check, reply the class SEND [`RegistryState::mint_class_send`]
    /// derives, or its refusal. A reply that fails moves no cap: the SEND is
    /// devmgr's still, and deleted, so no slot leaks. Logs nothing, as
    /// `QUERY_DEVICE` does not.
    fn mint_class_send(&self, msg: &IpcMessage, reply: &mut Reply)
    {
        if msg.badge & ipc::devmgr_labels::CLASS_AUTHORITY == 0
        {
            reply.set_status(ipc::devmgr_errors::UNAUTHORIZED);
            return;
        }
        if msg.word(0) != u64::from(ipc::DEVMGR_LABELS_VERSION)
        {
            reply.set_status(ipc::devmgr_errors::LABEL_VERSION_MISMATCH);
            return;
        }
        let minted = self.lock().mint_class_send(self.endpoint, msg);
        match minted
        {
            Ok(send) =>
            {
                reply.set_or_delete_caps(
                    IpcMessage::builder(ipc::devmgr_errors::SUCCESS)
                        .cap(send)
                        .build(),
                );
            }
            Err(code) => reply.set_status(code),
        }
    }

    /// `DECLINE_RESTART`: mark the driver at the requested ordinal of the
    /// class the caller's class badge names as one whose death is not
    /// restarted ([`firmware::restart::decline`]), until `SET_DRIVERS_DIR`
    /// has arrived, from which point a restart can read the mark, so marks
    /// are sealed and the request refused. Logs nothing, as `QUERY_DEVICE`
    /// does not.
    fn decline_restart(&self, msg: &IpcMessage, reply: &mut Reply)
    {
        let class = ipc::devmgr_labels::class_badge::decode(msg.badge)
            .map(|(slot, _)| slot)
            .filter(|&slot| self.lock().served.classes.get_slot(slot).is_some());
        let Some(slot) = class
        else
        {
            reply.set_status(ipc::devmgr_errors::UNAUTHORIZED);
            return;
        };
        if msg.word(0) != u64::from(ipc::DEVMGR_LABELS_VERSION)
        {
            reply.set_status(ipc::devmgr_errors::LABEL_VERSION_MISMATCH);
            return;
        }
        let ordinal = instance_ordinal(msg);
        let outcome = {
            let mut state = self.lock();
            let sealed = state.drivers_dir().is_some();
            state
                .served
                .classes
                .get_slot_mut(slot)
                .map_or(Decline::Absent, |served| {
                    firmware::restart::decline(served, ordinal, sealed, |d| d.declined = true)
                })
        };
        let code = match outcome
        {
            Decline::Declined => ipc::devmgr_errors::SUCCESS,
            Decline::Sealed => ipc::devmgr_errors::REFUSED,
            Decline::Withdrawn => ipc::devmgr_errors::WITHDRAWN,
            Decline::Absent => ipc::devmgr_errors::NO_DEVICE,
        };
        reply.set_status(code);
    }

    /// `QUERY_DEVICE_LOCATION`: reply where the device of the driver at the
    /// requested ordinal of the class the caller's class badge names sits,
    /// the address of the PCI function devmgr bound it to, or why there is
    /// none. A query whose answer would name no driver waits as
    /// `QUERY_DEVICE`'s does. Logs nothing, as `QUERY_DEVICE` does not.
    fn query_device_location(&self, msg: &IpcMessage, reply: &mut Reply)
    {
        let class = ipc::devmgr_labels::class_badge::decode(msg.badge)
            .map(|(slot, _)| slot)
            .filter(|&slot| self.lock().served.classes.get_slot(slot).is_some());
        let Some(slot) = class
        else
        {
            reply.set_status(ipc::devmgr_errors::UNAUTHORIZED);
            return;
        };
        if msg.word(0) != u64::from(ipc::DEVMGR_LABELS_VERSION)
        {
            reply.set_status(ipc::devmgr_errors::LABEL_VERSION_MISMATCH);
            return;
        }
        let ordinal = instance_ordinal(msg);
        let located = {
            let state = self
                .lock_settled(|s| matches!(s.served.slot_lookup(slot, ordinal), Lookup::Absent));
            match state.served.slot_lookup(slot, ordinal)
            {
                Lookup::Live(driver) => driver
                    .dev_caps
                    .as_ref()
                    .map(|caps| caps.address)
                    .ok_or(ipc::devmgr_errors::NO_LOCATION),
                Lookup::Withdrawn => Err(ipc::devmgr_errors::WITHDRAWN),
                Lookup::Absent => Err(ipc::devmgr_errors::NO_DEVICE),
            }
        };
        match located
        {
            Ok((segment, bus, device, function)) =>
            {
                let answer = IpcMessage::builder(ipc::devmgr_errors::SUCCESS)
                    .word(
                        0,
                        ipc::devmgr_labels::pci_function(segment, bus, device, function),
                    )
                    .build();
                reply.set(answer);
            }
            Err(code) => reply.set_status(code),
        }
    }

    /// `BIND_DRIVERS`: keep the directory cap it carries and the directory's
    /// absolute path (a name block from data word `DRIVERS_DIR_PATH_WORD`),
    /// reply, and post the on-demand pass over it, which the control thread
    /// runs and which deletes the cap once it ends. Admitted only once `SET_DRIVERS_DIR`
    /// has delivered the drivers directory, whose pass binds first, and while
    /// no earlier request's pass is posted; every rejection, including a request
    /// with no path, releases the cap before it replies.
    fn bind_drivers(&self, msg: &IpcMessage, ipc_buf: *mut u64, reply: &mut Reply)
    {
        let delivered_cap = msg.caps().first().copied();
        let mut refuse = |code| {
            if let Some(c) = delivered_cap
            {
                let _ = syscall::cap_delete(c);
            }
            reply.set_status(code);
        };
        if msg.badge & ipc::devmgr_labels::BIND_AUTHORITY == 0
        {
            refuse(ipc::devmgr_errors::UNAUTHORIZED);
            return;
        }
        if msg.word(0) != u64::from(ipc::DEVMGR_LABELS_VERSION)
        {
            refuse(ipc::devmgr_errors::LABEL_VERSION_MISMATCH);
            return;
        }
        let Some(dir_cap) = delivered_cap
        else
        {
            refuse(ipc::devmgr_errors::INVALID_REQUEST);
            return;
        };
        let Some(path) = DirPath::of(msg)
        else
        {
            refuse(ipc::devmgr_errors::INVALID_REQUEST);
            return;
        };
        let posted = self.lock().post_bind(dir_cap, &path);
        if !posted
        {
            refuse(ipc::devmgr_errors::INVALID_REQUEST);
            return;
        }
        reply_status(ipc::devmgr_errors::SUCCESS, ipc_buf);
        self.signal_jobs();
    }
}

/// Whether the class watch `note` is gone: devmgr's copy of its Notification
/// is the only reference left (`CAP_INFO_SOLE_REFERENCE`), every copy its
/// watcher held being deleted. Deletes `note` then. Once it answers so it
/// keeps answering so, since only devmgr could take a new reference through
/// its copy. A failed inquiry answers `false`, keeping the watch. Makes no
/// call that blocks, so it runs under the registry lock.
fn release_if_gone(note: u64) -> bool
{
    let gone = syscall::cap_info(note, syscall::CAP_INFO_SOLE_REFERENCE) == Ok(1);
    if gone
    {
        let _ = syscall::cap_delete(note);
    }
    gone
}

/// Signal the class watch `note` ([`ipc::devmgr_labels::WATCH_CLASS_CHANGED`])
/// and return `true`, or release it and return `false` when it is gone
/// ([`release_if_gone`]). Makes no call that blocks.
fn signal_watcher(note: u64) -> bool
{
    if release_if_gone(note)
    {
        return false;
    }
    let _ = syscall::notification_send(note, ipc::devmgr_labels::WATCH_CLASS_CHANGED);
    true
}

/// The IOMMU drivers a boot can spawn: one, of the architecture's family.
const IOMMU_DRIVERS: usize = 1;

/// Reply to a device query with a `SEND_GRANT` badged `verb_bits` on the
/// service endpoint of the served driver `lookup` names; `WITHDRAWN` when
/// that driver was withdrawn, `absent` when no driver is served there, and
/// `INVALID_REQUEST` when the derivation fails. A reply that fails moves no
/// cap, so the derived one is deleted.
fn reply_served(lookup: Lookup<'_, ServedDriver>, verb_bits: u64, absent: u64, reply: &mut Reply)
{
    let driver = match lookup
    {
        Lookup::Live(driver) => driver,
        Lookup::Withdrawn => return reply.set_status(ipc::devmgr_errors::WITHDRAWN),
        Lookup::Absent => return reply.set_status(absent),
    };
    let Ok(derived) =
        syscall::cap_derive_badge(driver.ep, syscall::RIGHTS_EP_SEND_GRANT, verb_bits)
    else
    {
        return reply.set_status(ipc::devmgr_errors::INVALID_REQUEST);
    };
    reply.set_or_delete_caps(
        IpcMessage::builder(ipc::devmgr_errors::SUCCESS)
            .cap(derived)
            .build(),
    );
}

/// The instance ordinal a `QUERY_DEVICE` request selects: `data[1]` when sent, else 0, the first instance.
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
        let Some(payload) = entry.payload.get(..byte_len)
        else
        {
            reply_status(ipc::devmgr_errors::INVALID_REQUEST, ipc_buf);
            return;
        };
        for (word, chunk) in words.iter_mut().skip(3).zip(payload.chunks(8))
        {
            let mut buf = [0u8; 8];
            for (b, &c) in buf.iter_mut().zip(chunk)
            {
                *b = c;
            }
            *word = u64::from_le_bytes(buf);
        }
        let Some(used) = words.get(..word_count.saturating_add(3))
        else
        {
            reply_status(ipc::devmgr_errors::INVALID_REQUEST, ipc_buf);
            return;
        };
        let reply = IpcMessage::builder(ipc::devmgr_errors::SUCCESS)
            .words(0, used)
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
    reply: &mut Reply,
)
{
    if badge & ipc::devmgr_labels::REGISTRY_QUERY_AUTHORITY == 0
    {
        reply.set_status(ipc::devmgr_errors::UNAUTHORIZED);
        return;
    }
    if msg.word(0) != u64::from(ipc::DEVMGR_LABELS_VERSION)
    {
        reply.set_status(ipc::devmgr_errors::LABEL_VERSION_MISMATCH);
        return;
    }
    let Some((region, table_phys)) =
        tables::locate_acpi_table(firmware, msg.word(1), msg.word(2), msg.word(3))
    else
    {
        reply.set_status(ipc::devmgr_errors::NO_DEVICE);
        return;
    };
    let Ok(memory_cap) = syscall::cap_derive(region.slot, syscall::RIGHTS_ALL)
    else
    {
        reply.set_status(ipc::devmgr_errors::INVALID_REQUEST);
        return;
    };
    let answer = IpcMessage::builder(ipc::devmgr_errors::SUCCESS)
        .word(0, region.base)
        .word(1, region.size)
        .word(2, table_phys)
        .cap(memory_cap)
        .build();
    reply.set_or_delete_caps(answer);
}

/// `QUERY_SHUTDOWN_DEVICE` handler: serve pwrmgr the platform's firmware
/// shutdown authority, gated on `SHUTDOWN_DEVICE_AUTHORITY`. devmgr runs no
/// shutdown logic. RISC-V: a Reset-only `SbiControl` derivation, re-derived
/// from devmgr's held cap on every call, so a pwrmgr restart re-acquires it.
/// x86-64: `NO_DEVICE`, since pwrmgr reaches the ACPI sleep and reset
/// registers through acpid.
fn handle_query_shutdown_device(
    firmware: &caps::Firmware,
    msg: &IpcMessage,
    badge: u64,
    reply: &mut Reply,
)
{
    if badge & ipc::devmgr_labels::SHUTDOWN_DEVICE_AUTHORITY == 0
    {
        reply.set_status(ipc::devmgr_errors::UNAUTHORIZED);
        return;
    }
    if msg.word(0) != u64::from(ipc::DEVMGR_LABELS_VERSION)
    {
        reply.set_status(ipc::devmgr_errors::LABEL_VERSION_MISMATCH);
        return;
    }

    arch::current::reply_shutdown_device(firmware, msg, reply);
}

// ── ECAM enumeration ────────────────────────────────────────────────────────

/// Carve, map, and scan one ECAM window, appending its functions to
/// `devices` and the PCI Express hotplug slot each of them leads to to
/// `slots` (`firmware::hotplug::slots`). Returns `false`, logging why, when no aperture covers the
/// window, the VA reservation or the funded mapping fails, or the
/// scan stops for lack of memory before recording any function; a scan that
/// stops after recording some keeps them and counts as scanned.
fn enumerate_ecam(
    caps: &mut caps::DevmgrCaps,
    loc: &firmware_tables::EcamLocation,
    devices: &mut Vec<pci::PciDevice>,
    slots: &mut Vec<Slot>,
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
            let scanned =
                firmware::scan::scan(&ecam, loc.segment, loc.start_bus, loc.end_bus, devices);
            let found = devices.get(found_before..).unwrap_or_default();
            if firmware::hotplug::slots(&ecam, found, slots).is_err()
            {
                std::os::seraph::log!(
                    warn: "ECAM segment {}: no memory to hold its hotplug slots; some not managed",
                    loc.segment
                );
            }
            scanned
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
/// `what`, when the VA reservation or the mapping, page-table funding
/// included (`mmio_map_funded`), fails; `access` then does not run.
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
    // SAFETY: `va` starts `range`, a fresh reservation of `pages` pages from
    // the per-process arena, owned here: VA no Rust object or IPC page
    // occupies. `access` reaches the mapping only through raw volatile
    // accesses, never a reference, and `range` is unreserved only after the
    // unmap below (`mmio_map` § Safety).
    let mapped = unsafe { std::os::seraph::mmio_map_funded(aspace, cap, va, pages) };
    if mapped.is_err()
    {
        std::os::seraph::log!(warn: "{}: mapping failed", what);
        // SAFETY: the span is `range`, owned here, which no reference reaches.
        unsafe { unmap_window(aspace, range) };
        return None;
    }
    let result = access(va);
    // SAFETY: `access` has returned, and was the mapping's only use; the span
    // is `range`, owned here.
    unsafe { unmap_window(aspace, range) };
    Some(result)
}

/// Unmap the whole span of `range`, a reservation in devmgr's own address
/// space `aspace` that a map may have left pages in, and return it to the
/// arena. A map can fail with the pages before the failing one mapped, and
/// unmapping a page that is not mapped is harmless. When the unmap fails the
/// range stays reserved for devmgr's lifetime, so no later reservation lands
/// on a page still mapped there.
///
/// # Safety
/// No live Rust reference or object lies in the span (`mem_unmap` § Safety).
pub(crate) unsafe fn unmap_window(aspace: u64, range: std::os::seraph::ReservedRange)
{
    // SAFETY: the caller's contract.
    if unsafe { syscall::mem_unmap(aspace, range.va_start(), range.page_count()) }.is_ok()
    {
        unreserve_pages(range);
    }
}

/// Keep a scanned ECAM window's cap and location in `caps.config_space` and
/// `caps.ecam_windows`, from which the configuration page of each function
/// devmgr binds is carved ([`bind::carve_function_config`]). A window the
/// tables cannot hold is logged; its cap stays held, and its functions get
/// no driver, since devmgr could not clear their Bus Master Enable.
fn keep_ecam(caps: &mut caps::DevmgrCaps, loc: &firmware_tables::EcamLocation, ecam_cap: u64)
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
/// page, out of the held BAR pages ([`caps::DevmgrCaps::slot_bars`]) that
/// cover it, else out of whichever aperture covers it. The lower remainder
/// `[ap_base, phys)` and the upper remainder stay in their table as
/// caps of their own: the surrounding range may host other useful MMIO
/// (e.g. the framebuffer lives below the ECAM in the same parent aperture on
/// x86-64 QEMU+OVMF). Returns `None` when no aperture covers the range, the
/// table cannot grow, or a split fails.
pub fn carve_subrange(caps: &mut caps::DevmgrCaps, phys: u64, size: u64) -> Option<u64>
{
    carve_bar(caps, phys, size).map(|span| span.slot)
}

/// [`carve_subrange`], returning the carved cap with the range it covers,
/// under which a withdrawal gives a BAR's cap back to the held BAR pages
/// (`bind::PciDeviceCaps::release`).
pub fn carve_bar(caps: &mut caps::DevmgrCaps, phys: u64, size: u64) -> Option<Span<u64>>
{
    let carved = match caps.slot_bars.carve_span(phys, size, PAGE_SIZE, split_mmio)
    {
        Err(CarveError::NotCovered) => caps.apertures.carve_span(phys, size, PAGE_SIZE, split_mmio),
        carved => carved,
    };
    match carved
    {
        Ok(span) => Some(span),
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

/// A carve out of the apertures alone, with its error: `NotCovered` when no
/// aperture covers the range, which a caller that refuses such a range tells
/// apart from a failed carve. The held BAR pages of a managed slot's
/// functions are not among the apertures, so no such carve reaches them.
///
/// # Errors
/// The aperture table's [`CarveError`].
pub fn carve_aperture(caps: &mut caps::DevmgrCaps, phys: u64, size: u64)
-> Result<u64, CarveError>
{
    caps.apertures.carve(phys, size, PAGE_SIZE, split_mmio)
}

/// Split the `Mmio` cap of `span` at the absolute address `at`
/// (`SYS_MMIO_SPLIT`), for a carve out of an aperture table.
///
/// # Errors
/// [`SplitError::Failed`] when the split fails.
pub fn split_mmio(span: &Span<u64>, at: u64) -> Result<(u64, u64), SplitError>
{
    // `mmio_split` takes the split point as an offset into the cap; the
    // tables record each cap's exact range, so no split asked for falls
    // outside its cap.
    let offset = at.checked_sub(span.base).ok_or(SplitError::Failed)?;
    syscall::mmio_split(span.slot, offset).map_err(|_| SplitError::Failed)
}

/// Merge the `Mmio` caps of `lower` and `upper`, two adjacent spans of an
/// aperture table, into one cap over their joined range (`SYS_MMIO_MERGE`),
/// for a range given back to the table. `None` when the kernel refuses
/// them: caps that are not derivation siblings (pieces of two aperture caps
/// with different derivation parents), a cap with a derivation of its own,
/// or a joined cap the `CSpace` cannot back. Neither cap is changed then, and the table keeps
/// both.
#[must_use]
pub fn merge_mmio(lower: &Span<u64>, upper: &Span<u64>) -> Option<u64>
{
    syscall::mmio_merge(lower.slot, upper.slot).ok()
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
    /// A copy of the range cap carrying `RIGHTS_IRQ_MINT` alone, the
    /// authority every message-signaled target is minted through
    /// ([`Self::mint_message`]); 0 when devmgr holds no range or the copy
    /// could not be derived. Derived before any split: `SYS_IRQ_SPLIT`
    /// re-links a split cap's derivation children under its parent, so the
    /// copy outlives every split of the range. Also the authority of the
    /// kernel's interrupt remapping switch (`intremap::enable`).
    mint: u64,
    /// Interrupt remapping, when devmgr turned it on: every line routed and
    /// every target minted has its remapping entry written before a device
    /// can raise it.
    remap: Option<Arc<intremap::InterruptRemap>>,
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
        let mint = if range_slot == 0
        {
            0
        }
        else
        {
            syscall::cap_derive(range_slot, syscall::RIGHTS_IRQ_MINT).unwrap_or_else(|_| {
                std::os::seraph::log!(
                    warn: "IRQ mint authority not derived; no message-signaled interrupts"
                );
                0
            })
        };
        Self {
            ranges,
            held: HeldLines::new(),
            overrides,
            mint,
            remap: None,
        }
    }

    /// Interrupt remapping, when on, for a device whose message targets it
    /// clears at release.
    fn remap(&self) -> Option<Arc<intremap::InterruptRemap>>
    {
        self.remap.clone()
    }

    /// Route wired line `gsi` in `mode` through its single-line cap `cap`,
    /// which then holds the route (`SYS_IRQ_ROUTE`; a line `cap` routed
    /// already in `mode` is left as it is), and write its remapping entry
    /// when remapping is on. [`line_cap`](Self::line_cap) calls it for every
    /// derivation of a held line: once the route and the entry are in place
    /// the repeat changes neither (the IOMMU driver leaves an entry that
    /// already holds what `REMAP_SET` asks for untouched), so a shared line
    /// delivers throughout, and a write that failed is retried.
    ///
    /// # Errors
    /// The `SYS_IRQ_ROUTE` error, or `InvalidState` when the remapping entry
    /// was not written (logged); a line routed stays routed, held by `cap`.
    fn route(
        remap: Option<&intremap::InterruptRemap>,
        cap: u64,
        gsi: u32,
        mode: u64,
    ) -> Result<(), i64>
    {
        syscall::irq_route(cap, mode)?;
        match remap
        {
            Some(remap) => remap
                .line(cap, gsi, mode)
                .map_err(|_| syscall_abi::SyscallError::InvalidState as i64),
            None => Ok(()),
        }
    }

    /// Mint one message-signaled target (`SYS_IRQ_MSG_ALLOC`) for the
    /// function `rid` (`iommu_labels::requester_id`): an unbound `Interrupt`
    /// cap carrying `RIGHTS_IRQ_NOTIFY`, on the next CPU in turn with a free
    /// slot, whose message the kernel reports through `SYS_CAP_INFO`, its
    /// remapping entry written for the function when remapping is on. The
    /// caller owns it and releases it with its device
    /// (`bind::release_message`), which frees the target once no copy
    /// remains.
    ///
    /// # Errors
    /// The `SYS_IRQ_MSG_ALLOC` error, `InvalidCapability` when devmgr holds
    /// no mint authority, or `InvalidState` when the remapping entry was not
    /// written (logged), the target deleted.
    fn mint_message(&self, rid: u64) -> Result<u64, i64>
    {
        if self.mint == 0
        {
            return Err(syscall_abi::SyscallError::InvalidCapability as i64);
        }
        let cap = syscall::irq_msg_alloc(self.mint)?;
        if let Some(remap) = &self.remap
            && remap.message(cap, rid).is_err()
        {
            let _ = syscall::cap_delete(cap);
            return Err(syscall_abi::SyscallError::InvalidState as i64);
        }
        Ok(cap)
    }

    /// The `SYS_IRQ_REGISTER` mode of PCI `INTx` line `gsi`, which every
    /// driver bound on the line passes (`arch::current::pci_line_mode`).
    fn line_mode(&self, gsi: u32) -> u64
    {
        arch::current::pci_line_mode(&self.overrides, gsi)
    }

    /// A device's own single-line cap on line `id`: a derivation of the
    /// line's held cap, the line carved off the range the first time any
    /// device asks for it. The held cap routes the line in its mode
    /// ([`line_mode`](Self::line_mode)) and holds the route
    /// ([`route`](Self::route)), so the line keeps its target for the boot.
    /// The caller owns the derivation and releases it with its device; the
    /// held cap stays with devmgr.
    ///
    /// # Errors
    /// [`LineError::Hold`] with [`HoldError::Split`]`(`[`CarveError::NotCovered`]`)`
    /// when no held range contains the line (it lies outside the range cap,
    /// or devmgr holds no range), another carve error when the split fails,
    /// or [`HoldError::NoMemory`]; [`LineError::Derive`] with the
    /// [`route`](Self::route) or `SYS_CAP_DERIVE` error, the line staying
    /// held.
    fn line_cap(&mut self, id: u32) -> Result<u64, LineError<i64>>
    {
        let mode = self.line_mode(id);
        let remap = self.remap.as_deref();
        let ranges = &mut self.ranges;
        self.held.derive(
            id,
            |id| Self::isolate_one(ranges, id),
            |held| {
                Self::route(remap, held, id, mode)?;
                syscall::cap_derive(held, syscall::RIGHTS_IRQ_NOTIFY)
            },
        )
    }

    /// Carve the single-line cap for line `id` off the range for one device
    /// alone, holding nothing: no later device gets a cap on the line, which
    /// [`line_cap`](Self::line_cap) then finds not covered. For a line whose
    /// driver does not acknowledge each delivery promptly (the UART's). The
    /// cap routes the line in `mode` and holds the route
    /// ([`route`](Self::route)) until devmgr deletes it with its device.
    ///
    /// # Errors
    /// [`ExclusiveLineError::Carve`] with [`CarveError::NotCovered`] when no
    /// held range contains the line, or another carve error when the split
    /// fails; [`ExclusiveLineError::Route`] with the [`route`](Self::route)
    /// error, the cap deleted.
    fn exclusive_line(&mut self, id: u32, mode: u64) -> Result<u64, ExclusiveLineError>
    {
        let cap = Self::isolate_one(&mut self.ranges, id).map_err(ExclusiveLineError::Carve)?;
        if let Err(e) = Self::route(self.remap.as_deref(), cap, id, mode)
        {
            let _ = syscall::cap_delete(cap);
            return Err(ExclusiveLineError::Route(e));
        }
        Ok(cap)
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

/// Why [`IrqRangeAllocator::exclusive_line`] gave no cap.
#[derive(Debug)]
enum ExclusiveLineError
{
    /// The line could not be carved off the range.
    Carve(CarveError),
    /// The line could not be routed, or its remapping entry written: the
    /// `SYS_IRQ_ROUTE` error, or `InvalidState`.
    Route(i64),
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
        self.payload.fill(0);
        let Some(dst) = self.payload.get_mut(..bytes.len())
        else
        {
            return false;
        };
        dst.copy_from_slice(bytes);
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
    /// that fetches no runtime metadata (serial, RTC, and a PCI-bound driver
    /// that declares no `VirtIO` status reset, and so is given no `VirtIO`
    /// register layout), so its ready report and death post name it like
    /// every other driver's.
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
/// and the driver's process handle.
struct ServedDriver
{
    /// The driver's service endpoint, which [`Self::release`] revokes and
    /// deletes; 0 for the IOMMU driver, whose endpoints are the IOMMU
    /// client's (`iommu::IommuClient`), deleted only once a restarted
    /// instance commits, so no withdrawal of the driver deletes one a thread
    /// still drains.
    ep: u64,
    dev_caps: Option<bind::PciDeviceCaps>,
    /// For a driver bound to a platform record, the caps devmgr carved for
    /// it.
    platform_caps: Option<bind::PlatformDeviceCaps>,
    /// The driver's badged procmgr process handle, kept while the driver is
    /// served, on which devmgr reads the reason procmgr gives the process
    /// when it dies (`QUERY_PROCESS`) and destroys it when it withdraws it
    /// (for the IOMMU driver, devmgr's own copy, `iommu::Iommu`, does); for a
    /// driver bound to a PCI record whose declaration performs DMA, procmgr
    /// holds its memory after its death until devmgr releases it
    /// (`CREATE_DMA_HOLD`). Deleted when the driver is withdrawn.
    process_handle: u64,
    /// What devmgr restarts the driver from when it dies; `None` for the
    /// IOMMU driver, which devmgr restarts from what it keeps itself
    /// (`iommu::Iommu::restart`), and for a driver whose install path could
    /// not be kept.
    restart: Option<bind::RestartSource>,
    /// Its consumer declined its restart (`DECLINE_RESTART`).
    declined: bool,
}

impl ServedDriver
{
    /// Withdraw the driver, live or dead: take its PCI device from it and
    /// destroy it ([`bind::withdraw_device`]), or destroy a driver with no
    /// such device through its process handle when devmgr still keeps one (a
    /// no-op for one procmgr has reaped); then [`Self::release`], the caps on
    /// its device's BARs given back to the held BAR pages `held`. Returns
    /// what the withdrawal left ([`bind::withdraw_device`]); a driver with no
    /// PCI device leaves its device quiet and no DMA hold.
    fn withdraw(&self, held: &mut SpanTable<u64>, ipc_buf: *mut u64) -> Teardown
    {
        let teardown = if let Some(dev_caps) = &self.dev_caps
        {
            bind::withdraw_device(
                dev_caps,
                spawn::HeldChild {
                    process_handle: self.process_handle,
                    release_token: dev_caps.release_token,
                },
                ipc_buf,
            )
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
            Teardown {
                quiet: true,
                released: true,
            }
        };
        self.release(held);
        teardown
    }

    /// Release what the registry holds for the driver: revoke its service
    /// endpoint, when it holds one (every copy derived from it: the driver's
    /// receive copy and every client SEND), and delete it, so callers queued
    /// on it return, and release the device's caps, those on a PCI device's
    /// BARs given back to `held` (`bind::PciDeviceCaps::release`). The
    /// device's catalog entry stays, so its badge is never recycled.
    fn release(&self, held: &mut SpanTable<u64>)
    {
        if self.ep != 0
        {
            let _ = syscall::cap_revoke(self.ep);
            let _ = syscall::cap_delete(self.ep);
        }
        if let Some(dev_caps) = &self.dev_caps
        {
            dev_caps.release(held);
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
fn record_spawned(
    roster: &mut Roster<SpawnedDriver>,
    spawned: SpawnedDriver,
    held: &mut SpanTable<u64>,
    ipc_buf: *mut u64,
)
{
    if let Err(spawned) = roster.add(spawned.badge, spawned)
    {
        std::os::seraph::log!(
            warn: "{}: driver not recorded; device not served",
            spawned.name.as_str()
        );
        spawned.driver.withdraw(held, ipc_buf);
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
    /// The IOMMU driver's instances, each once its batch settles, in spawn
    /// order: the boot instance at ordinal 0, each restarted one after. A
    /// record holds no service endpoint (the endpoints are the client's)
    /// and a copy of the process handle, for the reason procmgr gives the
    /// process when it dies, deleted when the record is withdrawn; devmgr
    /// destroys the instance through its own (`iommu::Iommu`). The serving
    /// instance's death restarts the driver ([`Registry::iommu_died`]).
    iommu: Served<ServedDriver>,
    /// The client the IOMMU driver is called through, once it is ready.
    iommu_client: Option<Arc<iommu::IommuClient>>,
    /// Whether the IOMMU driver's failure has withdrawn the confined
    /// devices' drivers.
    iommu_dependants_withdrawn: bool,
}

impl ServedDrivers
{
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

    /// Whether the IOMMU driver has failed, so a confined device's driver
    /// can no longer be served.
    fn iommu_failed(&self) -> bool
    {
        self.iommu_client.as_ref().is_some_and(|c| c.failed())
    }

    /// Append the ready driver `spawned` to what it is served as. Returns the
    /// driver and why it is not served when it is not: the IOMMU confining
    /// its device has failed, or there is no room for it.
    fn serve_ready(&mut self, spawned: SpawnedDriver) -> Option<(ServedDriver, &'static str)>
    {
        let confined = spawned
            .driver
            .dev_caps
            .as_ref()
            .is_some_and(bind::PciDeviceCaps::confined);
        if confined && self.iommu_failed()
        {
            return Some((spawned.driver, "its device's IOMMU is gone; withdrawn"));
        }
        let serves = spawned.serves;
        let list = match serves
        {
            Serves::Class(class) => self.classes.intern(&class),
            Serves::Iommu => Some(&mut self.iommu),
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
        // Room was reserved just above, so the push holds.
        let _ = list.push(spawned.badge, spawned.driver);
        if let Serves::Class(class) = serves
        {
            self.classes.signal(&class, signal_watcher);
        }
        None
    }

    /// Record that the IOMMU driver failed: the client it is called through,
    /// and whether this is the first failure recorded, whose caller withdraws
    /// the confined devices' drivers. `None` when no client is recorded.
    fn note_iommu_failed(&mut self) -> Option<(Arc<iommu::IommuClient>, bool)>
    {
        let client = self.iommu_client.clone()?;
        let first = !core::mem::replace(&mut self.iommu_dependants_withdrawn, true);
        Some((client, first))
    }

    /// The process handle of the driver served under device badge `badge`,
    /// of a class or the IOMMU driver; `None` when none is served under it.
    fn process_handle(&mut self, badge: u64) -> Option<u64>
    {
        if let Some(record) = self.iommu.find(badge)
        {
            return Some(record.process_handle);
        }
        self.classes
            .iter_mut()
            .find_map(|(_, served)| served.find(badge))
            .map(|d| d.process_handle)
    }

    /// Take out the served driver whose device badge is `badge`, leaving a
    /// tombstone at its ordinal, with its class: `None` for the IOMMU driver,
    /// whose record holds nothing to release but its copy of the process
    /// handle, which the caller deletes, and whose death the caller fails the
    /// client on; a class's driver the caller withdraws, its
    /// class's watchers signalled. `None` when no driver is served under
    /// `badge`.
    fn take_dead(&mut self, badge: u64) -> Option<(Option<ClassName>, ServedDriver)>
    {
        if let Some(record) = self.iommu.withdraw(badge)
        {
            return Some((None, record));
        }
        let (class, driver) = self
            .classes
            .iter_mut()
            .find_map(|(class, served)| served.withdraw(badge).map(|d| (*class, d)))?;
        self.classes.signal(&class, signal_watcher);
        Some((Some(class), driver))
    }

    /// Take out the first served driver of a device the IOMMU confines,
    /// leaving its tombstone, for the caller to withdraw, its class's
    /// watchers signalled.
    fn take_confined(&mut self) -> Option<(ClassName, ServedDriver)>
    {
        let confined = |d: &ServedDriver| {
            d.dev_caps
                .as_ref()
                .is_some_and(bind::PciDeviceCaps::confined)
        };
        let mut taken = None;
        for (class, served) in self.classes.iter_mut()
        {
            let found = core::cell::Cell::new(false);
            served.withdraw_matching(
                |d| !found.get() && confined(d),
                |d| {
                    found.set(true);
                    taken = Some((*class, d));
                },
            );
            if taken.is_some()
            {
                break;
            }
        }
        let (class, driver) = taken?;
        self.classes.signal(&class, signal_watcher);
        Some((class, driver))
    }

    /// Take out the served driver of the PCI function at `address`, leaving
    /// its tombstone, for the caller to withdraw, its class's watchers
    /// signalled; `None` when no class serves one. A record is bound at most
    /// once, so at most one driver is served for an address's live record.
    fn take_at(&mut self, address: (u16, u8, u8, u8)) -> Option<(ClassName, ServedDriver)>
    {
        let at = |d: &ServedDriver| d.dev_caps.as_ref().is_some_and(|c| c.address == address);
        let mut taken = None;
        for (class, served) in self.classes.iter_mut()
        {
            let found = core::cell::Cell::new(false);
            served.withdraw_matching(
                |d| !found.get() && at(d),
                |d| {
                    found.set(true);
                    taken = Some((*class, d));
                },
            );
            if taken.is_some()
            {
                break;
            }
        }
        let (class, driver) = taken?;
        self.classes.signal(&class, signal_watcher);
        Some((class, driver))
    }
}

/// Settle `batch` against `watch` and serve its drivers: withdraw, in the
/// served classes, every driver whose death the settle takes outside the
/// batch, then revoke the batch's private endpoint and serve the batch
/// ([`Registry::serve`]). A withdrawal gives its device's BAR caps back to
/// the held BAR pages `held`.
#[expect(
    clippy::too_many_arguments,
    reason = "the settle takes the batch, its roster, the death watch, the catalog, the registry, \
              the held BAR pages its withdrawals give back to, and its bound"
)]
fn settle_batch(
    batch: settle::SettleBatch,
    mut roster: Roster<SpawnedDriver>,
    watch: &mut settle::DriverWatch,
    catalog: &DeviceCatalog,
    registry: &Registry,
    held: &mut SpanTable<u64>,
    bound: core::time::Duration,
    ipc_buf: *mut u64,
)
{
    let mut on_other_death = |post| registry.withdraw_dead(post, held, ipc_buf);
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
    registry.serve(roster, held, ipc_buf);
}

/// Spawn and settle the boot batch: the boot pass over every record
/// ([`bind::boot_pass`]), from the declared boot modules `modules`. The
/// registry's workers start only after it, so every client sees the settled
/// drivers.
#[expect(
    clippy::too_many_arguments,
    reason = "the boot pass takes the records, the boot modules, and every table a bind and its \
              settle batch carve from or record into"
)]
fn spawn_boot_drivers(
    records: &mut bind::Records,
    modules: Vec<(driver_binding::decl::DriverDecl, decls::Binary)>,
    caps: &mut caps::DevmgrCaps,
    irq_range: &mut IrqRangeAllocator,
    bridges: &firmware::acpid::Bridges,
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
            module.release();
        }
        return;
    };
    let mut roster = Roster::new();
    let mut retries = firmware::restart::Retries::new();
    bind::boot_pass(
        records,
        modules,
        &mut bind::Carve {
            caps,
            irq_range,
            catalog,
            bridges,
        },
        &mut bind::Pass {
            batch: &batch,
            watch,
            roster: &mut roster,
            retries: &mut retries,
        },
        ipc_buf,
    );
    settle_batch(
        batch,
        roster,
        watch,
        catalog,
        registry,
        &mut caps.slot_bars,
        settle::SETTLE_TIMEOUT,
        ipc_buf,
    );
    registry.hold_retries(&mut retries);
}

/// Create a driver service endpoint devmgr owns; `None` when it cannot be
/// created.
fn create_service_endpoint() -> Option<u64>
{
    std::os::seraph::object_slab_retype(std::os::seraph::ENDPOINT_RETYPE_BYTES, |slab| {
        syscall::cap_create_endpoint(slab).ok()
    })
}

/// Spawn and settle the batch of a drivers-directory pass, on the control
/// thread, as the job `SET_DRIVERS_DIR` or `BIND_DRIVERS` posts or a hotplug
/// arrival runs: the pass
/// over the records no earlier driver was bound to
/// ([`bind::drivers_dir_pass`]), each binary read through `dir_cap`, the
/// `LOOKUP | READ | READDIR`-attenuated directory cap the request delivered
/// (namespace-protocol rights, not kernel cap rights), and named under
/// `dir_path`, the directory's absolute path. A driver not spawned,
/// or not ready when the batch settles, is never served, and its device's
/// carved caps are released. `what` names the batch in a log line.
#[expect(
    clippy::too_many_arguments,
    reason = "the pass takes the records, the carve tables, the directory cap and its path, and \
              the watch, registry and IPC buffer its batch settles with"
)]
fn spawn_dir_drivers(
    what: &str,
    records: &mut bind::Records,
    carve: &mut bind::Carve,
    dir_cap: u64,
    dir_path: &[u8],
    watch: &mut settle::DriverWatch,
    registry: &Registry,
    ipc_buf: *mut u64,
)
{
    let Some(batch) = settle::SettleBatch::new()
    else
    {
        std::os::seraph::log!(warn: "{}: no settle batch; no driver spawned", what);
        return;
    };
    let mut roster = Roster::new();
    let mut retries = firmware::restart::Retries::new();
    bind::drivers_dir_pass(
        records,
        dir_cap,
        dir_path,
        carve,
        &mut bind::Pass {
            batch: &batch,
            watch,
            roster: &mut roster,
            retries: &mut retries,
        },
        ipc_buf,
    );
    settle_batch(
        batch,
        roster,
        watch,
        carve.catalog,
        registry,
        &mut carve.caps.slot_bars,
        settle::SETTLE_TIMEOUT,
        ipc_buf,
    );
    registry.hold_retries(&mut retries);
}

/// Restart the driver `source` describes in a settle batch of its own, on
/// the control thread, as the restart job runs it: its drivers-directory
/// entry read through `dir_cap`, the drivers directory at `dir_path`
/// ([`bind::restart`]), and the batch settled and served
/// ([`settle_batch`]), the new instance at its class's next ordinal.
#[expect(
    clippy::too_many_arguments,
    reason = "the restart takes its source, the records, the carve tables, the drivers directory's \
              cap and path, and the watch, registry and IPC buffer its batch settles with"
)]
fn restart_driver(
    source: bind::RestartSource,
    records: &bind::Records,
    carve: &mut bind::Carve,
    dir_cap: u64,
    dir_path: &[u8],
    watch: &mut settle::DriverWatch,
    registry: &Registry,
    ipc_buf: *mut u64,
)
{
    let Some(batch) = settle::SettleBatch::new()
    else
    {
        std::os::seraph::log!(
            warn: "{}: no settle batch; not restarted",
            source.name.as_str()
        );
        source.release();
        return;
    };
    let mut roster = Roster::new();
    let mut retries = firmware::restart::Retries::new();
    bind::restart(
        records,
        source,
        dir_cap,
        dir_path,
        carve,
        &mut bind::Pass {
            batch: &batch,
            watch,
            roster: &mut roster,
            retries: &mut retries,
        },
        ipc_buf,
    );
    settle_batch(
        batch,
        roster,
        watch,
        carve.catalog,
        registry,
        &mut carve.caps.slot_bars,
        settle::SETTLE_TIMEOUT,
        ipc_buf,
    );
    registry.hold_retries(&mut retries);
}

/// Retry the start `retry` holds, once its delay has passed, in a settle
/// batch of its own, on the control thread, as `run_jobs` runs it: a
/// start's record bound to the same driver, read and verified again from its
/// entry, or the records still unbound bound to an entry's driver
/// ([`bind::retry`]), and the batch settled and served ([`settle_batch`]), the new instance at
/// its class's next ordinal. The retry is counted a job while it runs, so a
/// query that would find no driver waits for its settle, as for a restart's.
fn retry_driver(
    retry: bind::Retry,
    records: &mut bind::Records,
    carve: &mut bind::Carve,
    watch: &mut settle::DriverWatch,
    registry: &Registry,
    ipc_buf: *mut u64,
)
{
    let Some(batch) = settle::SettleBatch::new()
    else
    {
        std::os::seraph::log!(warn: "{}: no settle batch; create not retried", retry.name());
        retry.release();
        return;
    };
    registry.begin_job();
    let mut roster = Roster::new();
    let mut retries = firmware::restart::Retries::new();
    bind::retry(
        records,
        retry,
        carve,
        &mut bind::Pass {
            batch: &batch,
            watch,
            roster: &mut roster,
            retries: &mut retries,
        },
        ipc_buf,
    );
    settle_batch(
        batch,
        roster,
        watch,
        carve.catalog,
        registry,
        &mut carve.caps.slot_bars,
        settle::SETTLE_TIMEOUT,
        ipc_buf,
    );
    registry.hold_retries(&mut retries);
    registry.finish_job(|_| ());
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
