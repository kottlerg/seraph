// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/vfsd/src/main.rs

//! Seraph virtual filesystem daemon.
//!
//! vfsd presents a unified virtual filesystem namespace to all other
//! processes via a synthetic system-root cap. A mount installs a
//! badged SEND on the underlying driver's namespace endpoint into
//! `VfsdRootBackend`; clients walk that root via `NS_LOOKUP` and reach
//! per-file node caps directly on the driver. After the walk vfsd is
//! out of the path: file reads, memory-cap requests, and closes go straight
//! from client to driver.
//!
//! vfsd self-mounts the Seraph root partition at `/` (and the boot ESP at
//! `/esp` and the data partitions at their paths) during startup, before
//! serving any request; the runtime `MOUNT` IPC mounts the root or the
//! data role at a path, resolved as the self-mount resolves it, and only
//! test fixtures call it. The swap partition is never mounted:
//! `GET_SWAP_PARTITION` hands its holder a raw partition cap.
//!
//! See `services/vfsd/README.md` for the design and
//! `services/fs/docs/fs-driver-protocol.md` for the driver-side protocol.

mod driver;
mod partition;
mod restart;
mod role_guids;
mod watch;
mod worker;
mod worker_pool;

use std::os::seraph::startup_info;
use std::sync::{Mutex, OnceLock, PoisonError};

use ipc::serve::{Reply, next_request};
use ipc::{IpcMessage, blk_labels, ns_labels};
use namespace_protocol::{GateError, NsError, compose_forward_lookup_rights, gate};
use root_backend::{Mount, VfsdRootBackend};
use worker_pool::WorkerPool;

/// Number of threads that recv on the service endpoint. A concurrency
/// knob that bounds no capacity: a request that finds every handler busy
/// waits in the endpoint's queue for the next free thread. No
/// service-endpoint request waits on another one's IPC, so the count cannot
/// deadlock: what a `MOUNT` handler blocks on (the worker pool, procmgr's
/// `CREATE_FROM_FILE`, whose binary reads go to the fs driver that minted
/// the file cap, the `NS_LOOKUP` walk the namespace thread serves, the
/// driver's bootstrap round, which its death ends, and its `FS_MOUNT` probe,
/// within `driver::PROBE_TIMEOUT_MS`) and what an `UNMOUNT` handler blocks on (the
/// driver's `FS_UNMOUNT` and its death, each within a bound, procmgr's
/// `DESTROY_PROCESS`, and the `NS_LOOKUP` walk for a fall-through cap)
/// never calls the service endpoint, and neither does the read of the
/// storage statement after a runtime root `MOUNT` (the `NS_LOOKUP` walk to
/// it and procmgr's `READ_VERIFIED`, whose read goes to the root fs
/// driver) nor the discovery of new
/// disks a `MOUNT` and the first `GET_SWAP_PARTITION` run before their role
/// lookup: devmgr's `QUERY_DEVICE`, the GPT reads of each new disk, a
/// scratch page from memmgr when a failed read lost the one held, and the
/// forced unmount of a mount on a new disk found withdrawn, which blocks as
/// an `UNMOUNT` does. A `GET_SWAP_PARTITION` handler also waits for the
/// discovery lock, held across one discovery, and for the swap lock, which
/// its holder keeps across the first request's discovery and one
/// `REGISTER_PARTITION` call to the block driver; none of devmgr, memmgr
/// and the block drivers calls vfsd.
const SERVICE_THREAD_COUNT: usize = 4;

/// Bound on a fall-through call the namespace thread makes to the root
/// filesystem. The thread serves every walk, so a root fs driver that stops
/// answering would otherwise hold up every lookup, those into healthy mounts
/// included; a call that has not returned within the bound is answered
/// `NsError::IoError`. The walk that finds a fall-through directory after an
/// unmount (`walk_root_mount_path`) takes the same bound, since it can run
/// on the watch thread.
const FALLTHROUGH_TIMEOUT_MS: u32 = 10_000;

/// Longest mount path a `MOUNT` or `UNMOUNT` request can name: the bytes
/// the request's data words carry after its first two words. Set by the IPC
/// message size, not a table; vfsd's only path limit, with each component
/// bounded by `namespace_protocol::MAX_NAME_LEN`.
const MAX_MOUNT_PATH_LEN: usize = (syscall_abi::MSG_DATA_WORDS_MAX - 2) * 8;

// Every path the storage statement names is one vfsd mounts at.
const _: () = assert!(storage_statement::MAX_PATH_LEN <= MAX_MOUNT_PATH_LEN);

// ── Data structures ────────────────────────────────────────────────────────

pub struct VfsdCaps
{
    pub procmgr_ep: u64,
    pub memmgr_ep: u64,
    /// The `block` class SEND init requested from devmgr; `QUERY_DEVICE` on
    /// it yields each disk's whole-disk cap.
    pub block_class: u64,
    pub service_ep: u64,
    pub fatfs_module_cap: u64,
    /// The fatfs module's size in bytes, which its cap, covering whole
    /// pages, does not give: the length of the signed object procmgr
    /// verifies.
    pub fatfs_module_len: u64,
    pub self_aspace: u64,
    /// Worker-owned bootstrap endpoint. Populated after the bootstrap worker
    /// thread is spawned. Main derives badged SEND caps on this slot to hand
    /// to each fatfs child as its creator endpoint.
    pub bootstrap_ep: u64,
    /// The device the firmware booted from, from round 1
    /// (`ipc::vfsd_bootstrap`).
    pub boot_device: ipc::vfsd_bootstrap::BootDevice,
}

// ── Bootstrap ──────────────────────────────────────────────────────────────
//
// init → vfsd bootstrap plan:
//   Round 1 (2 caps, ipc::vfsd_bootstrap::BOOT_DEVICE_WORDS data words):
//     caps[0]: service endpoint (vfsd receives on this)
//     caps[1]: the `block` class SEND on devmgr's registry endpoint
//     data:    the boot device record, laid out by `ipc::vfsd_bootstrap`
//   Round 2 (1 cap, 1 data word):
//     caps[0]: fatfs module memory cap
//     data[0]: the module's size in bytes, the signed object's length
//
// log_ep and procmgr_ep arrive via `ProcessInfo`/`StartupInfo`, not through
// this protocol.

fn bootstrap_caps(info: &std::os::seraph::StartupInfo, ipc_buf: *mut u64) -> Option<VfsdCaps>
{
    if info.creator_endpoint == 0
    {
        return None;
    }
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let round1 = unsafe { ipc::bootstrap::request_round(info.creator_endpoint, ipc_buf) }.ok()?;
    if round1.cap_count < 2 || round1.done
    {
        return None;
    }
    let boot_device =
        ipc::vfsd_bootstrap::BootDevice::from_words(round1.data.get(..round1.data_words)?)?;
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let round2 = unsafe { ipc::bootstrap::request_round(info.creator_endpoint, ipc_buf) }.ok()?;
    if round2.cap_count < 1 || !round2.done || round2.data_words < 1 || round2.data[0] == 0
    {
        return None;
    }

    Some(VfsdCaps {
        service_ep: round1.caps[0],
        block_class: round1.caps[1],
        procmgr_ep: info.procmgr_endpoint,
        memmgr_ep: info.memmgr_endpoint,
        fatfs_module_cap: round2.caps[0],
        fatfs_module_len: round2.data[0],
        self_aspace: info.self_aspace,
        bootstrap_ep: 0,
        boot_device,
    })
}

/// Log the boot device init handed over, one line per part.
fn log_boot_device(device: &ipc::vfsd_bootstrap::BootDevice)
{
    match device.esp
    {
        Some(esp) => std::os::seraph::log!(
            "boot ESP: GPT partition {} at block {} ({} blocks)",
            esp.partition_number,
            esp.start_lba,
            esp.size_lba
        ),
        None => std::os::seraph::log!("boot ESP: not reported"),
    }
    match device.location
    {
        Some(pci) => std::os::seraph::log!(
            "boot controller: PCI {:04x}:{:02x}:{:02x}.{}",
            pci.segment,
            pci.bus,
            pci.device,
            pci.function
        ),
        None => std::os::seraph::log!("boot controller: not reported"),
    }
}

/// The boot disk among `disks`, the disks held at startup: the one at the
/// location the firmware reported, compared whole, that carries the boot ESP
/// its device path describes (`gpt::find_boot_disk`). With none, logs why,
/// with what the firmware reported and where each held disk sits, and
/// returns `None`: then no role resolves on any disk, and the root
/// self-mount fails.
fn identify_boot_disk(
    device: &ipc::vfsd_bootstrap::BootDevice,
    disks: &[partition::Disk],
) -> Option<BootDisk>
{
    let esp = device.esp.map(|esp| gpt::PartitionDescriptor {
        type_guid: role_guids::EFI_SYSTEM_PARTITION,
        unique_guid: esp.partition_guid,
        number: esp.partition_number,
        first_lba: esp.start_lba,
        length_lba: esp.size_lba,
    });
    let found = match &esp
    {
        None => Err(String::from("the boot ESP was not reported")),
        Some(esp) =>
        {
            let held = disks
                .iter()
                .map(|d| (d.location.as_ref(), d.partitions.as_slice()));
            gpt::find_boot_disk(device.location.as_ref(), esp, held)
                .map(|index| BootDisk { index, esp: *esp })
                .map_err(|e| e.to_string())
        }
    };
    match found
    {
        Ok(boot) =>
        {
            let disk = disks.get(boot.index);
            std::os::seraph::log!(
                "boot disk: disk {} at {}",
                disk.map_or(0, |d| d.ordinal),
                Where(disk.and_then(|d| d.location))
            );
            Some(boot)
        }
        Err(why) =>
        {
            std::os::seraph::log!(
                error: "no boot disk: {why}; no disk takes a storage role (reported: controller at {})",
                Where(device.location)
            );
            if let Some(esp) = &esp
            {
                let guid = storage_statement::format_guid(&esp.unique_guid);
                std::os::seraph::log!(
                    error: "no boot disk: reported ESP: partition {}, GUID {}, blocks {}+{}",
                    esp.number,
                    core::str::from_utf8(&guid).unwrap_or_default(),
                    esp.first_lba,
                    esp.length_lba
                );
            }
            for d in disks
            {
                std::os::seraph::log!(
                    error: "no boot disk: held disk {} at {}, {} partitions",
                    d.ordinal,
                    Where(d.location),
                    d.partitions.len()
                );
            }
            None
        }
    }
}

/// A disk's or a controller's location, as the log lines write it.
struct Where(Option<ipc::vfsd_bootstrap::PciLocation>);

impl core::fmt::Display for Where
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
    {
        match self.0
        {
            Some(pci) => write!(
                f,
                "PCI {:04x}:{:02x}:{:02x}.{}",
                pci.segment, pci.bus, pci.device, pci.function
            ),
            None => f.write_str("no PCI location"),
        }
    }
}

// ── Entry point ────────────────────────────────────────────────────────────

#[expect(
    clippy::too_many_lines,
    reason = "vfsd's main is the in-order startup transcript — bootstrap caps, worker pool, block \
              class watch, GPT scratch alloc, disk discovery, namespace endpoint create, runtime \
              leak, namespace- and watch-thread spawn, service-thread fanout, then the calling \
              thread's own service loop. Each step depends on the prior step's locals; splitting introduces threading \
              those locals through helper arguments without buying any structural clarity"
)]
fn main() -> !
{
    std::os::seraph::log::register_name(b"vfsd");
    let info = startup_info();

    #[expect(
        clippy::cast_ptr_alignment,
        reason = "IPC buffer is registered by `std::os::seraph::_start` and page-aligned by the \
                  boot protocol; `info.ipc_buffer` carries the same VA as a `*mut u8` we \
                  reinterpret as `*mut u64` (4 KiB page alignment ≫ u64)"
    )]
    let ipc_buf = info.ipc_buffer.cast::<u64>();

    // A core of vfsd would be written through it, so the crash service
    // must write none: declare it on the core path before it serves
    // (`procmgr_labels::DECLARE_NO_CORE`). A refusal leaves its core to the
    // crash service's dump bound.
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let _ = unsafe {
        ipc::ipc_call(
            info.procmgr_endpoint,
            &ipc::IpcMessage::new(ipc::procmgr_labels::DECLARE_NO_CORE),
            ipc_buf,
        )
    };

    let Some(mut caps) = bootstrap_caps(info, ipc_buf)
    else
    {
        syscall::thread_exit();
    };

    std::os::seraph::log!("starting");
    log_boot_device(&caps.boot_device);

    if caps.service_ep == 0 || caps.block_class == 0
    {
        std::os::seraph::log!(error: "missing required endpoints");
        idle_loop();
    }

    // Spawn the worker pool before any MOUNT can arrive.
    let Some(pool) = WorkerPool::new()
    else
    {
        std::os::seraph::log!(error: "FATAL: worker pool setup failed");
        idle_loop();
    };
    caps.bootstrap_ep = pool.bootstrap_ep();

    // Watch the block class before the discovery, so a disk withdrawn after
    // it signals the watch thread (`watch::WatchSet`).
    let Some(watch) = watch::WatchSet::new(caps.block_class, ipc_buf)
    else
    {
        std::os::seraph::log!(error: "FATAL: block class watch setup failed");
        idle_loop();
    };

    // Allocate a single scratch memory cap for GPT block reads. The
    // BLK_READ_INTO_MEMORY contract requires the caller to supply the DMA
    // target memory cap; vfsd reuses one scratch page across every disk's
    // GPT reads, replacing it before the next disk when a failed read left
    // the slot empty (`partition::Discovery::discover`). vfsd never frees a
    // scratch page or its VA reservation.
    let Some(mut discovery) =
        partition::Discovery::new(caps.block_class, caps.memmgr_ep, caps.self_aspace, ipc_buf)
    else
    {
        std::os::seraph::log!(error: "FATAL: GPT scratch allocation failed");
        idle_loop();
    };

    // Hold every block device devmgr serves and parse each one's GPT: the
    // boot disk is found among them, and a statement may name a partition on
    // any of them.
    std::os::seraph::log!("querying devmgr for block devices");
    let disks = discovery.discover(ipc_buf);
    if disks.is_empty()
    {
        std::os::seraph::log!(error: "no block device available");
        idle_loop();
    }
    // The boot disk is fixed from the disks held now: the root and `/esp`
    // resolve on it alone, and every other role on it unless the storage
    // statement names its partition (docs/storage.md § GPT Role-GUID
    // Discovery).
    let boot_disk = identify_boot_disk(&caps.boot_device, &disks);

    // Namespace endpoint: separate recv surface for the cap-native
    // protocol (`NS_LOOKUP` / `NS_STAT` / `NS_READDIR`) against vfsd's
    // synthetic root. The service endpoint carries only `MOUNT`, `UNMOUNT`,
    // `GET_SYSTEM_ROOT_CAP` and `GET_SWAP_PARTITION`; the namespace
    // endpoint is separated so
    // a single dispatcher thread can serve every walk without
    // contending with mount-table mutations.
    let Some(namespace_ep) = std::os::seraph::create_endpoint()
    else
    {
        std::os::seraph::log!(error: "FATAL: cannot create namespace endpoint");
        idle_loop();
    };

    // Vfsd-internal system-root cap. Used for vfsd's own walks (e.g.
    // resolving `/services/fs/fatfs` before a worker spawns a fresh fatfs
    // instance via procmgr `CREATE_FROM_FILE`). Mirrors the cap shape
    // returned by `GET_SYSTEM_ROOT_CAP` to external callers.
    let badge = namespace_protocol::pack(
        namespace_protocol::NodeId::ROOT,
        namespace_protocol::NamespaceRights::ALL,
    );
    let Ok(system_root_cap) =
        syscall::cap_derive_badge(namespace_ep, syscall::RIGHTS_EP_SEND, badge)
    else
    {
        std::os::seraph::log!(error: "FATAL: vfsd internal system-root cap derive failed");
        idle_loop();
    };

    let boot_module_cap = caps.fatfs_module_cap;
    let runtime: &'static VfsdRuntime = Box::leak(Box::new(VfsdRuntime {
        caps,
        discovery: Mutex::new(discovery),
        disks: Mutex::new(disks),
        watch,
        pool,
        boot_module_cap: Mutex::new(boot_module_cap),
        namespace_ep,
        system_root_cap,
        root_backend: Mutex::new(VfsdRootBackend::new()),
        swap: Mutex::new(swap::SwapPartition::new()),
        boot_disk,
        statement: OnceLock::new(),
    }));

    // Spawn the namespace dispatcher first: the `/esp` self-mount below
    // takes the VFS spawn path, which re-enters vfsd's namespace endpoint
    // to resolve `/services/fs/fatfs`.
    if std::thread::Builder::new()
        .name("vfsd-namespace".into())
        .spawn(move || namespace_loop(runtime))
        .is_err()
    {
        std::os::seraph::log!(error: "FATAL: namespace thread spawn failed");
        idle_loop();
    }

    // Self-mount the root filesystem (and the ESP) before any service
    // thread can serve `GET_SYSTEM_ROOT_CAP`, so the seed system-root cap
    // is never handed out against an unmounted root. On failure vfsd still
    // serves: `GET_SYSTEM_ROOT_CAP` replies `NO_MOUNT` so init FATALs
    // promptly rather than blocking forever.
    if !self_mount(runtime, ipc_buf)
    {
        std::os::seraph::log!(warn: "root unavailable; system-root requests will fail");
    }

    // Spawn the service threads. Each runs the same recv/dispatch loop on
    // the shared service endpoint.
    for i in 0..SERVICE_THREAD_COUNT
    {
        let name = std::format!("vfsd-service-{i}");
        if std::thread::Builder::new()
            .name(name)
            .spawn(move || service_loop(runtime))
            .is_err()
        {
            std::os::seraph::log!(error: "FATAL: service helper thread spawn failed");
            idle_loop();
        }
    }

    // Main becomes the watch thread: it acts on driver deaths and disk
    // removals. The loss of the root ends vfsd from whichever thread finds
    // it (`watch::root_lost`), since an address-space exit ends the whole
    // process (docs/process-lifecycle.md § Exit reason). A death or a class
    // change from before the loop starts stays pending in the set, so the
    // loop acts on it once it waits.
    std::os::seraph::log!("entering the watch loop");
    watch::watch_loop(runtime)
}

/// Live state shared by every service-handler thread. `Box::leak`ed at
/// startup so workers and helper threads can reference it as `'static`
/// without per-thread `Arc` clones.
pub struct VfsdRuntime
{
    pub caps: VfsdCaps,
    /// Disk discovery's state: the next ordinal to query and the GPT scratch
    /// page. Held across a whole discovery, so one runs at a time; taken
    /// before `disks`, never after it.
    pub discovery: Mutex<partition::Discovery>,
    /// Every block device devmgr served vfsd, each with its whole-disk cap
    /// and its used GPT partition entries, in the order found: at startup,
    /// then by the discovery before each runtime role lookup (`find_partition`
    /// and the first `GET_SWAP_PARTITION`). A disk devmgr
    /// withdrew stays, marked removed, so a mount record's disk index keeps
    /// naming it. Held only across reads and updates of the table, never
    /// across IPC, and never together with `root_backend`.
    pub disks: Mutex<Vec<partition::Disk>>,
    /// The wait set the watch thread waits on (`watch::WatchSet`).
    pub watch: watch::WatchSet,
    pub pool: WorkerPool,
    /// Boot-module fatfs cap consumed (and zeroed) by the very first MOUNT.
    /// Mutex-guarded because that MOUNT may land on any handler thread.
    pub boot_module_cap: Mutex<u64>,
    /// Un-badged SEND on vfsd's own namespace endpoint. Source of every
    /// node cap minted on the synthetic root (the system-root cap and
    /// any descendants that resolve to vfsd-local nodes — currently
    /// none, since the synthetic root only carries External entries).
    pub namespace_ep: u64,
    /// Badged SEND on `namespace_ep` addressing the synthetic root at
    /// full namespace rights. Vfsd's own copy of the system-root cap,
    /// minted at boot. Used by worker threads to walk the namespace
    /// (e.g. resolving `/services/fs/fatfs`) before issuing
    /// `procmgr_labels::CREATE_FROM_FILE`.
    pub system_root_cap: u64,
    /// Synthetic system-root backend. Service handlers append entries
    /// on each successful MOUNT; the namespace dispatcher reads on each
    /// `NS_*` request.
    pub root_backend: Mutex<VfsdRootBackend>,
    /// The swap partition cap vfsd keeps, registered by the first
    /// `GET_SWAP_PARTITION` that finds the partition. The lock is held
    /// across a whole hand-out, so the first request's registration and a
    /// later request's revoke never interleave.
    pub swap: Mutex<swap::SwapPartition>,
    /// The disk the firmware booted from, identified once at startup
    /// ([`identify_boot_disk`]); `None` when there is none, and then no
    /// role resolves on any disk. A disk index in `disks`, which keeps a
    /// removed disk, so it names the same disk for the rest of the boot.
    pub boot_disk: Option<BootDisk>,
    /// The storage statement (`storage_statement::PATH`), read once after
    /// the root mount ([`read_statement`]); unset until then, and read as
    /// naming nothing ([`VfsdRuntime::statement`]).
    pub statement: OnceLock<storage_statement::Statement>,
}

impl VfsdRuntime
{
    /// The storage statement read after the root mount, or the statement
    /// that names nothing before it, or when none was taken.
    fn statement(&self) -> &storage_statement::Statement
    {
        static NOTHING: storage_statement::Statement = storage_statement::Statement::new();
        self.statement.get().unwrap_or(&NOTHING)
    }
}

/// The boot disk: its index in `VfsdRuntime::disks` and the boot ESP the
/// firmware's device path describes, which it carries.
#[derive(Clone, Copy, Debug)]
pub struct BootDisk
{
    pub index: usize,
    pub esp: gpt::PartitionDescriptor,
}

// ── Service loop ───────────────────────────────────────────────────────────

/// `RecvGuard` diagnostic hook: one line at the start of a failure streak,
/// one more before the fatal exit. Shared by the service, namespace, and
/// bootstrap-worker receive loops.
pub(crate) fn recv_diag(stage: ipc::recv_guard::RecvFailureStage, err: i64)
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

/// Service-handler entry. One copy of this loop runs per
/// [`SERVICE_THREAD_COUNT`] thread; all share the [`VfsdRuntime`].
/// The threads let independent requests proceed while one handler waits
/// on a fatfs spawn; correctness does not depend on their count (see
/// [`SERVICE_THREAD_COUNT`]).
///
/// Concurrency invariants. `MOUNT` routes into `do_mount`, and a
/// successful root `MOUNT` then auto-mounts `/esp` and the data paths
/// through `auto_mount_role` ([`after_root_mount`]); all of them reach `do_mount_internal`, which
/// mutates shared runtime state under the `VfsdRuntime` mutexes:
/// - `rt.boot_module_cap` — Mutex; swapped to zero by the first mount
///   that reaches the driver spawn, whether or not it succeeds.
/// - `rt.root_backend` — Mutex; the synthetic-root tree's only
///   mutator. `VfsdRootBackend::can_install` and
///   `VfsdRootBackend::install` reject an already-terminal entry, so
///   two concurrent MOUNTs targeting the same path serialise on the
///   lock and the loser sees `can_install` (or, if both pass that
///   check before either installs, `install`) reject. `UNMOUNT`
///   (`do_unmount`) begins a removal under the same lock, and only the
///   request that began it ends it (`restore_mount` or `remove_mount`):
///   meanwhile a `MOUNT` at the path is refused and a second `UNMOUNT`
///   finds the removal under way. The watch thread begins removals under
///   the same lock, after a driver's death or a disk's loss, and restarts
///   after a driver's death, which a restart thread ends under it
///   (`restart`); a restart is refused as a removal under way is. Every
///   remover or restarter takes the mount's death queue out of the watch set
///   in the hold that begins the removal or the restart (the claim rule of
///   `watch`).
/// - `rt.discovery` — Mutex; held across a discovery of new disks, a
///   `MOUNT`'s or a `GET_SWAP_PARTITION`'s, so one runs at a time.
/// - `rt.disks` — Mutex; held only across reads and updates of the disk
///   table, taken after `rt.discovery` when both are, and never together
///   with `rt.root_backend`.
///
/// No `do_mount`- or `do_unmount`-touched state is shared without one of
/// these locks. `GET_SWAP_PARTITION` holds `rt.swap` across a hand-out;
/// the first one runs a discovery while it holds it, taking `rt.discovery`
/// and then `rt.disks`, and nothing takes `rt.swap` while it holds either.
fn service_loop(rt: &'static VfsdRuntime) -> !
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    if ipc_buf.is_null()
    {
        std::os::seraph::log!(error: "service thread has no registered IPC buffer");
        syscall::thread_exit();
    }

    let mut guard = ipc::recv_guard::RecvGuard::new(recv_diag);
    // The other service threads (`SERVICE_THREAD_COUNT`) receive on the
    // service endpoint too.
    let mut reply = Reply::pooled();
    loop
    {
        // SAFETY: ipc_buf is the thread-registered IPC buffer page.
        let recv = match unsafe { next_request(rt.caps.service_ep, &mut reply, ipc_buf) }
        {
            Ok(recv) => recv,
            Err(e) =>
            {
                guard.on_failure(e);
                continue;
            }
        };
        guard.on_success();
        dispatch_service_request(&recv, ipc_buf, rt, &mut reply);
    }
}

/// Serves one request received on the service endpoint: gates it on its
/// badge's verb bit, then hands it to its label's handler, which replies.
fn dispatch_service_request(
    recv: &IpcMessage,
    ipc_buf: *mut u64,
    rt: &VfsdRuntime,
    reply: &mut Reply,
)
{
    let opcode = recv.label & 0xFFFF;
    let badge = recv.badge;

    match opcode
    {
        ipc::vfsd_labels::MOUNT =>
        {
            // Verb-bit gate (docs/capability-model.md): MOUNT spawns a
            // driver and installs a mount, so only a MOUNT_AUTHORITY
            // badge reaches the handler.
            if badge & ipc::vfsd_labels::MOUNT_AUTHORITY == 0
            {
                std::os::seraph::log!(warn: "MOUNT rejected: badge lacks MOUNT_AUTHORITY");
                reply.set_status(ipc::vfsd_errors::UNAUTHORIZED);
            }
            else
            {
                handle_mount_request(recv, ipc_buf, rt, reply);
            }
        }
        ipc::vfsd_labels::UNMOUNT =>
        {
            // Who may mount may unmount: the same verb bit gates it.
            if badge & ipc::vfsd_labels::MOUNT_AUTHORITY == 0
            {
                std::os::seraph::log!(warn: "UNMOUNT rejected: badge lacks MOUNT_AUTHORITY");
                reply.set_status(ipc::vfsd_errors::UNAUTHORIZED);
            }
            else
            {
                handle_unmount_request(recv, ipc_buf, rt, reply);
            }
        }
        ipc::vfsd_labels::GET_SYSTEM_ROOT_CAP =>
        {
            if badge & ipc::vfsd_labels::SEED_AUTHORITY == 0
            {
                std::os::seraph::log!(
                    warn: "GET_SYSTEM_ROOT_CAP rejected: badge lacks SEED_AUTHORITY"
                );
                reply.set_status(ipc::vfsd_errors::UNAUTHORIZED);
            }
            else if recv.word(0) != u64::from(ipc::VFSD_LABELS_VERSION)
            {
                std::os::seraph::log!(
                    warn: "GET_SYSTEM_ROOT_CAP rejected: caller VFSD_LABELS_VERSION={} \
                     expected {}",
                    recv.word(0),
                    ipc::VFSD_LABELS_VERSION
                );
                reply.set_status(ipc::vfsd_errors::LABEL_VERSION_MISMATCH);
            }
            else
            {
                handle_get_system_root_cap(rt, reply);
            }
        }
        ipc::vfsd_labels::GET_SWAP_PARTITION =>
        {
            // Verb-bit gate: the hand-out revokes the previous holder's
            // cap, so only the swap service's SWAP_AUTHORITY badge
            // reaches it.
            if badge & ipc::vfsd_labels::SWAP_AUTHORITY == 0
            {
                std::os::seraph::log!(
                    warn: "GET_SWAP_PARTITION rejected: badge lacks SWAP_AUTHORITY"
                );
                reply.set_status(ipc::vfsd_errors::UNAUTHORIZED);
            }
            else if recv.word(0) != u64::from(ipc::VFSD_LABELS_VERSION)
            {
                std::os::seraph::log!(
                    warn: "GET_SWAP_PARTITION rejected: caller VFSD_LABELS_VERSION={} \
                     expected {}",
                    recv.word(0),
                    ipc::VFSD_LABELS_VERSION
                );
                reply.set_status(ipc::vfsd_errors::LABEL_VERSION_MISMATCH);
            }
            else
            {
                handle_get_swap_partition(ipc_buf, rt, reply);
            }
        }
        _ =>
        {
            reply.set_status(ipc::vfsd_errors::UNKNOWN_OPCODE);
        }
    }
}

// ── Namespace dispatcher ──────────────────────────────────────────────────

/// Dedicated thread that serves `NS_*` requests against vfsd's
/// synthetic root.
///
/// One thread is sufficient: every backend operation is an in-memory walk
/// of one node's children, or of one node's ancestors; the only blocking
/// call is the optional fall-through call to a root-fs cap, bounded by
/// [`FALLTHROUGH_TIMEOUT_MS`] per call, so a root fs driver that stops
/// answering delays a walk queued behind fall-through calls by up to the
/// bound for each of them. A
/// multi-threaded recv on `namespace_ep` would only buy concurrency
/// between independent `NS_*` requests and is not load-bearing today.
///
/// [`try_forward_lookup_fallthrough`] makes its fall-through call on this
/// thread's own `ipc_buf` page, after the request was copied out of it, and
/// reads only the copied request and the copied reply. Further dispatcher
/// threads on `namespace_ep`, each on its own page, would need no change to
/// it (`docs/ipc-design.md` § Multi-threaded servers).
fn namespace_loop(rt: &'static VfsdRuntime) -> !
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    if ipc_buf.is_null()
    {
        std::os::seraph::log!(error: "namespace thread has no registered IPC buffer");
        syscall::thread_exit();
    }

    let mut guard = ipc::recv_guard::RecvGuard::new(recv_diag);
    let mut reply = Reply::new();
    loop
    {
        // SAFETY: ipc_buf is the thread-registered IPC buffer page.
        let recv = match unsafe { next_request(rt.namespace_ep, &mut reply, ipc_buf) }
        {
            Ok(recv) => recv,
            Err(e) =>
            {
                guard.on_failure(e);
                continue;
            }
        };
        guard.on_success();

        // No request on this endpoint takes a cap: an `NS_*` request carries
        // none, and a fall-through call forwards none. Every cap a request
        // carries is deleted here, before it is served or refused, whatever
        // its label, so a caller cannot fill vfsd's `CSpace` with them
        // (`dispatch_request` neither reads nor deletes them).
        for &cap in recv.caps()
        {
            let _ = syscall::cap_delete(cap);
        }

        // Fall-through delegation: an `NS_LOOKUP` on any synthetic
        // tree node (the synthetic root or a multi-component
        // intermediate) for a path whose first component does not match
        // any local child forwards to that node's `fallthrough_cap`.
        // The cap addresses the corresponding directory in the root
        // filesystem, captured at install time. This preserves the
        // namespace-model invariant that root-fs entries remain
        // reachable unless explicitly shadowed by a registered mount.
        if try_forward_lookup_fallthrough(rt, &recv, ipc_buf, &mut reply)
        {
            continue;
        }

        // Fall-through enumeration: an `NS_READDIR` on a synthetic node
        // with a `fallthrough_cap` lists its local children first, then
        // the underlying root-fs directory's entries, so a listing shows
        // both mounts and root-fs contents (mirroring lookup fall-through).
        if try_forward_readdir_fallthrough(rt, &recv, ipc_buf, &mut reply)
        {
            continue;
        }

        let mut backend = rt
            .root_backend
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        // rt.namespace_ep is the un-badged source for child caps minted by
        // the protocol crate's `cap_derive_badge` calls.
        namespace_protocol::dispatch_request(&mut *backend, &recv, rt.namespace_ep, &mut reply);
    }
}

/// If `recv` is an `NS_LOOKUP` whose parent `NodeId` resolves to a
/// synthetic tree node that has no local child matching the first
/// component of the requested path, forward the request to that node's
/// `fallthrough_cap` and reply with the upstream response. Returns `true`
/// when the request was handled (caller skips normal dispatch).
///
/// The whole path is forwarded: every component of it lies under the
/// first, in the root filesystem, which walks as many of them as it owns
/// in the one call (`shared/namespace-protocol/README.md` § `NS_LOOKUP`).
/// The reply's consumed count and failing-component index count the
/// components of that same path, so they reach the caller unchanged. The
/// local dispatch does not walk past a synthetic node with a
/// fall-through (`VfsdRootBackend::continues_walk`), so a path whose
/// later component falls through reaches this function in a request of
/// its own.
///
/// The outbound message is rebuilt with the same label, path bytes,
/// and shape, but its `caller_requested` word (`word(0)`) is replaced
/// by the intersection of the caller's parent rights (extracted from
/// `recv.badge`) with the caller's original `caller_requested` —
/// computed via [`compose_forward_lookup_rights`]. Forwarding the
/// caller's `word(0)` verbatim would launder authority because the
/// receiving fs driver composes against the *destination cap's*
/// badge (the fall-through cap, full rights), not the caller's. The
/// reply travels back unchanged: any cap it surfaces is the upstream
/// fs's freshly-minted node cap, handed to the original caller
/// directly. vfsd performs no cap derivation here, so no per-lookup
/// cap leak in vfsd's `CSpace`. A call that has not returned within
/// [`FALLTHROUGH_TIMEOUT_MS`] is answered `NsError::IoError`; any other
/// failed call goes to normal dispatch, which answers `NotFound`.
fn try_forward_lookup_fallthrough(
    rt: &'static VfsdRuntime,
    recv: &IpcMessage,
    ipc_buf: *mut u64,
    reply: &mut Reply,
) -> bool
{
    let opcode = recv.label & 0xFFFF;
    if opcode != ns_labels::NS_LOOKUP
    {
        return false;
    }
    // Gate the request through namespace-protocol's per-label rights
    // table. On `Err`, fall through to the main path: `dispatch_request`
    // will produce the matching `NsError` reply (PermissionDenied or
    // NotSupported). Forwarding a request the caller could not have
    // issued locally would launder authority across the mount.
    let parent = match gate(recv.label, recv.badge)
    {
        Ok((node, _)) => node,
        Err(GateError::PermissionDenied | GateError::UnknownLabel | GateError::WrongKind) =>
        {
            return false;
        }
    };
    // Cast is range-safe: path_len lives in bits 16..32 of the label.
    let path_len = ((recv.label >> 16) & 0xFFFF) as usize;
    let data_bytes = recv.data_bytes();
    if path_len == 0
    {
        return false;
    }
    let Some(path) = data_bytes.get(8..).and_then(|d| d.get(..path_len))
    else
    {
        return false;
    };
    // `split` yields at least one item; an empty first component (a
    // malformed path) matches no local child and is forwarded, and the
    // driver answers it `InvalidName` as the local dispatch would.
    let first = path.split(|&b| b == b'/').next().unwrap_or(path);

    let backend = rt
        .root_backend
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let Some(parent_idx) = backend.resolve(parent)
    else
    {
        return false;
    };
    if backend.has_local_child(parent_idx, first)
    {
        return false;
    }
    let fallthrough = backend.fallthrough_of(parent_idx);
    drop(backend);
    if fallthrough == 0
    {
        return false;
    }

    // Repack the request: replace the caller's `word(0)` with the
    // intersection of their parent rights and their original request,
    // so the receiving fs driver's
    // `parent_rights ∩ entry.max_rights ∩ caller_requested`
    // composition reflects the original caller's authority rather
    // than the fall-through cap's full-rights badge.
    let composed_rights = compose_forward_lookup_rights(recv.badge, recv.word(0));
    let forward = IpcMessage::builder(recv.label)
        .word(0, u64::from(composed_rights))
        .bytes(1, path)
        .build();

    let Some(answer) = fallthrough_call(fallthrough, &forward, ipc_buf)
    else
    {
        return false;
    };
    reply.set(answer);
    true
}

/// Call the root filesystem through the fall-through cap `fallthrough`,
/// bounded by [`FALLTHROUGH_TIMEOUT_MS`]. Returns the driver's reply, or an
/// `NsError::IoError` reply, logged, when the bound expired first; `None`
/// when the call failed otherwise.
fn fallthrough_call(fallthrough: u64, msg: &IpcMessage, ipc_buf: *mut u64) -> Option<IpcMessage>
{
    // SAFETY: ipc_buf is the thread-registered IPC buffer.
    match unsafe { ipc::ipc_call_timeout(fallthrough, msg, ipc_buf, FALLTHROUGH_TIMEOUT_MS) }
    {
        Ok(reply) => Some(reply),
        Err(code) if code == syscall_abi::SyscallError::WouldBlock as i64 =>
        {
            std::os::seraph::log!(
                warn: "root fs did not answer a fall-through call within \
                 {FALLTHROUGH_TIMEOUT_MS} ms; answering IoError"
            );
            Some(IpcMessage::new(NsError::IoError.as_label()))
        }
        Err(_) => None,
    }
}

/// If `recv` is an `NS_READDIR` on a synthetic tree node that carries a
/// `fallthrough_cap`, serve the merged enumeration and return `true`
/// (caller skips normal dispatch). The node's local children occupy
/// indices `0..local_count` and are served by normal dispatch; this
/// handler serves higher indices from the fall-through directory,
/// skipping any name shadowed by a local child. Without it, listing a
/// synthetic node would show only its in-tree mounts and hide root-fs
/// entries reachable by name (e.g. `/programs`, `/data` under the
/// synthetic root), making enumeration inconsistent with lookup. An
/// index beyond `u32` is answered `END_OF_DIR` here, on any node the
/// caller may read, as the protocol crate answers it.
///
/// `NS_READDIR` surfaces names only — no caps — so, unlike lookup
/// fall-through, there is no authority to launder: the caller's
/// `READDIR` right is checked via [`gate`], and the fall-through probe
/// rides vfsd's own full-rights root cap.
///
/// Assumption: the probe applies no per-entry visibility filter (the
/// backend's `visible_requires` per `docs/namespace-model.md`). That is
/// sound only because no current fs backend hides entries by rights; a
/// backend that did would need the probe to compose the caller's rights
/// (as the lookup path does) before enumerating. Per client `NS_READDIR`
/// this re-probes the fall-through dir from index 0, so a full listing is
/// O(n²); acceptable for the small synthetic nodes (root, `/esp`). A probe
/// call that has not returned within [`FALLTHROUGH_TIMEOUT_MS`] ends the
/// enumeration with `NsError::IoError`.
fn try_forward_readdir_fallthrough(
    rt: &'static VfsdRuntime,
    recv: &IpcMessage,
    ipc_buf: *mut u64,
    reply: &mut Reply,
) -> bool
{
    let opcode = recv.label & 0xFFFF;
    if opcode != ns_labels::NS_READDIR
    {
        return false;
    }
    // Enforce the caller's READDIR right and resolve the directory node.
    // On `Err`, fall through to normal dispatch, which emits the matching
    // error reply.
    let dir = match gate(recv.label, recv.badge)
    {
        Ok((node, _)) => node,
        Err(GateError::PermissionDenied | GateError::UnknownLabel | GateError::WrongKind) =>
        {
            return false;
        }
    };
    // An index beyond u32 cannot name an entry; answer `END_OF_DIR` as
    // namespace-protocol's `handle_readdir` does for the local children,
    // so both readdir paths agree.
    let Ok(idx) = u32::try_from(recv.word(0))
    else
    {
        let end = IpcMessage::new(ipc::fs_labels::END_OF_DIR);
        reply.set(end);
        return true;
    };

    let backend = rt
        .root_backend
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let Some(parent_idx) = backend.resolve(dir)
    else
    {
        return false;
    };
    let fallthrough = backend.fallthrough_of(parent_idx);
    let local_count = backend.local_child_count(parent_idx);
    drop(backend);

    // No fall-through, or still within the local children: normal dispatch
    // serves it (a local child, then `END_OF_DIR` past the last one).
    if fallthrough == 0 || idx < local_count
    {
        return false;
    }

    // Enumerate the fall-through directory, skipping names shadowed by a
    // local child, until the `(idx - local_count)`-th survivor.
    // `idx < local_count` returned above, so the difference does not saturate.
    let target = idx.saturating_sub(local_count);
    let mut matched = 0u32;
    let mut probe = 0u32;
    loop
    {
        let req = IpcMessage::builder(ns_labels::NS_READDIR)
            .word(0, u64::from(probe))
            .build();
        let Some(answer) = fallthrough_call(fallthrough, &req, ipc_buf)
        else
        {
            return false;
        };
        // `END_OF_DIR` or any upstream error terminates the merged
        // enumeration; forward it verbatim as the client's terminator.
        if answer.label != 0
        {
            reply.set(answer);
            return true;
        }
        #[expect(
            clippy::cast_possible_truncation,
            reason = "cast is range-safe: name_len rides word 1, bounded by the protocol's max \
                      name length"
        )]
        let name_len = answer.word(1) as usize;
        let data = answer.data_bytes();
        // Reply layout: word 0 = kind, word 1 = name_len, name at byte 16.
        let name = if name_len == 0
        {
            None
        }
        else
        {
            data.get(16..).and_then(|d| d.get(..name_len))
        };
        let Some(name) = name
        else
        {
            // Malformed upstream reply: terminate enumeration cleanly.
            let end = IpcMessage::new(ipc::fs_labels::END_OF_DIR);
            reply.set(end);
            return true;
        };
        let shadowed = {
            let backend = rt
                .root_backend
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            backend.has_local_child(parent_idx, name)
        };
        if !shadowed
        {
            if matched == target
            {
                reply.set(answer);
                return true;
            }
            matched = matched.saturating_add(1);
        }
        probe = probe.saturating_add(1);
    }
}

// ── System-root cap delivery ─────────────────────────────────────────────

/// Handle [`vfsd_labels::GET_SYSTEM_ROOT_CAP`]: mint a fresh badged SEND
/// on vfsd's namespace endpoint addressing the synthetic root at full
/// rights and reply with it.
///
/// Source for the seed cap init holds at bootstrap and from which all
/// later tier-3 namespace-cap distribution flows. The dispatcher gates
/// this entry on [`vfsd_labels::SEED_AUTHORITY`] in the caller's
/// service-endpoint badge: holding the bit is equivalent to holding
/// the system-root cap, so only consumers explicitly entrusted with
/// seed authority reach this handler.
///
/// Replies [`vfsd_errors::NO_MOUNT`] when the root filesystem is not
/// mounted. vfsd self-mounts root before any service thread starts, so
/// this fires only when the self-mount failed (no `SERAPH_ROOT`
/// partition, or fatfs bring-up failed); init then FATALs instead of
/// receiving a system-root cap that resolves against an empty root.
fn handle_get_system_root_cap(rt: &VfsdRuntime, reply: &mut Reply)
{
    if rt
        .root_backend
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .root_mount_cap()
        == 0
    {
        std::os::seraph::log!(warn: "GET_SYSTEM_ROOT_CAP rejected: root not mounted");
        reply.set_status(ipc::vfsd_errors::NO_MOUNT);
        return;
    }

    let badge = namespace_protocol::pack(
        namespace_protocol::NodeId::ROOT,
        namespace_protocol::NamespaceRights::ALL,
    );
    let answer = if let Ok(cap) =
        syscall::cap_derive_badge(rt.namespace_ep, syscall::RIGHTS_EP_SEND, badge)
    {
        IpcMessage::builder(ipc::vfsd_errors::SUCCESS)
            .cap(cap)
            .build()
    }
    else
    {
        std::os::seraph::log!(warn: "GET_SYSTEM_ROOT_CAP derive failed");
        IpcMessage::new(ipc::vfsd_errors::IO_ERROR)
    };
    reply.set_or_delete_caps(answer);
}

// ── Swap-partition hand-out ─────────────────────────────────────────────────

/// The operations of a swap-partition hand-out, carried out with the held
/// disks' GPTs, the block drivers, and capability syscalls on this thread's
/// IPC buffer.
struct SwapIo<'a>
{
    rt: &'a VfsdRuntime,
    ipc_buf: *mut u64,
}

impl swap::SwapOps for SwapIo<'_>
{
    fn lookup(&mut self) -> Result<gpt::PartitionLocation, gpt::GptLookupError>
    {
        // The role resolves as a mount role does (docs/storage.md § GPT
        // Role-GUID Discovery): the partition the statement names, on any
        // disk devmgr serves, so the discovery first holds each disk served
        // since the last one; else the boot disk's by type and priority.
        discover_new_disks(self.rt, self.ipc_buf);
        resolve_role(self.rt, Want::Swap).map(|(location, _)| location)
    }

    fn register(&mut self, location: &gpt::PartitionLocation) -> Option<u64>
    {
        // The lookup ran over `rt.disks`, so its index is in range; a disk
        // removed since holds no cap, and the registration fails.
        let blk_ep = held_disk_cap(self.rt, location.disk)?;
        derive_and_register_partition(
            blk_ep,
            location.first_lba,
            location.length_lba,
            self.ipc_buf,
        )
    }

    fn revoke_descendants(&mut self, cap: u64) -> bool
    {
        match syscall::cap_revoke_all(cap)
        {
            Ok(()) => true,
            Err(code) =>
            {
                std::os::seraph::log!(
                    warn: "GET_SWAP_PARTITION: cap_revoke_all failed: code={code}"
                );
                false
            }
        }
    }

    fn derive(&mut self, cap: u64) -> Option<u64>
    {
        syscall::cap_derive(cap, syscall::RIGHTS_EP_SEND_GRANT).ok()
    }
}

/// Handle [`vfsd_labels::GET_SWAP_PARTITION`]: hand the caller a
/// `SEND_GRANT` on the swap partition, revoking the cap an earlier
/// hand-out returned ([`swap::SwapPartition::hand_out`]).
///
/// The dispatcher admits only a `SWAP_AUTHORITY` badge. The partition is
/// resolved and registered on the first request, never at startup
/// ([`resolve_role`], after [`discover_new_disks`]): the one the storage
/// statement names, else the boot disk's by type and priority. With none,
/// the request replies [`vfsd_errors::NO_MOUNT`]; so does a tie, and a
/// named partition that is no swap partition.
/// A failed registration, revoke or derivation replies
/// [`vfsd_errors::IO_ERROR`].
fn handle_get_swap_partition(ipc_buf: *mut u64, rt: &VfsdRuntime, reply: &mut Reply)
{
    let handed = rt
        .swap
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .hand_out(&mut SwapIo { rt, ipc_buf });
    let answer = match handed
    {
        Ok(cap) => IpcMessage::builder(ipc::vfsd_errors::SUCCESS)
            .cap(cap)
            .build(),
        Err(e) =>
        {
            std::os::seraph::log!(warn: "GET_SWAP_PARTITION failed: {e:?}");
            let label = match e
            {
                swap::HandOutError::NoPartition | swap::HandOutError::Ambiguous =>
                {
                    ipc::vfsd_errors::NO_MOUNT
                }
                swap::HandOutError::Register
                | swap::HandOutError::Revoke
                | swap::HandOutError::Derive => ipc::vfsd_errors::IO_ERROR,
            };
            IpcMessage::new(label)
        }
    };
    reply.set(answer);
}

// ── MOUNT handler ──────────────────────────────────────────────────────────

/// Mount role decoded from the MOUNT IPC wire byte. The holder of the
/// `vfsd.mount` SEND, a test fixture, names the role it wants a partition of; vfsd resolves it to a partition with
/// [`resolve_role`] (docs/storage.md § GPT Role-GUID Discovery).
#[derive(Clone, Copy, Debug)]
enum MountRole
{
    /// The Seraph root partition (`role_guids::SERAPH_ROOT`), on the boot
    /// disk.
    Root,
    /// A Seraph data partition (`role_guids::SERAPH_DATA`) at the request's
    /// path: the one the storage statement names for that path, else the
    /// boot disk's by type and priority.
    Data,
}

impl MountRole
{
    fn from_wire(byte: u8) -> Option<Self>
    {
        match byte
        {
            0 => Some(MountRole::Root),
            1 => Some(MountRole::Data),
            _ => None,
        }
    }

    /// What a mount of the role at `path` asks [`resolve_role`] for.
    fn want(self, path: &[u8]) -> Want<'_>
    {
        match self
        {
            MountRole::Root => Want::Root,
            MountRole::Data => Want::Data(path),
        }
    }
}

/// A partition vfsd mounts or hands out, as [`resolve_role`] resolves it.
#[derive(Clone, Copy, Debug)]
enum Want<'a>
{
    /// The root partition: the boot disk's by type and priority.
    Root,
    /// The boot ESP the firmware's device path describes, on the boot disk.
    Esp,
    /// A data partition mounted at the path: the one the statement names
    /// for the path, else the boot disk's by type and priority.
    Data(&'a [u8]),
    /// The swap partition: the one the statement names, else the boot
    /// disk's by type and priority.
    Swap,
}

impl Want<'_>
{
    /// The GPT partition type GUID the partition carries.
    fn type_guid(self) -> [u8; 16]
    {
        match self
        {
            Want::Root => role_guids::SERAPH_ROOT,
            Want::Esp => role_guids::EFI_SYSTEM_PARTITION,
            Want::Data(_) => role_guids::SERAPH_DATA,
            Want::Swap => role_guids::SERAPH_SWAP,
        }
    }

    /// The partition the statement names for it: its disk and unique GUID.
    fn named(self, statement: &storage_statement::Statement) -> Option<&storage_statement::Named>
    {
        match self
        {
            Want::Root | Want::Esp => None,
            Want::Data(path) => statement.named(storage_statement::Role::Data, Some(path)),
            Want::Swap => statement.named(storage_statement::Role::Swap, None),
        }
    }
}

impl core::fmt::Display for Want<'_>
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
    {
        match self
        {
            Want::Root => f.write_str("root"),
            Want::Esp => f.write_str("/esp"),
            Want::Data(path) =>
            {
                f.write_str(core::str::from_utf8(path).unwrap_or("<non-UTF-8 path>"))
            }
            Want::Swap => f.write_str("swap"),
        }
    }
}

/// The place a statement's disk field binds a partition to, in the
/// locations devmgr reports for the held disks.
fn bound_disk(disk: storage_statement::Disk) -> gpt::BoundDisk<ipc::vfsd_bootstrap::PciLocation>
{
    match disk
    {
        storage_statement::Disk::Boot => gpt::BoundDisk::Boot,
        storage_statement::Disk::Pci(at) => gpt::BoundDisk::At(ipc::vfsd_bootstrap::PciLocation {
            segment: at.segment,
            bus: at.bus,
            device: at.device,
            function: at.function,
        }),
    }
}

/// The disk a statement binds a partition to, as vfsd's lines name it: the
/// boot disk, or the location in the form a disk's line gives it.
struct Bound(storage_statement::Disk);

impl core::fmt::Display for Bound
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
    {
        match bound_disk(self.0)
        {
            gpt::BoundDisk::Boot => f.write_str("the boot disk"),
            gpt::BoundDisk::At(at) => core::fmt::Display::fmt(&Where(Some(at)), f),
        }
    }
}

/// Resolve `want` to a partition and its disk's whole-disk cap, over the
/// held disks (docs/storage.md § GPT Role-GUID Discovery). With no boot
/// disk nothing resolves. The root resolves on the boot disk by type and
/// priority, `/esp` is the boot ESP on the boot disk, and a role the
/// statement names resolves to the named partition on the disk the
/// statement binds it to only (`gpt::resolve_named`: the boot disk, or the
/// disks at a PCI location); a role not named resolves on the boot disk by
/// type and priority. A disk neither the boot disk nor named takes no role.
/// Logs the partition it resolved, with its disk's location, or why none:
/// for a named partition seen only on a disk outside its place, that disk.
fn resolve_role(
    rt: &VfsdRuntime,
    want: Want<'_>,
) -> Result<(gpt::PartitionLocation, u64), gpt::GptLookupError>
{
    let Some(boot) = rt.boot_disk
    else
    {
        std::os::seraph::log!(warn: "{want}: no boot disk, so no partition takes the role");
        return Err(gpt::GptLookupError::NotFound);
    };
    let named = want
        .named(rt.statement())
        .map(|entry| (entry.disk, entry.guid));
    let disks = rt.disks.lock().unwrap_or_else(PoisonError::into_inner);
    let on_boot = disks
        .get(boot.index)
        .map_or(&[][..], |d| d.partitions.as_slice());
    let found = match (want, named)
    {
        (Want::Esp, _) if boot.esp.on(on_boot) => Ok(gpt::PartitionLocation {
            disk: boot.index,
            first_lba: boot.esp.first_lba,
            length_lba: boot.esp.length_lba,
        }),
        (Want::Esp, _) => Err(gpt::GptLookupError::NotFound),
        (_, Some((disk, guid))) => gpt::resolve_named(
            &want.type_guid(),
            &guid,
            &bound_disk(disk),
            boot.index,
            disks
                .iter()
                .map(|d| (d.location.as_ref(), d.partitions.as_slice())),
        ),
        (_, None) => gpt::lookup_on_disk(boot.index, &want.type_guid(), on_boot),
    };
    let held = found.map(|location| {
        let disk = disks.get(location.disk);
        (
            location,
            disk.map_or(0, |d| d.blk_ep),
            disk.map_or(0, |d| d.ordinal),
            disk.and_then(|d| d.location),
        )
    });
    // The disk outside its place a named partition was seen on.
    let seen = match held
    {
        Err(gpt::GptLookupError::Elsewhere { disk }) =>
        {
            disks.get(disk).map(|d| (d.ordinal, d.location))
        }
        _ => None,
    };
    drop(disks);
    let how = if named.is_some()
    {
        "named by the storage statement"
    }
    else
    {
        "on the boot disk"
    };
    let bound = named.map(|(disk, _)| Bound(disk));
    match held
    {
        Ok((location, blk_ep, ordinal, at)) =>
        {
            std::os::seraph::log!(
                "{want}: partition {how} at block {} on disk {ordinal} at {}",
                location.first_lba,
                Where(at)
            );
            Ok((location, blk_ep))
        }
        Err(e) =>
        {
            let why = match e
            {
                gpt::GptLookupError::NotFound => "none found",
                gpt::GptLookupError::DuplicateTie => "two or more answer equally; none taken",
                gpt::GptLookupError::WrongType =>
                {
                    "the named partition is of another type; not taken"
                }
                gpt::GptLookupError::Elsewhere { .. } => "not on its disk",
            };
            match (bound, seen)
            {
                (Some(bound), Some((ordinal, at))) => std::os::seraph::log!(
                    warn: "{want}: no partition {how}: not on {bound}; seen on disk {ordinal} at {}; not taken",
                    Where(at)
                ),
                (Some(bound), None) =>
                {
                    std::os::seraph::log!(warn: "{want}: no partition {how} on {bound}: {why}");
                }
                (None, _) => std::os::seraph::log!(warn: "{want}: no partition {how}: {why}"),
            }
            Err(e)
        }
    }
}

/// Mount the Seraph root partition at `/` during vfsd startup, then read
/// the storage statement and auto-mount the ESP and the data partitions
/// ([`after_root_mount`]).
///
/// Runs on the main thread before any service handler exists, so a
/// `GET_SYSTEM_ROOT_CAP` request can never observe an unmounted root.
/// The namespace dispatcher must already be running: the walk to the
/// statement, and the `/esp` and data mounts, which take the VFS spawn
/// path to resolve `/services/fs/fatfs`, re-enter vfsd's namespace
/// endpoint. Returns whether the root mount succeeded; the auto-mounts are
/// best-effort and never gate the return value. With no boot disk the root
/// resolves on no disk and the mount fails.
fn self_mount(rt: &VfsdRuntime, ipc_buf: *mut u64) -> bool
{
    match do_mount_internal(rt, ipc_buf, Want::Root, b"/", Discover::No)
    {
        Ok(caller_root_cap) =>
        {
            // The per-mount caller cap rides back to an IPC caller; the
            // self-mount has none, and vfsd reaches root through the
            // synthetic backend, so drop it.
            log_cap_delete("self-mount caller_root_cap", caller_root_cap);
            std::os::seraph::log!("root self-mounted at /");
            decline_root_disk_restart(rt, ipc_buf);
        }
        Err(code) =>
        {
            std::os::seraph::log!(error: "FATAL: root self-mount failed: code={code:#x}");
            return false;
        }
    }

    after_root_mount(rt, ipc_buf);
    true
}

/// Once the root is mounted: read the storage statement, if it has not
/// been read, then auto-mount the boot ESP at `/esp`, each data partition
/// the statement names at its path, and, unless the statement names one for
/// `/data`, the boot disk's data partition there. Each auto-mount is
/// best-effort ([`auto_mount_role`]).
fn after_root_mount(rt: &VfsdRuntime, ipc_buf: *mut u64)
{
    if rt.statement.get().is_none()
    {
        // Only the thread that mounted the root reads it; a second root
        // mount is refused, so no other sets it.
        let _ = rt
            .statement
            .set(read_statement(rt.system_root_cap, ipc_buf));
    }
    auto_mount_role(rt, ipc_buf, Want::Esp, b"/esp");
    let statement = rt.statement();
    for entry in statement.entries()
    {
        if let (storage_statement::Role::Data, Some(path)) = (entry.role, &entry.path)
        {
            auto_mount_role(rt, ipc_buf, Want::Data(path.as_bytes()), path.as_bytes());
        }
    }
    if statement
        .named(storage_statement::Role::Data, Some(b"/data"))
        .is_none()
    {
        auto_mount_role(rt, ipc_buf, Want::Data(b"/data"), b"/data");
    }
}

/// The storage statement at `storage_statement::PATH`, walked from
/// `root_cap` and read through procmgr's verified read in the configuration
/// role under that path (docs/signing.md § Configuration). A statement that
/// is missing, that procmgr refuses, or that does not parse is logged and
/// names nothing: every role then resolves on the boot disk.
fn read_statement(root_cap: u64, ipc_buf: *mut u64) -> storage_statement::Statement
{
    let path = storage_statement::PATH;
    // LOOKUP on each directory the walk passes, READ on the file.
    let rights = u64::from(namespace_protocol::rights::LOOKUP | namespace_protocol::rights::READ);
    // SAFETY: ipc_buf is the calling thread's registered IPC buffer.
    let walked = unsafe {
        ns_client::walk_to_file(
            root_cap,
            path.trim_start_matches('/').as_bytes(),
            rights,
            ipc_buf,
        )
    };
    let Some(walked) = walked
    else
    {
        std::os::seraph::log!("storage statement {path}: none; no partition named");
        return storage_statement::Statement::new();
    };
    let data = match std::os::seraph::read_verified(
        walked.file_cap,
        walked.size,
        path,
        std::os::seraph::VerifiedRole::Configuration,
    )
    {
        Ok(data) => data,
        Err(e) =>
        {
            std::os::seraph::log!(
                warn: "storage statement {path}: procmgr's verified read refused it ({:?}); no partition named",
                e.kind()
            );
            return storage_statement::Statement::new();
        }
    };
    match storage_statement::parse(data.bytes())
    {
        Ok(statement) =>
        {
            for entry in statement.entries()
            {
                let guid = storage_statement::format_guid(&entry.guid);
                std::os::seraph::log!(
                    "storage statement {path}: {} {}names partition {} on {}",
                    entry.role.keyword(),
                    entry
                        .path
                        .as_deref()
                        .map_or(String::new(), |p| format!("{p} ")),
                    core::str::from_utf8(&guid).unwrap_or_default(),
                    Bound(entry.disk)
                );
            }
            statement
        }
        Err(e) =>
        {
            std::os::seraph::log!(warn: "storage statement {path}: refused, {e}; no partition named");
            storage_statement::Statement::new()
        }
    }
}

/// Decline devmgr's restart of the driver of the disk the root filesystem
/// sits on (`devmgr_labels::DECLINE_RESTART`): the loss of that disk ends
/// vfsd (`watch::root_lost`), so a new instance of its driver would serve
/// no one. Sent from the self-mount, before vfsd serves anything and so
/// before svcmgr, which vfsd's root brings up, hands devmgr its drivers
/// directory, from which point devmgr refuses the request. A failure is
/// logged; devmgr then restarts the driver if it dies, and vfsd ends all the
/// same.
fn decline_root_disk_restart(rt: &VfsdRuntime, ipc_buf: *mut u64)
{
    let disk = rt
        .root_backend
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .mounted(watch::ROOT_NODE)
        .map(|m| m.disk);
    let ordinal = disk.and_then(|disk| {
        rt.disks
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(disk)
            .map(|d| d.ordinal)
    });
    let Some(ordinal) = ordinal
    else
    {
        std::os::seraph::log!(warn: "root disk not found; its driver's restart not declined");
        return;
    };
    // SAFETY: ipc_buf is the registered IPC buffer.
    match unsafe { ipc::decline_restart(rt.caps.block_class, ordinal, ipc_buf) }
    {
        Ok(()) => std::os::seraph::log!("root disk (block ordinal {ordinal}): restart declined"),
        Err(e) => std::os::seraph::log!(
            warn: "root disk (block ordinal {ordinal}): restart not declined ({e:?})"
        ),
    }
}

/// Handle a runtime MOUNT request from an authorized client.
///
/// vfsd self-mounts the root, `/esp` and the data partitions at startup
/// ([`self_mount`]); `MOUNT` mounts the root or the data role at a path at
/// runtime. Its in-tree callers are test fixtures alone: svctest and the
/// `hotplug-check` disk fixture. The service loop admits a request here
/// only when the caller's badge carries `vfsd_labels::MOUNT_AUTHORITY`.
///
/// IPC data layout (services/vfsd/docs/vfs-ipc-interface.md, `MOUNT`):
/// - `data[0]` low byte: [`MountRole`] discriminant
/// - `data[1]`: mount path length
/// - `data[2..]`: mount path bytes (packed into u64 words)
///
/// Decodes the wire payload and delegates to [`do_mount`] for the
/// real work. When the requested role is [`MountRole::Root`], vfsd
/// then reads the storage statement and auto-mounts as the self-mount does
/// ([`after_root_mount`]).
#[expect(
    clippy::cast_possible_truncation,
    reason = "the role byte is the low byte of data[0] by wire contract, so the `as` keeps the \
              whole value the handler accepts"
)]
fn handle_mount_request(recv: &IpcMessage, ipc_buf: *mut u64, rt: &VfsdRuntime, reply: &mut Reply)
{
    let role_byte = recv.word(0) as u8;
    let Some(role) = MountRole::from_wire(role_byte)
    else
    {
        std::os::seraph::log!(warn: "MOUNT: unknown role byte {role_byte}");
        reply.set_status(ipc::vfsd_errors::NOT_FOUND);
        return;
    };

    let Some(path) = request_path(recv, "MOUNT")
    else
    {
        reply.set_status(ipc::vfsd_errors::NOT_FOUND);
        return;
    };

    let answer = match do_mount(rt, ipc_buf, role, path)
    {
        Ok(0) => IpcMessage::new(ipc::vfsd_errors::SUCCESS),
        Ok(cap) => IpcMessage::builder(ipc::vfsd_errors::SUCCESS)
            .cap(cap)
            .build(),
        Err(label) => IpcMessage::new(label),
    };

    // Once a root is up, read the storage statement and auto-mount the ESP
    // and the data partitions, as the self-mount does. Best-effort: a
    // failure does not propagate into the root mount's reply.
    if matches!(role, MountRole::Root) && answer.label == ipc::vfsd_errors::SUCCESS
    {
        after_root_mount(rt, ipc_buf);
    }

    reply.set(answer);
}

/// The path a `MOUNT` or `UNMOUNT` request names: `data[1]` bytes from
/// `data[2]` on. `None`, logged under `what`, when the length is zero,
/// longer than [`MAX_MOUNT_PATH_LEN`], or longer than the data words
/// carry; the caller replies `NOT_FOUND`.
fn request_path<'a>(recv: &'a IpcMessage, what: &str) -> Option<&'a [u8]>
{
    let Ok(path_len) = usize::try_from(recv.word(1))
    else
    {
        std::os::seraph::log!(warn: "{what}: invalid path length");
        return None;
    };
    if path_len == 0 || path_len > MAX_MOUNT_PATH_LEN
    {
        std::os::seraph::log!(warn: "{what}: invalid path length");
        return None;
    }
    // The path bytes start at word 2 (byte offset 16).
    let path = recv
        .data_bytes()
        .get(2 * 8..)
        .and_then(|d| d.get(..path_len));
    if path.is_none()
    {
        // The data words carry fewer path bytes than `data[1]` claims;
        // acting on the bytes that are there would name a different path.
        std::os::seraph::log!(warn: "{what}: path shorter than its stated length");
    }
    path
}

/// Handle an `UNMOUNT` request from an authorized client
/// (`services/vfsd/docs/vfs-ipc-interface.md` § Label 11). The service
/// loop admits a request here only when the caller's badge carries
/// `vfsd_labels::MOUNT_AUTHORITY`.
///
/// IPC data layout:
/// - `data[0]`: the caller's `VFSD_LABELS_VERSION`
/// - `data[1]`: mount path length
/// - `data[2..]`: mount path bytes (packed into u64 words)
/// - label bit 16: `vfsd_labels::UNMOUNT_FORCE`
fn handle_unmount_request(recv: &IpcMessage, ipc_buf: *mut u64, rt: &VfsdRuntime, reply: &mut Reply)
{
    let answer = if recv.word(0) == u64::from(ipc::VFSD_LABELS_VERSION)
    {
        if let Some(path) = request_path(recv, "UNMOUNT")
        {
            let force = if recv.label & ipc::vfsd_labels::UNMOUNT_FORCE == 0
            {
                Force::No
            }
            else
            {
                Force::Yes
            };
            do_unmount(rt, ipc_buf, path, force)
        }
        else
        {
            IpcMessage::new(ipc::vfsd_errors::NOT_FOUND)
        }
    }
    else
    {
        std::os::seraph::log!(
            warn: "UNMOUNT rejected: caller VFSD_LABELS_VERSION={} expected {}",
            recv.word(0),
            ipc::VFSD_LABELS_VERSION
        );
        IpcMessage::new(ipc::vfsd_errors::LABEL_VERSION_MISMATCH)
    };
    reply.set(answer);
}

/// Bound on the driver's answer to `FS_UNMOUNT`. The driver's single
/// dispatch thread answers it after the operation in flight, whose block
/// I/O is bounded only by the device; a driver that has not answered by
/// then is torn down without its cooperation.
///
/// The tightest bound a client puts on a call to a filesystem driver, so
/// fatfs logs a request it held this long (`SLOW_REQUEST` in
/// `services/fs/fat/src/held.rs`, which states the same value): a change
/// here changes that threshold too.
const FS_UNMOUNT_TIMEOUT_MS: u32 = 5000;

/// Bound on the wait for a torn-down driver's death to post. A driver that
/// answered `FS_UNMOUNT` exits at once, and one whose endpoint was revoked
/// exits on its next receive; `DESTROY_PROCESS` follows either way, so the
/// bound limits only how long the unmount waits to log the exit reason.
const DRIVER_DEATH_TIMEOUT_MS: u64 = 2000;

/// Whether an unmount goes ahead with files open: the request's
/// `vfsd_labels::UNMOUNT_FORCE` bit, sent on to the driver as
/// `fs_labels::UNMOUNT_FORCE`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Force
{
    No,
    Yes,
}

/// Unmount the mount at `path`, returning the reply for the caller.
///
/// The sequence of `docs/namespace-composition.md` § Unmount: stop
/// lookups crossing the mount; ask the driver to unmount (`FS_UNMOUNT`,
/// forced on [`Force::Yes`]), keeping the mount when it answers `BUSY`
/// to an unforced request; otherwise tear the driver down
/// ([`teardown_mount`]), whether it answered or not; remove the record,
/// and give a node that stays an intermediate its fall-through cap
/// ([`finish_unmount`]). The mount's death queue leaves the watch set in
/// the hold that begins the removal, and returns to it in the hold that
/// restores a refused one (the claim rule of `watch`).
fn do_unmount(rt: &VfsdRuntime, ipc_buf: *mut u64, path: &[u8], force: Force) -> IpcMessage
{
    let begun = {
        let mut backend = rt
            .root_backend
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        backend
            .find(path)
            .ok_or(root_backend::UnmountError::NotMounted)
            .and_then(|idx| watch::begin_claim(rt, &mut backend, idx).map(|mount| (idx, mount)))
    };
    let (idx, mount) = match begun
    {
        Ok(begun) => begun,
        Err(root_backend::UnmountError::Root) =>
        {
            std::os::seraph::log!(warn: "UNMOUNT rejected: / is never unmounted");
            return IpcMessage::new(ipc::vfsd_errors::UNAUTHORIZED);
        }
        Err(root_backend::UnmountError::NotMounted | root_backend::UnmountError::InProgress) =>
        {
            std::os::seraph::log!(
                warn: "UNMOUNT: no mount at the path, or its unmount or restart is under way"
            );
            return IpcMessage::new(ipc::vfsd_errors::NO_MOUNT);
        }
    };

    match driver_unmount(mount.endpoint, force, ipc_buf)
    {
        DriverUnmount::Busy(open) if force == Force::No =>
        {
            // Only this request began the node's unmount, and only it ends
            // the unmount, so the restore finds it under way.
            let restored = watch::restore_claim(
                rt,
                &mut rt
                    .root_backend
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner),
                idx,
                mount.death_queue,
            );
            if !restored
            {
                std::os::seraph::log!(error: "UNMOUNT: the refused unmount was not under way");
            }
            // The claims of a disk found removed may have passed this mount
            // while this request held it; its loss ends it as if those
            // claims had found it.
            if watch::unmount_if_removed(rt, mount.disk, mount.death_queue, ipc_buf)
            {
                std::os::seraph::log!(warn: "UNMOUNT: the disk was removed during the unmount");
                return IpcMessage::new(ipc::vfsd_errors::NO_MOUNT);
            }
            std::os::seraph::log!("UNMOUNT: refused, {open} file(s) open");
            return IpcMessage::builder(ipc::vfsd_errors::BUSY)
                .word(0, open)
                .build();
        }
        DriverUnmount::Done =>
        {
            std::os::seraph::log!(debug: "UNMOUNT: the driver released its opens");
        }
        DriverUnmount::Busy(_) | DriverUnmount::Failed =>
        {
            std::os::seraph::log!(
                warn: "UNMOUNT: the driver did not unmount; tearing it down without it"
            );
        }
    }

    teardown_mount(&mount, ipc_buf);
    finish_unmount(rt, idx, ipc_buf);
    std::os::seraph::log!("UNMOUNT: done");
    IpcMessage::new(ipc::vfsd_errors::SUCCESS)
}

/// Unmount, with its files open or not, the mount at node `idx` whose
/// removal the watch thread or a `MOUNT` began after its disk was lost
/// (`watch::claim`): `FS_UNMOUNT` with `fs_labels::UNMOUNT_FORCE`, then the
/// teardown and the record's removal, as [`do_unmount`] does with
/// [`Force::Yes`].
fn force_unmount(rt: &VfsdRuntime, idx: u32, mount: &Mount, ipc_buf: *mut u64)
{
    if !matches!(
        driver_unmount(mount.endpoint, Force::Yes, ipc_buf),
        DriverUnmount::Done
    )
    {
        std::os::seraph::log!(
            warn: "forced unmount: the driver did not unmount; tearing it down without it"
        );
    }
    teardown_mount(mount, ipc_buf);
    finish_unmount(rt, idx, ipc_buf);
    std::os::seraph::log!("forced unmount: done");
}

/// End the removal begun on node `idx` once its driver is torn down: clear
/// the record, and give a node that stays an intermediate its fall-through
/// cap.
fn finish_unmount(rt: &VfsdRuntime, idx: u32, ipc_buf: *mut u64)
{
    let needs_fallthrough = {
        let mut backend = rt
            .root_backend
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if backend.remove_mount(idx).is_none()
        {
            std::os::seraph::log!(error: "unmount: the finished removal was not under way");
        }
        backend.needs_fallthrough(idx)
    };
    // A node with a mount below it stays visible as an intermediate; the
    // unmount walks for its fall-through cap, as an install walks for the
    // intermediates it makes visible.
    if needs_fallthrough
    {
        populate_fallthrough_caps(rt, ipc_buf, &[idx]);
    }
}

/// The driver's answer to `FS_UNMOUNT`.
enum DriverUnmount
{
    /// It released every open and exits.
    Done,
    /// It kept serving: this many opens are live.
    Busy(u64),
    /// It answered anything else, or not at all within
    /// [`FS_UNMOUNT_TIMEOUT_MS`].
    Failed,
}

/// Send `FS_UNMOUNT` (with `fs_labels::UNMOUNT_FORCE` on [`Force::Yes`])
/// to the driver behind `endpoint`, on a SEND derived for the call.
fn driver_unmount(endpoint: u64, force: Force, ipc_buf: *mut u64) -> DriverUnmount
{
    let Ok(send) = syscall::cap_derive(endpoint, syscall::RIGHTS_EP_SEND)
    else
    {
        std::os::seraph::log!(warn: "UNMOUNT: driver SEND derive failed");
        return DriverUnmount::Failed;
    };
    let label = match force
    {
        Force::No => ipc::fs_labels::FS_UNMOUNT,
        Force::Yes => ipc::fs_labels::FS_UNMOUNT | ipc::fs_labels::UNMOUNT_FORCE,
    };
    let msg = IpcMessage::builder(label)
        .word(0, u64::from(ipc::FS_LABELS_VERSION))
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer.
    let reply = unsafe { ipc::ipc_call_timeout(send, &msg, ipc_buf, FS_UNMOUNT_TIMEOUT_MS) };
    log_cap_delete("FS_UNMOUNT send", send);
    match reply
    {
        Ok(reply) if reply.label == ipc::fs_errors::SUCCESS => DriverUnmount::Done,
        Ok(reply) if reply.label == ipc::fs_errors::BUSY => DriverUnmount::Busy(reply.word(0)),
        Ok(reply) =>
        {
            std::os::seraph::log!(warn: "UNMOUNT: FS_UNMOUNT answered {:#x}", reply.label);
            DriverUnmount::Failed
        }
        Err(code) =>
        {
            std::os::seraph::log!(warn: "UNMOUNT: FS_UNMOUNT call failed: code={code}");
            DriverUnmount::Failed
        }
    }
}

/// Tear down the driver of a mount whose unmount began: revoke its
/// partition cap, so it reaches the disk no more; revoke its service
/// endpoint ([`driver::teardown_driver`]), which invalidates every cap a
/// client holds on the mount; wait, bounded, for its death to post; then
/// destroy its process ([`destroy_driver`]), which a driver that did not
/// exit needs and one that did takes as a no-op.
fn teardown_mount(mount: &Mount, ipc_buf: *mut u64)
{
    revoke_partition(mount.partition);
    driver::teardown_driver(mount.endpoint);
    match syscall::event_recv_timeout(mount.death_queue, DRIVER_DEATH_TIMEOUT_MS)
    {
        Ok(reason) => std::os::seraph::log!(debug: "unmount: driver exited: reason={reason:#x}"),
        Err(code) => std::os::seraph::log!(
            warn: "unmount: no driver death within {DRIVER_DEATH_TIMEOUT_MS} ms (code={code}); \
             destroying it"
        ),
    }
    destroy_driver(mount, ipc_buf);
}

/// Tear down the driver of a mount whose removal began after its death:
/// revoke its partition cap and its service endpoint, as
/// [`teardown_mount`] does, and destroy what is left of its process; its
/// death has posted, so nothing is waited for.
fn teardown_dead_mount(mount: &Mount, ipc_buf: *mut u64)
{
    revoke_partition(mount.partition);
    driver::teardown_driver(mount.endpoint);
    destroy_driver(mount, ipc_buf);
}

/// Destroy a torn-down driver's process (`DESTROY_PROCESS`, a no-op for one
/// that exited), and delete its process handle and death queue.
fn destroy_driver(mount: &Mount, ipc_buf: *mut u64)
{
    let destroy = IpcMessage::new(ipc::procmgr_labels::DESTROY_PROCESS);
    // SAFETY: ipc_buf is the registered IPC buffer.
    if let Err(code) = unsafe { ipc::ipc_call(mount.process, &destroy, ipc_buf) }
    {
        std::os::seraph::log!(warn: "unmount: DESTROY_PROCESS failed: code={code}");
    }
    log_cap_delete("driver process handle", mount.process);
    log_cap_delete("driver death queue", mount.death_queue);
}

/// One-shot best-effort mount of the partition `want` resolves to at
/// `mount_path` ([`resolve_role`]). When none resolves, the resolution
/// logs why and `mount_path` resolves through the root-fs fall-through. On
/// a match, runs the mount transaction and logs the outcome. Never fatal,
/// unlike the root self-mount, whose failure gates boot. Idempotent if
/// invoked twice: a mount on an already-terminal mount path is rejected by
/// [`VfsdRootBackend::can_install`] before any partition is registered or
/// driver spawned.
fn auto_mount_role(rt: &VfsdRuntime, ipc_buf: *mut u64, want: Want<'_>, mount_path: &[u8])
{
    let shown = core::str::from_utf8(mount_path).unwrap_or("<non-UTF-8 path>");
    match do_mount_internal(rt, ipc_buf, want, mount_path, Discover::No)
    {
        Ok(caller_cap) =>
        {
            // The auto-mount has no IPC caller for the returned badged SEND;
            // vfsd reaches the mount through its synthetic backend.
            log_cap_delete("auto-mount caller cap", caller_cap);
            std::os::seraph::log!("MOUNT: {shown} auto-mounted");
        }
        Err(code) => std::os::seraph::log!(
            warn: "MOUNT: {shown} not auto-mounted: code={code:#x}"
        ),
    }
}

/// Delete `slot` and log the kernel error code on failure. A no-op on
/// `slot == 0` (sentinel for "no cap held"). Used at every `cap_delete`
/// site whose failure would otherwise be operator-invisible: the kernel
/// reports invalid-slot / table-corruption via the returned code and
/// silent discards leak that notification.
fn log_cap_delete(context: &str, slot: u64)
{
    if slot == 0
    {
        return;
    }
    if let Err(code) = syscall::cap_delete(slot)
    {
        std::os::seraph::log!(
            warn: "MOUNT: cap_delete({context}, slot={slot}) failed: code={code}"
        );
    }
}

/// Whether `path` denotes the mount root — `/`, the empty path, or an
/// all-separator string like `///` — i.e. has no non-empty component.
/// Mirrors [`VfsdRootBackend::install`]'s root-vs-terminal split so the
/// mount transaction stores the matching cap kind for each role: a
/// badged fall-through SEND for the root, the unbadged driver endpoint
/// for a terminal mount.
fn mount_path_is_root(path: &[u8]) -> bool
{
    path.split(|&b| b == b'/').all(<[u8]>::is_empty)
}

/// Mount the partition `role` names at `path`.
///
/// Resolves the role ([`resolve_role`]) after discovering the disks devmgr
/// served since the last discovery ([`find_partition`]), registers
/// the partition bound with the block driver of the disk that holds it,
/// spawns a fatfs driver, and stores the mount's record in
/// [`VfsdRootBackend`]: the driver's namespace endpoint (terminal mounts)
/// or a badged SEND on the root fs (the root mount), through which the
/// system-root cap resolves into the new mount, with the driver's caps and
/// the partition cap (`docs/namespace-composition.md` § Mount record).
///
/// On success returns a fresh badged SEND for the caller (zero if
/// minting failed; the mount itself still landed). On failure
/// returns the matching `vfsd_errors::*` label.
pub(crate) fn do_mount(
    rt: &VfsdRuntime,
    ipc_buf: *mut u64,
    role: MountRole,
    path: &[u8],
) -> Result<u64, u64>
{
    do_mount_internal(rt, ipc_buf, role.want(path), path, Discover::First)
}

/// Whether a mount's role lookup first discovers the disks devmgr served
/// since the last discovery.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Discover
{
    /// Resolve over the held disks alone: the startup self-mount and the
    /// auto-mounts after a root mount.
    No,
    /// Discover first ([`discover_new_disks`]): a runtime `MOUNT`.
    First,
}

/// The partition `want` resolves to ([`resolve_role`]), and the whole-disk
/// cap of the disk that holds it. On [`Discover::First`] the disks devmgr
/// served since the last discovery are held first, so a partition the
/// statement names on a disk added after startup is found. A failure,
/// which the resolution logs, returns `vfsd_errors::NO_MOUNT`; the caller
/// decides what it means (the root self-mount treats it as fatal, an
/// auto-mount skips its path).
fn find_partition(
    rt: &VfsdRuntime,
    ipc_buf: *mut u64,
    want: Want<'_>,
    discover: Discover,
) -> Result<(gpt::PartitionLocation, u64), u64>
{
    if discover == Discover::First
    {
        discover_new_disks(rt, ipc_buf);
    }
    resolve_role(rt, want).map_err(|_| ipc::vfsd_errors::NO_MOUNT)
}

/// The whole-disk cap of the held disk at `disk`; `None` once it is
/// removed.
fn held_disk_cap(rt: &VfsdRuntime, disk: usize) -> Option<u64>
{
    rt.disks
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(disk)
        .map(|d| d.blk_ep)
        .filter(|&ep| ep != 0)
}

/// Query devmgr for the disks it served since the last discovery and hold
/// each one ([`partition::Discovery::discover`]). Disks the table has no
/// room for are released, and the next discovery queries them again.
fn discover_new_disks(rt: &VfsdRuntime, ipc_buf: *mut u64)
{
    // The discovery lock is held until the new disks are in the table, so a
    // concurrent MOUNT's discovery, which finds none of them, looks them up
    // after they are held.
    let mut discovery = rt.discovery.lock().unwrap_or_else(PoisonError::into_inner);
    let found = discovery.discover(ipc_buf);
    hold_new_disks(rt, discovery, found, ipc_buf);
}

/// Append the disks `found`, which `discovery` just found, to the disk
/// table, holding `discovery` until they are, then ask devmgr again
/// whether it serves each one ([`watch::probe_disk`]). When the table has
/// no room, their caps are deleted and `discovery` queries them again on
/// its next run.
fn hold_new_disks(
    rt: &VfsdRuntime,
    mut discovery: std::sync::MutexGuard<'_, partition::Discovery>,
    found: Vec<partition::Disk>,
    ipc_buf: *mut u64,
)
{
    let Some(first) = found.first().map(|d| d.ordinal)
    else
    {
        return;
    };
    let mut disks = rt.disks.lock().unwrap_or_else(PoisonError::into_inner);
    let start = disks.len();
    if disks.try_reserve(found.len()).is_err()
    {
        drop(disks);
        std::os::seraph::log!(warn: "no memory to hold {} new disk(s)", found.len());
        discovery.rewind(first);
        for disk in found
        {
            log_cap_delete("unheld disk", disk.blk_ep);
        }
        return;
    }
    disks.extend(found);
    let end = disks.len();
    drop(disks);
    drop(discovery);
    // devmgr may have withdrawn a disk after discovery asked about it and
    // before it was held, and the watch thread, probing the disks held then,
    // passed it; asking again once it is held closes that window, as a later
    // withdrawal signals a watch that finds it held.
    for disk in start..end
    {
        watch::probe_disk(rt, disk, ipc_buf);
    }
}

/// Shared implementation for both role-driven (`do_mount`) and
/// internally-triggered (`auto_mount_role`) mounts. Takes a [`Want`]
/// directly so callers without a [`MountRole`] (the `/esp` and data
/// auto-mounts) can reuse the transaction body.
#[expect(
    clippy::too_many_lines,
    reason = "the mount-and-publish transaction runs inline. The install pre-check, partition \
              registration with virtio-blk, fatfs spawn, synthetic-root install, and \
              namespace-root cap minting share the `partition` / `fatfs` / `driver_ep` locals, \
              and every failure arm after the spawn releases the mount through \
              `release_failed_mount`; folding a subset into helpers would thread those locals \
              through and hide which arm releases what"
)]
fn do_mount_internal(
    rt: &VfsdRuntime,
    ipc_buf: *mut u64,
    want: Want<'_>,
    path: &[u8],
    discover: Discover,
) -> Result<u64, u64>
{
    let (location, blk_ep) = find_partition(rt, ipc_buf, want, discover)?;
    let (partition_lba, partition_len) = (location.first_lba, location.length_lba);
    std::os::seraph::log!(
        debug: "MOUNT: partition on disk {} LBA={partition_lba:#018x} length={partition_len:#018x}",
        location.disk
    );

    // Reject a mount the synthetic root would refuse (root already mounted,
    // `path` already a mount point, or a component the namespace protocol
    // cannot name), and a second mount of a partition a mount holds, before
    // registering a partition or spawning a driver for it.
    let (installable, held) = {
        let backend = rt
            .root_backend
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        (
            backend.can_install(path),
            backend.holds_partition(location.disk, partition_lba),
        )
    };
    if !installable
    {
        std::os::seraph::log!(warn: "MOUNT: mount point taken or path not installable");
        return Err(ipc::vfsd_errors::TABLE_FULL);
    }
    if held
    {
        std::os::seraph::log!(warn: "MOUNT: the partition is already mounted");
        return Err(ipc::vfsd_errors::TABLE_FULL);
    }

    // vfsd keeps the registered partition cap in the mount record and hands
    // the driver a derivation of it, so revoking the kept cap cuts the
    // driver off the partition (`docs/namespace-composition.md` § Mount
    // record).
    let Some(partition) =
        derive_and_register_partition(blk_ep, partition_lba, partition_len, ipc_buf)
    else
    {
        std::os::seraph::log!(warn: "MOUNT: partition cap registration failed");
        return Err(ipc::vfsd_errors::SPAWN_FAILED);
    };
    let Ok(partition_ep) = syscall::cap_derive(partition, syscall::RIGHTS_EP_SEND_GRANT)
    else
    {
        std::os::seraph::log!(warn: "MOUNT: partition cap derive failed");
        revoke_partition(partition);
        return Err(ipc::vfsd_errors::SPAWN_FAILED);
    };

    // First MOUNT (root) consumes the boot module cap; later mounts pass 0
    // and the spawn path walks vfsd's own system-root cap to /services/fs/fatfs
    // and uses procmgr `CREATE_FROM_FILE` via a worker. Hold the lock
    // only across the swap so other handlers can read it (and observe
    // 0) immediately.
    let module_cap_for_spawn = {
        let mut bmc = rt
            .boot_module_cap
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let v = *bmc;
        *bmc = 0;
        v
    };

    // `spawn_fatfs_driver` owns `partition_ep` from here: it is the child's
    // on success and released on failure.
    let Some(fatfs) = driver::spawn_fatfs_driver(
        &rt.caps,
        &rt.pool,
        path,
        partition_ep,
        module_cap_for_spawn,
        rt.system_root_cap,
        ipc_buf,
    )
    else
    {
        std::os::seraph::log!(warn: "MOUNT: failed to spawn fatfs");
        log_cap_delete("module_cap (spawn-fail)", module_cap_for_spawn);
        revoke_partition(partition);
        return Err(ipc::vfsd_errors::SPAWN_FAILED);
    };
    let driver_ep = fatfs.send;

    // Root MOUNT succeeded — drop the boot module cap. The IPC has already
    // transferred a derived child to procmgr; this releases vfsd's outer slot.
    log_cap_delete("module_cap (post-spawn)", module_cap_for_spawn);

    // The MOUNT caller receives a full-rights badged SEND on this
    // mount's root (the mounter holds full authority over the mount it
    // requested); internal/auto callers drop it. Revocation is
    // destroy-the-fs-driver: `cap_revoke` on the driver's namespace
    // endpoint cascades through the kernel derivation graph and
    // invalidates every cap ever derived from it — the namespace-model
    // `kill the server` shape (see `docs/namespace-model.md`
    // § Revocation). Per-cap revocation is not supported by this scheme.
    let root_badge = namespace_protocol::pack(
        namespace_protocol::NodeId::ROOT,
        namespace_protocol::NamespaceRights::ALL,
    );
    let caller_root_cap =
        syscall::cap_derive_badge(driver_ep, syscall::RIGHTS_EP_SEND, root_badge).ok();

    // What the backend retains for this mount depends on its role:
    //   - Root mount (`/`): a *badged* full-rights SEND on the root fs,
    //     kept as the synthetic root's `fallthrough_cap`. The
    //     fall-through forwarder pre-composes each forwarded request
    //     with the caller's own rights (`compose_forward_lookup_rights`),
    //     so a full-rights badge here cannot over-grant; `driver_ep` is
    //     not retained, and is deleted once the badged caps exist (they
    //     stay derived from `fatfs.endpoint`).
    //   - Terminal mount (`/esp`, `/data`, …): the *unbadged* driver
    //     endpoint itself. Every `NS_LOOKUP` crossing the mount mints a
    //     freshly-attenuated badged SEND from it (the
    //     `EntryTarget::External` arm of `handle_lookup`). Storing the
    //     endpoint rather than a pre-badged root cap is what carries
    //     attenuation across the mount boundary: the kernel forbids
    //     re-badging an already-badged cap, so a stored badged cap
    //     could only ever be `cap_derive`-copied at full rights.
    let install_cap = if mount_path_is_root(path)
    {
        let Ok(c) = syscall::cap_derive_badge(driver_ep, syscall::RIGHTS_EP_SEND, root_badge)
        else
        {
            std::os::seraph::log!(warn: "MOUNT: root fall-through cap derive failed");
            // Revoking the endpoint also invalidates `caller_root_cap` and
            // stops the driver, which nothing would reach otherwise.
            release_failed_mount(&fatfs, partition);
            return Err(ipc::vfsd_errors::IO_ERROR);
        };
        c
    }
    else
    {
        driver_ep
    };

    // Install the mount, its death queue joining the watch set in the same
    // hold (the claim rule of `watch`), so the watch thread sees the driver's
    // death only once the mount is in the tree; capture the synthetic
    // intermediates the install made visible so we can populate their
    // fall-through caps after releasing the lock (the walk needs IPC and we
    // must not block other namespace traffic on it).
    let install_result = {
        let mut backend = rt
            .root_backend
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let mount = Mount {
            cap: install_cap,
            endpoint: fatfs.endpoint,
            process: fatfs.process,
            death_queue: fatfs.death_queue,
            partition,
            disk: location.disk,
            first_lba: partition_lba,
        };
        // A concurrent MOUNT of the partition may have installed since the
        // check before the spawn: one driver serves a partition.
        let observed = if backend.holds_partition(location.disk, partition_lba)
        {
            false
        }
        else
        {
            rt.watch.add(&backend, fatfs.death_queue)
        };
        let installed = if observed
        {
            backend.install(path, mount)
        }
        else
        {
            None
        };
        if observed && installed.is_none()
        {
            rt.watch.remove(&backend, fatfs.death_queue);
        }
        installed
    };
    let Some(install_result) = install_result
    else
    {
        // A concurrent MOUNT took the mount point or the partition since the
        // checks before the spawn, the tree holds its most mounts, or it could
        // not grow, or the watch set refused the death queue. Revoking the
        // endpoint invalidates `install_cap` and `caller_root_cap` (both
        // derive from it) and stops the driver nothing would reach.
        std::os::seraph::log!(
            warn: "MOUNT: synthetic-root install failed (mount point or partition taken, \
             mount limit, no memory, or driver not observed)"
        );
        release_failed_mount(&fatfs, partition);
        return Err(ipc::vfsd_errors::TABLE_FULL);
    };

    if install_cap != driver_ep
    {
        // Root mount: the badged fall-through and caller caps are derived,
        // so the unbadged SEND_GRANT has no further use.
        log_cap_delete("root mount driver_ep", driver_ep);
    }
    // The mount record now holds `fatfs.endpoint`, the process handle, the
    // death queue and the partition cap for the life of the mount.

    populate_fallthrough_caps(rt, ipc_buf, install_result.as_slice());

    // The claims of a disk found removed may have passed this mount before
    // its install.
    if watch::unmount_if_removed(rt, location.disk, fatfs.death_queue, ipc_buf)
    {
        std::os::seraph::log!(warn: "MOUNT: the disk was removed during the mount");
        log_cap_delete("caller cap (disk removed)", caller_root_cap.unwrap_or(0));
        return Err(ipc::vfsd_errors::NO_MOUNT);
    }

    std::os::seraph::log!("MOUNT: registered");
    Ok(caller_root_cap.unwrap_or(0))
}

/// Release what a mount transaction holds once it fails after its driver
/// started: the partition cap is revoked, cutting the driver off its
/// partition; the driver's service endpoint is revoked
/// ([`driver::teardown_driver`]), invalidating every cap minted from it
/// and stopping the driver; and the process handle and death queue are
/// deleted.
fn release_failed_mount(fatfs: &driver::FatfsDriver, partition: u64)
{
    revoke_partition(partition);
    driver::teardown_driver(fatfs.endpoint);
    log_cap_delete("driver process handle", fatfs.process);
    log_cap_delete("driver death queue", fatfs.death_queue);
}

/// Revoke and delete a partition cap vfsd registered: the driver's
/// derivation of it stops reaching the block driver.
fn revoke_partition(partition: u64)
{
    if let Err(code) = syscall::cap_revoke_all(partition)
    {
        std::os::seraph::log!(warn: "partition revoke: cap_revoke_all failed: code={code}");
    }
    log_cap_delete("partition cap", partition);
}

/// For each synthetic intermediate the install made visible, walk the
/// root mount to the corresponding directory and record the resulting
/// cap as that intermediate's `fallthrough_cap`.
///
/// A walk that fails (root mount not yet installed, or the path does
/// not exist in the root filesystem) leaves `fallthrough_cap = 0`;
/// subsequent unmatched lookups against that intermediate then reply
/// `NotFound` instead of forwarding. A walked cap the tree refuses,
/// because the node no longer needs one by the time the walk ends, is
/// deleted. Every skip is logged.
fn populate_fallthrough_caps(rt: &VfsdRuntime, ipc_buf: *mut u64, intermediates: &[u32])
{
    for &node_idx in intermediates
    {
        let (path, root_mount_cap) = {
            let backend = rt
                .root_backend
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            (backend.path_of(node_idx), backend.root_mount_cap())
        };
        let Some(path) = path
        else
        {
            std::os::seraph::log!(
                warn: "MOUNT: fallthrough skip node_idx={node_idx}: no memory for its path",
            );
            continue;
        };
        if root_mount_cap == 0
        {
            std::os::seraph::log!(
                warn: "MOUNT: fallthrough skip node_idx={node_idx}: no root mount installed",
            );
            continue;
        }
        if let Some(cap) = walk_root_mount_path(root_mount_cap, &path, ipc_buf)
        {
            let stored = rt
                .root_backend
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .set_fallthrough_cap(node_idx, cap);
            if !stored
            {
                std::os::seraph::log!(
                    warn: "MOUNT: fallthrough skip node_idx={node_idx}: the node no longer \
                     needs one",
                );
                log_cap_delete("unneeded fallthrough cap", cap);
            }
        }
        else
        {
            // Install validated every component as UTF-8 (`validate_name`).
            let shown = core::str::from_utf8(&path).unwrap_or("<non-UTF-8>");
            std::os::seraph::log!(
                warn: "MOUNT: fallthrough skip node_idx={node_idx}: no directory {shown} \
                 in the root fs",
            );
        }
    }
}

/// Walk `root_mount_cap` to `path` (a `/`-prefixed slash-separated
/// component list) via per-component `NS_LOOKUP`. Each intermediate
/// cap is dropped as the walk descends; only the final cap survives,
/// returned to the caller. Returns `None` on any walk failure or if
/// any intermediate is not a directory. Each lookup is bounded by
/// [`FALLTHROUGH_TIMEOUT_MS`], since the walk also runs on the watch thread
/// (`finish_unmount` of a driver's teardown), which a root fs that stops
/// answering must not hold.
fn walk_root_mount_path(root_mount_cap: u64, path: &[u8], ipc_buf: *mut u64) -> Option<u64>
{
    let stripped = path.trim_prefix(b"/");
    if stripped.is_empty()
    {
        return None;
    }
    let mut current_cap: u64 = root_mount_cap;
    let mut current_owned = false;
    for component in stripped.split(|&b| b == b'/')
    {
        if component.is_empty()
        {
            continue;
        }
        // Components are bounded by `namespace_protocol::MAX_NAME_LEN`
        // (255), which `install` enforces, so the length fits the label's
        // 16-bit name-length field and the request's data words.
        let name_len = component.len() as u64;
        let label = ns_labels::NS_LOOKUP | (name_len << 16);
        let msg = IpcMessage::builder(label)
            .word(0, 0xFFFF)
            .bytes(1, component)
            .build();
        // SAFETY: ipc_buf is the thread-registered IPC buffer page.
        let reply =
            unsafe { ipc::ipc_call_timeout(current_cap, &msg, ipc_buf, FALLTHROUGH_TIMEOUT_MS) };
        if current_owned
        {
            let _ = syscall::cap_delete(current_cap);
        }
        let Ok(reply) = reply
        else
        {
            return None;
        };
        if reply.label != 0
        {
            return None;
        }
        // word(0) is the entry kind; word(1) the size hint. We require
        // a directory at every walk step; a file at an intermediate
        // path means the install is structurally inconsistent.
        let kind = reply.word(0);
        if kind != namespace_protocol::NodeKind::Dir as u64
        {
            if let Some(&cap) = reply.caps().first()
            {
                let _ = syscall::cap_delete(cap);
            }
            return None;
        }
        let &next = reply.caps().first()?;
        current_cap = next;
        current_owned = true;
    }
    if current_owned
    {
        Some(current_cap)
    }
    else
    {
        None
    }
}

fn idle_loop() -> !
{
    loop
    {
        let _ = syscall::thread_yield();
    }
}

/// Register a partition bound with the block driver of the disk that holds
/// it, through that disk's whole-disk cap `blk_ep`, and receive back a
/// badged `SEND_GRANT` cap scoped to that partition.
///
/// `blk_ep` is itself a badged cap (the `blk_labels::MOUNT_AUTHORITY` cap
/// minted by devmgr), so vfsd cannot mint partition caps locally — the
/// kernel rejects re-badging of a badged source. Partition cap
/// derivation lives server-side in virtio-blk; this call just sends the
/// bounds and consumes the cap from the reply.
fn derive_and_register_partition(
    blk_ep: u64,
    base_lba: u64,
    length_lba: u64,
    ipc_buf: *mut u64,
) -> Option<u64>
{
    let msg = IpcMessage::builder(blk_labels::REGISTER_PARTITION)
        .word(0, u64::from(ipc::BLK_LABELS_VERSION))
        .word(1, base_lba)
        .word(2, length_lba)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let Ok(reply) = (unsafe { ipc::ipc_call(blk_ep, &msg, ipc_buf) })
    else
    {
        std::os::seraph::log!(warn: "REGISTER_PARTITION ipc_call failed");
        return None;
    };
    if reply.label != ipc::blk_errors::SUCCESS
    {
        std::os::seraph::log!(warn: "REGISTER_PARTITION rejected (code={})", reply.label);
        return None;
    }
    reply.caps().first().copied()
}
