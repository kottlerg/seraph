// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svcmgr/src/main.rs

//! Seraph service manager — monitors services, detects crashes via a
//! growable set of death-notification event queues, and restarts them per
//! their restart policy.
//!
//! svcmgr is loaded from the root filesystem by init (via procmgr's
//! `CREATE_FROM_FILE`). Init serves svcmgr its handover endowment
//! over bootstrap rounds, then sends `HANDOVER_COMPLETE` through a
//! `HANDOVER_AUTHORITY`-badged SEND and exits. svcmgr runs for the lifetime
//! of the system.
//!
//! Every supervised service has two death observers on svcmgr's death queues:
//! one on its main thread and one on its address space, which a terminal
//! fault of any of its threads posts. Both post the service's `DeathTag`, its
//! table slot and instance, as the correlator; a further queue joins when
//! every pool is out of nodes. The main wait set, which `death_set::DeathSet`
//! owns and widens as the queues fill it, holds the service endpoint (badge
//! 0), every death queue (badge 1) and the memory-pressure Notification
//! (badge 2), which wakes a restart that waits for memory. On death wakeup
//! svcmgr drains the queues and routes each payload to its `ServiceEntry` via
//! the tag, dropping a post of an instance already routed.
//! Multiplexing avoids consuming a wait-set slot per supervised process.
//!
//! See `svcmgr/docs/ipc-interface.md` and `svcmgr/docs/restart-protocol.md`.

mod arch;
mod classes;
mod config;
mod death_queues;
mod definitions;
mod endowed_servers;
mod restart;
mod service;
mod stop;

use definitions::reconcile::{PendingRegistration, ServiceTable};
use ipc::{IpcMessage, svcmgr_labels};
use registry::{Resolver, Visibility};
use service::bootstrap_caps;
use std::os::seraph::{StartupInfo, startup_info};
use svcmgr_defs::DeathTag;
use svcmgr_defs::drivers_dir;
use svcmgr_defs::memory_wait::{MemoryWaits, Timer, Wake};
use syscall_abi::SyscallError;

/// Monotonic time since the first call, in nanoseconds, for the windowed
/// restart budget. Saturates rather than wraps.
pub(crate) fn now_ns() -> u64
{
    static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    let start = START.get_or_init(std::time::Instant::now);
    u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

/// Read a name of `name_len` bytes packed into IPC data words from word 0,
/// as `svcmgr_labels::pack_name` packs it. `None` when the length is 0 or
/// past `svcmgr_labels::NAME_MAX`, or the message carries too few words.
pub(crate) fn read_name_from_msg(
    msg: &IpcMessage,
    name_len: usize,
) -> Option<[u8; svcmgr_labels::NAME_MAX]>
{
    svcmgr_labels::unpack_name(msg.words(), name_len)
}

// ── Halt ───────────────────────────────────────────────────────────────────

/// Halt the CPU in an infinite loop. Used on unrecoverable failures.
pub fn halt_loop() -> !
{
    loop
    {
        arch::current::halt();
    }
}

// ── Entry point ────────────────────────────────────────────────────────────

fn main() -> !
{
    std::os::seraph::log::register_name(b"svcmgr");
    let info = startup_info();

    // IPC buffer was registered by `std::os::seraph::_start`. The raw
    // pointer is all the new `ipc::ipc_call`/`ipc_recv`/`ipc_reply` and
    // `ipc::bootstrap::*` wrappers need.
    #[expect(
        clippy::cast_ptr_alignment,
        reason = "IPC buffer is page-aligned by the boot protocol"
    )]
    let ipc_buf = info.ipc_buffer.cast::<u64>();

    // State is created before the endowment is drained so `bootstrap_caps`
    // can park the substrate `(name, thread_cap)` pairs directly in
    // `state.pending`; `HANDOVER_COMPLETE` reconciles them later.
    let mut state = SvcmgrState {
        table: ServiceTable::new(),
        pending: Vec::new(),
        registry: registry::Registry::new(),
        handover_done: false,
    };

    let Some(caps) = bootstrap_caps(info, ipc_buf, &mut state.pending)
    else
    {
        syscall::thread_exit();
    };

    std::os::seraph::log!("started");

    if caps.service_ep == 0
    {
        std::os::seraph::log!(error: "no service endpoint, halting");
        halt_loop();
    }
    if info.procmgr_endpoint == 0
    {
        std::os::seraph::log!(error: "no procmgr endpoint, halting");
        halt_loop();
    }

    // The main wait set, holding the service endpoint, room for the
    // memory-pressure Notification (`event_loop`), and the first death queue;
    // further queues join it as pools run out, and it is replaced by a wider
    // one as they fill it.
    let Some(deaths) = death_set::DeathSet::new(
        caps.service_ep,
        WS_BADGE_SERVICE,
        1,
        WS_BADGE_DEATHS,
        death_queues::DEATHS_EQ_CAPACITY,
        death_queues::FIRST_POOL_OBSERVERS,
    )
    else
    {
        std::os::seraph::log!(error: "failed to create the main wait set and first death queue");
        halt_loop();
    };

    // Publish the well-known names svcmgr owns, configure devmgr's device
    // classes and publish their SENDs, and hand devmgr its drivers dir — all
    // from the handover endowment caps — before the event loop, so they are
    // in place before `HANDOVER_COMPLETE` drives reconciliation and any
    // launched consumer resolves them.
    publish_well_known(&mut state.registry, &caps);
    classes::configure(
        &mut state.registry,
        caps.devmgr_registry,
        &state.pending,
        ipc_buf,
    );
    install_drivers_dir(&caps, &state.pending, ipc_buf);

    let core_death_queue = observe_core_deaths(info, &state.pending);

    std::os::seraph::log!("endowed; waiting for handover");

    event_loop(info, &caps, deaths, core_death_queue, ipc_buf, &mut state);
}

/// Entries and observers of the core-death queue: one main-thread and one
/// address-space observer each for svcmgr, memmgr and procmgr, each posting
/// once in its life.
const CORE_DEATH_CAPACITY: u32 = 6;

/// Create the core-death queue and bind on it the death observers of the core
/// set (docs/supervision.md § Core Set and System Death): svcmgr's own main
/// thread and address space, under `pwrmgr_labels::CORE_DEATH_SVCMGR`, and
/// memmgr's and procmgr's, through the thread and `Control`-only
/// address-space caps init endowed in their `SUBSTRATE` rounds (`pending`),
/// under their own correlators (`svcmgr_defs::core_death_correlator`). Each
/// main thread's exit and the first terminal end of any thread of each
/// member post an entry, and a member already dead posts its retained reason
/// as the bind lands. The binds need Control, which svcmgr alone holds, so
/// svcmgr makes them and hands the shutdown actuator only a receive-only
/// derivation of the queue ([`restart::mint_core_death_recv`]); svcmgr routes
/// no core death itself. Returns the queue, or `0`, logged, when it cannot
/// be created or no observer binds; each observer that does not bind is
/// logged.
fn observe_core_deaths(info: &StartupInfo, pending: &[PendingRegistration]) -> u64
{
    let Some(queue) = std::os::seraph::object_slab_retype(
        std::os::seraph::event_queue_retype_bytes(
            u64::from(CORE_DEATH_CAPACITY),
            u64::from(CORE_DEATH_CAPACITY),
        ),
        |slab| {
            syscall::event_queue_create_observed(slab, CORE_DEATH_CAPACITY, CORE_DEATH_CAPACITY)
                .ok()
        },
    )
    else
    {
        std::os::seraph::log!(error: "core-death queue not created; a core death is unobserved");
        return 0;
    };
    let mut bound = bind_core_member(
        queue,
        "svcmgr",
        info.self_thread,
        info.self_aspace,
        ipc::pwrmgr_labels::CORE_DEATH_SVCMGR,
    );
    for registration in pending
    {
        let Some(correlator) = svcmgr_defs::core_death_correlator(registration.name_str())
        else
        {
            continue;
        };
        let aspace = match registration.observer
        {
            svcmgr_endowment::SubstrateObserver::AddressSpace(cap) => cap,
            svcmgr_endowment::SubstrateObserver::ProcessHandle(_)
            | svcmgr_endowment::SubstrateObserver::None => 0,
        };
        bound |= bind_core_member(
            queue,
            registration.name_str(),
            registration.thread_cap,
            aspace,
            correlator,
        );
    }
    if !bound
    {
        std::os::seraph::log!(error: "no core-death observer bound; a core death is unobserved");
        let _ = syscall::cap_delete(queue);
        return 0;
    }
    queue
}

/// Bind the core member `name`'s main-thread observer through `thread` and
/// its address-space observer through `aspace` (`0`: none endowed) on
/// `queue`, both under `correlator`. Each observer that does not bind is
/// logged at error level; whether either bound.
fn bind_core_member(queue: u64, name: &str, thread: u64, aspace: u64, correlator: u64) -> bool
{
    let thread_bound = syscall::thread_bind_notification(thread, queue, correlator).is_ok();
    if !thread_bound
    {
        std::os::seraph::log!(
            error: "{name}'s main-thread core-death observer not bound; its main-thread exit is \
             unobserved"
        );
    }
    let aspace_bound =
        aspace != 0 && syscall::aspace_bind_notification(aspace, queue, correlator).is_ok();
    if !aspace_bound
    {
        std::os::seraph::log!(
            error: "{name}'s address-space core-death observer not bound; a worker fault of {name} \
             is unobserved"
        );
    }
    thread_bound || aspace_bound
}

/// Publish the well-known names svcmgr owns into its own discovery
/// registry, from the caps init endowed at handover. These are internal
/// `registry.publish` calls (no `PUBLISH_AUTHORITY` badge — svcmgr owns
/// the registry). Each provider's own `provides` names are published
/// separately on the launch path ([`definitions::launch`]).
fn publish_well_known(registry: &mut registry::Registry, caps: &service::SvcmgrCaps)
{
    // rootfs.root — SEND on vfsd's synthetic root, endowed pre-derived by
    // init from its system-root cap. Seed-only: the whole namespace, across
    // every mount, reaches only the recipes that seed it.
    publish_endowed_send(
        registry,
        caps.rootfs_root,
        ipc::published_names::ROOTFS_ROOT,
    );
    // vfsd.mount / vfsd.deny / vfsd.swap — SENDs on vfsd's service
    // endpoint, endowed pre-badged by init (`MOUNT_AUTHORITY`, the
    // no-authority `DENY_BADGE`, and `SWAP_AUTHORITY`). Seed-only: svctest
    // alone seeds the first two; swapd's recipe seeds `vfsd.swap`, which
    // svctest's seeds too, to drive only the stale-version refusal.
    publish_endowed_send(registry, caps.vfsd_mount, ipc::published_names::VFSD_MOUNT);
    publish_endowed_send(registry, caps.vfsd_deny, ipc::published_names::VFSD_DENY);
    publish_endowed_send(registry, caps.vfsd_swap, ipc::published_names::VFSD_SWAP);
    // memmgr.swap — memmgr's swap authority, endowed pre-badged by init
    // (`SWAP_AUTHORITY`) with `GRANT`, which its seeds keep: each swap label
    // but `SWAP_DONE` moves a cap to memmgr. Seed-only: swapd's
    // recipe seeds it, and svctest's seeds it too, as a second swap client
    // that registers nothing.
    publish_endowed(
        registry,
        caps.memmgr_swap,
        ipc::published_names::MEMMGR_SWAP,
        Visibility::SeedOnlyGrant,
    );

    // svcmgr — SEND on svcmgr's own service endpoint (crasher seeds it),
    // badged so no consumer holds an unbadged source it could re-badge with
    // a verb bit.
    match syscall::cap_derive_badge(
        caps.service_ep,
        syscall::RIGHTS_EP_SEND,
        svcmgr_labels::PUBLISHED_SEND_BADGE,
    )
    {
        Ok(send) =>
        {
            if registry
                .publish(ipc::published_names::SVCMGR, send, Visibility::Public)
                .is_err()
            {
                std::os::seraph::log!(warn: "publish svcmgr failed");
                let _ = syscall::cap_delete(send);
            }
        }
        Err(_) => std::os::seraph::log!(warn: "derive svcmgr SEND failed"),
    }

    // devmgr.registry / devmgr.shutdown / devmgr.bind / devmgr.acpi — badged SENDs minted
    // from the endowed badge-0 `SEND|GRANT` source. The badge bits ride
    // through `registry_lookup_derived`'s plain `cap_derive` to consumers.
    // Each carries verb-bit authority, so each is seed-only: `QUERY_ENDPOINT`
    // refuses it, and only the recipes that seed the name hold its bits.
    // `devmgr.bind` keeps `GRANT` for its seeds (`SeedOnlyGrant`), since
    // `BIND_DRIVERS` moves a directory cap to devmgr.
    let query = ipc::devmgr_labels::REGISTRY_QUERY_AUTHORITY;
    for (name, badge, visibility) in [
        (
            ipc::published_names::DEVMGR_REGISTRY,
            query,
            Visibility::SeedOnly,
        ),
        (
            ipc::published_names::DEVMGR_SHUTDOWN,
            query | ipc::devmgr_labels::SHUTDOWN_DEVICE_AUTHORITY,
            Visibility::SeedOnly,
        ),
        (
            ipc::published_names::DEVMGR_BIND,
            query | ipc::devmgr_labels::BIND_AUTHORITY,
            Visibility::SeedOnlyGrant,
        ),
        (
            ipc::published_names::DEVMGR_ACPI,
            query | ipc::devmgr_labels::ACPI_AUTHORITY,
            Visibility::SeedOnly,
        ),
    ]
    {
        publish_minted_send(
            registry,
            caps.devmgr_registry,
            "devmgr-registry",
            name,
            badge,
            visibility,
        );
    }

    // logd.query — a `LOG_QUERY_AUTHORITY`-badged SEND minted from the
    // reserved master-log source: logd's query labels. Seed-only, like the
    // devmgr names above.
    publish_minted_send(
        registry,
        caps.master_log_source,
        "master-log",
        ipc::published_names::LOGD_QUERY,
        ipc::log_labels::LOG_QUERY_AUTHORITY,
        Visibility::SeedOnly,
    );
}

/// Publish the endowed, pre-derived SEND `cap` seed-only as `name`, as-is:
/// `registry_lookup_derived` re-derives a SEND per consumer and the badge
/// survives. Logs and skips when the cap is absent; deletes it when the
/// publish fails.
fn publish_endowed_send(registry: &mut registry::Registry, cap: u64, name: &[u8])
{
    publish_endowed(registry, cap, name, Visibility::SeedOnly);
}

/// [`publish_endowed_send`] with `visibility`: [`Visibility::SeedOnlyGrant`]
/// for an endowed `SEND|GRANT` whose seeds keep `GRANT`.
fn publish_endowed(registry: &mut registry::Registry, cap: u64, name: &[u8], visibility: Visibility)
{
    let shown = core::str::from_utf8(name).unwrap_or("?");
    if cap == 0
    {
        std::os::seraph::log!(warn: "no {shown} source cap; not published");
        return;
    }
    if registry.publish(name, cap, visibility).is_err()
    {
        std::os::seraph::log!(warn: "publish {shown} failed");
        let _ = syscall::cap_delete(cap);
    }
}

/// Publish `name` with `visibility`, a seed-only one, as a `badge`-badged
/// SEND minted from the endowed `source` (named `source_name` in the log),
/// with `GRANT` for [`Visibility::SeedOnlyGrant`]; logs and skips when the
/// source is absent or the derive or publish fails.
fn publish_minted_send(
    registry: &mut registry::Registry,
    source: u64,
    source_name: &str,
    name: &[u8],
    badge: u64,
    visibility: Visibility,
)
{
    let shown = core::str::from_utf8(name).unwrap_or("?");
    if source == 0
    {
        std::os::seraph::log!(warn: "no {source_name} source cap; {shown} not published");
        return;
    }
    let rights = if visibility == Visibility::SeedOnlyGrant
    {
        syscall::RIGHTS_EP_SEND_GRANT
    }
    else
    {
        syscall::RIGHTS_EP_SEND
    };
    match syscall::cap_derive_badge(source, rights, badge)
    {
        Ok(send) =>
        {
            if registry.publish(name, send, visibility).is_err()
            {
                std::os::seraph::log!(warn: "publish {shown} failed");
                let _ = syscall::cap_delete(send);
            }
        }
        Err(_) => std::os::seraph::log!(warn: "derive {shown} cap failed"),
    }
}

/// The absolute path of the drivers directory devmgr is handed, which
/// `SET_DRIVERS_DIR` also carries so devmgr names each driver by its install
/// path.
const DRIVERS_DIR_PATH: &str = "/services/drivers";

/// Hand devmgr a `LOOKUP | READ | READDIR`-attenuated `/services/drivers/`
/// subtree cap and its path via `SET_DRIVERS_DIR`, so devmgr can list the
/// directory, read the declaration of each driver binary in it, and spawn the
/// drivers that match its devices (the consoles and the per-arch RTC among
/// them), and, when the walk finds it, the same-rights cap of the platform
/// description tables' directory (`devmgr_labels::PLATFORM_TABLES_PATH`),
/// whose tables devmgr reads first. svcmgr walks its universal root for each
/// dir and mints a `DRIVERS_DIR_AUTHORITY` `SEND|GRANT` from the endowed
/// devmgr-registry source.
///
/// The walks go through vfsd and the call goes to devmgr, so the step reads
/// each one's liveness before it and after every call to it that fails, and
/// ends at a dead one (`svcmgr_defs::drivers_dir::run`,
/// `endowed_servers::death`): a call to a dead server fails with
/// `NoReceiver`, which does not itself say that the server died.
///
/// Best-effort: any other failure leaves devmgr without a drivers dir, so
/// none of its drivers starts (the consoles and the RTC among them); timed
/// sees `NO_DEVICE` on its first `QUERY_DEVICE` through the `rtc` class
/// and degrades to its no-RTC path; the rest of startup proceeds.
fn install_drivers_dir(
    caps: &service::SvcmgrCaps,
    pending: &[PendingRegistration],
    ipc_buf: *mut u64,
)
{
    if caps.devmgr_registry == 0
    {
        std::os::seraph::log!(warn: "SET_DRIVERS_DIR skipped: no devmgr registry source");
        return;
    }
    let root_cap = std::os::seraph::root_dir_cap();
    if root_cap == 0
    {
        std::os::seraph::log!(warn: "SET_DRIVERS_DIR skipped: no root_dir_cap");
        return;
    }
    let mut calls = DriversDirCalls {
        root_cap,
        devmgr_registry: caps.devmgr_registry,
        pending,
        ipc_buf,
    };
    match drivers_dir::run(
        &mut calls,
        DRIVERS_DIR_PATH,
        ipc::devmgr_labels::PLATFORM_TABLES_PATH,
    )
    {
        drivers_dir::Outcome::Installed { .. } => std::os::seraph::log!("SET_DRIVERS_DIR ok"),
        drivers_dir::Outcome::Rejected =>
        {
            std::os::seraph::log!(warn: "SET_DRIVERS_DIR rejected; no driver from the drivers dir");
        }
        drivers_dir::Outcome::Dead(server) =>
        {
            let server = match server
            {
                drivers_dir::Server::Vfsd => endowed_servers::VFSD,
                drivers_dir::Server::Devmgr => endowed_servers::DEVMGR,
            };
            std::os::seraph::log!(warn: "SET_DRIVERS_DIR skipped: {server} is dead");
        }
        drivers_dir::Outcome::NoDriversDir(e) =>
        {
            std::os::seraph::log!(warn: "SET_DRIVERS_DIR: walk {DRIVERS_DIR_PATH} failed: {e}");
        }
        drivers_dir::Outcome::NotSent(why) =>
        {
            std::os::seraph::log!(warn: "SET_DRIVERS_DIR {why}; no driver from the drivers dir");
        }
    }
}

/// The calls of the `SET_DRIVERS_DIR` step (`svcmgr_defs::drivers_dir`):
/// walks of `root_cap`, served by vfsd, the request on a
/// `DRIVERS_DIR_AUTHORITY` SEND derived from `devmgr_registry`, and the
/// servers' liveness read from their registrations in `pending`.
struct DriversDirCalls<'a>
{
    root_cap: u64,
    devmgr_registry: u64,
    pending: &'a [PendingRegistration],
    ipc_buf: *mut u64,
}

impl drivers_dir::Calls for DriversDirCalls<'_>
{
    type Cap = u64;
    type Error = std::io::Error;

    fn dead(&mut self, server: drivers_dir::Server) -> bool
    {
        let name = match server
        {
            drivers_dir::Server::Vfsd => endowed_servers::VFSD,
            drivers_dir::Server::Devmgr => endowed_servers::DEVMGR,
        };
        endowed_servers::death(self.pending, name, self.ipc_buf).is_some()
    }

    fn walk(&mut self, path: &str) -> std::io::Result<u64>
    {
        // Attenuated rights: only what devmgr needs to list the subtree, walk
        // into it, and read its files; the namespace server intersects per
        // hop.
        let rights = u64::from(
            namespace_protocol::rights::LOOKUP
                | namespace_protocol::rights::READ
                | namespace_protocol::rights::READDIR,
        );
        std::os::seraph::namespace_lookup_dir(self.root_cap, path, rights)
    }

    fn send(&mut self, drivers: u64, tables: Option<u64>) -> drivers_dir::Sent
    {
        // `RIGHTS_EP_SEND_GRANT` (not bare SEND): SET_DRIVERS_DIR transfers
        // the dir caps, and the IPC kernel requires the GRANT bit to move
        // caps.
        let Ok(bind_ep) = syscall::cap_derive_badge(
            self.devmgr_registry,
            syscall::RIGHTS_EP_SEND_GRANT,
            ipc::devmgr_labels::DRIVERS_DIR_AUTHORITY,
        )
        else
        {
            return drivers_dir::Sent::NotSent("DRIVERS_DIR_AUTHORITY derive failed");
        };
        let sent = send_drivers_dir(bind_ep, drivers, tables, self.ipc_buf);
        let _ = syscall::cap_delete(bind_ep);
        match sent
        {
            Ok(ipc::devmgr_errors::SUCCESS) => drivers_dir::Sent::Accepted,
            Ok(_) => drivers_dir::Sent::Rejected,
            // Not sent, or a transport error before the kernel committed the
            // transfer: the source slots still own the dir caps.
            Err(why) => drivers_dir::Sent::NotSent(why),
        }
    }

    fn release(&mut self, cap: u64)
    {
        let _ = syscall::cap_delete(cap);
    }
}

/// Send `SET_DRIVERS_DIR` on `bind_ep`: `drivers_dir`, its path, and
/// `tables_dir` second when the walk found it. Returns the reply's label;
/// `Err`, naming why, when the request is not sendable or the call fails
/// before the kernel moved the caps, which svcmgr then still holds. A
/// function of its own, so the request and its reply live in this frame
/// alone and [`install_drivers_dir`]'s holds neither.
fn send_drivers_dir(
    bind_ep: u64,
    drivers_dir: u64,
    tables_dir: Option<u64>,
    ipc_buf: *mut u64,
) -> Result<u64, &'static str>
{
    let builder = IpcMessage::builder(ipc::devmgr_labels::SET_DRIVERS_DIR)
        .word(0, u64::from(ipc::DEVMGR_LABELS_VERSION))
        .cap(drivers_dir);
    let builder = match tables_dir
    {
        Some(cap) => builder.cap(cap),
        None => builder,
    };
    let msg = ipc::with_name_block(
        builder,
        ipc::devmgr_labels::DRIVERS_DIR_PATH_WORD,
        DRIVERS_DIR_PATH.as_bytes(),
        ipc::devmgr_labels::DRIVERS_DIR_PATH_MAX,
    )
    .ok_or("path not sendable")?
    .build();
    // SAFETY: ipc_buf is the registered IPC buffer.
    unsafe { ipc::ipc_call(bind_ep, &msg, ipc_buf) }
        .map(|reply| reply.label)
        .map_err(|_| "ipc error")
}

/// `WaitSet` badge for svcmgr's service endpoint.
const WS_BADGE_SERVICE: u64 = 0;
/// `WaitSet` badge for svcmgr's death event queues, all of them.
const WS_BADGE_DEATHS: u64 = 1;
/// `WaitSet` badge for the Notification memmgr signals on a change of its
/// pressure level.
const WS_BADGE_PRESSURE: u64 = 2;

/// Monitored service table, pending-registration table, discovery
/// registry, and handover flag. Held across the event loop for the
/// lifetime of the process.
///
/// `pending` is populated by [`service::bootstrap_caps`] as it drains
/// init's handover endowment (one substrate `(name, thread_cap)` round
/// each). On `HANDOVER_COMPLETE`
/// [`definitions::reconcile::reconcile_and_launch`] pairs each entry with
/// a `.svc` recipe, binds death-notification, and populates `services`.
/// After reconciliation `pending` is effectively read-only — the
/// unconsumed entries persist as logged configuration errors but are not
/// re-used.
pub struct SvcmgrState
{
    /// Supervised services and their restart recipes, index-aligned via the
    /// death correlator; grows on the heap with no fixed count.
    pub table: ServiceTable,
    /// Substrate registrations parked from init's endowment.
    pub pending: Vec<PendingRegistration>,
    pub registry: registry::Registry,
    /// Set by the one `HANDOVER_COMPLETE` svcmgr honours; a repeat is
    /// rejected so reconciliation cannot launch a second instance of every
    /// defined service.
    pub handover_done: bool,
}

/// Main event loop: dispatches IPC registrations and death notifications.
fn event_loop(
    info: &StartupInfo,
    caps: &service::SvcmgrCaps,
    deaths: death_set::DeathSet,
    core_death_queue: u64,
    ipc_buf: *mut u64,
    state: &mut SvcmgrState,
) -> !
{
    let pressure_notification = pressure_member(&deaths);
    let restart_ctx = restart::RestartCtx {
        procmgr_ep: info.procmgr_endpoint,
        service_ep: caps.service_ep,
        bootstrap_ep: caps.bootstrap_ep,
        ipc_buf,
        deaths,
        master_log_source: caps.master_log_source,
        procmgr_death_auth_source: caps.procmgr_death_auth_source,
        entropy_source: caps.entropy_source,
        core_death_queue,
        pressure_notification,
        memory_waits: core::cell::Cell::new(MemoryWaits::new(pressure_notification != 0)),
    };

    // One guard covers both spin shapes: a failing wait_set_wait, and a
    // level-triggered wait set that keeps reporting ready while the recv in
    // dispatch_ipc keeps failing. Only a successful recv counts as progress.
    let mut guard = ipc::recv_guard::RecvGuard::new(recv_diag);
    loop
    {
        // The retry timer of the restarts that wait for memory
        // (`MemoryWaits::poll_timer`): its deadline is kept across every
        // wake, so no stream of requests holds a timed retry off, and with no
        // restart waiting below CRITICAL the wait has no timeout, so svcmgr
        // makes no idle wake-up.
        let waiting = state
            .table
            .services
            .iter()
            .any(|svc| svc.memory_wait.is_some());
        let mut waits = restart_ctx.memory_waits.get();
        let timer = waits.poll_timer(waiting, now_ns());
        restart_ctx.memory_waits.set(waits);
        let timeout_ms = match timer
        {
            Timer::Off => 0,
            Timer::Wait { ms } => ms,
            Timer::Due =>
            {
                retry_memory_waits(state, &restart_ctx, Wake::Timer);
                continue;
            }
        };
        // Read every time: a bind that grows the death queues may have
        // replaced the wait set.
        let badge = match syscall::wait_set_wait_timeout(restart_ctx.deaths.ws_cap(), timeout_ms)
        {
            Ok(badge) => badge,
            // The timeout expired: the next pass finds the deadline due.
            Err(e) if timeout_ms != 0 && e == SyscallError::WouldBlock as i64 => continue,
            Err(e) =>
            {
                guard.on_failure(e);
                continue;
            }
        };

        match badge
        {
            WS_BADGE_SERVICE => dispatch_ipc(caps.service_ep, state, &restart_ctx, &mut guard),
            WS_BADGE_DEATHS => dispatch_deaths(state, &restart_ctx),
            WS_BADGE_PRESSURE =>
            {
                // Take the bits before the read, so a change after the read
                // signals again. Only the level's bit retries (`Wake::signal`):
                // an opening of memmgr's draw room alone is the timer's.
                let bits =
                    syscall::notification_try_wait(restart_ctx.pressure_notification).unwrap_or(0);
                if let Some(wake) = Wake::signal(bits, std::os::seraph::MEMORY_PRESSURE_BIT)
                {
                    retry_memory_waits(state, &restart_ctx, wake);
                }
            }
            _ => std::os::seraph::log!(warn: "unexpected wait-set badge"),
        }
    }
}

/// Add the Notification memmgr signals on a change of its pressure level
/// (`std::os::seraph::memory_pressure_notification`) to the main wait set
/// under [`WS_BADGE_PRESSURE`], and return it; `0`, logged, when svcmgr has no
/// registration or the add fails. Without it no restart waits for memory
/// (`svcmgr_defs::memory_wait`).
fn pressure_member(deaths: &death_set::DeathSet) -> u64
{
    let Some(notification) = std::os::seraph::memory_pressure_notification()
    else
    {
        std::os::seraph::log!(warn: "no memory-pressure registration; no restart waits for memory");
        return 0;
    };
    if let Err(err) = deaths.add_member(notification, WS_BADGE_PRESSURE)
    {
        std::os::seraph::log!(
            warn: "memory-pressure Notification not waited on (err={err}); no restart waits \
             for memory"
        );
        return 0;
    }
    notification
}

/// Handle `wake` for the restarts that wait for memory: read memmgr's level,
/// record it (which arms or disarms the retry timer), and when it makes a
/// retry due (`MemoryWaits::wake`: the level reads below `CRITICAL`) retry
/// the restart of every waiting service (`restart::retry_memory_wait`),
/// routing each outcome as a death's: an unrecoverable one starts the
/// graceful shutdown once every retry is made.
fn retry_memory_waits(state: &mut SvcmgrState, ctx: &restart::RestartCtx, wake: Wake)
{
    let mut waits = ctx.memory_waits.get();
    waits.record_level(restart::pressure_level());
    ctx.memory_waits.set(waits);
    let Some(retry) = waits.wake(wake)
    else
    {
        return;
    };
    let mut unrecoverable = false;
    for idx in 0..state.table.services.len()
    {
        let SvcmgrState {
            table, registry, ..
        } = state;
        let (Some(entry), Ok(slot)) = (table.services.get_mut(idx), u32::try_from(idx))
        else
        {
            continue;
        };
        let recipe = table.recipes.get(idx).and_then(Option::as_ref);
        if restart::retry_memory_wait(entry, ctx, slot, recipe, registry, retry)
            == Some(restart::DeathOutcome::Unrecoverable)
        {
            unrecoverable = true;
        }
    }
    if unrecoverable
    {
        initiate_graceful_shutdown(state, ctx);
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
            std::os::seraph::log!(warn: "recv loop failing (err={err}); backing off");
        }
        ipc::recv_guard::RecvFailureStage::Fatal =>
        {
            std::os::seraph::log!(error: "recv loop wedged (err={err}); exiting");
        }
    }
}

/// Handle an IPC message on the service endpoint (registration, handover,
/// discovery-registry publish/query, or a stop-authority holder's stop or
/// list of stoppable services). `ctx` carries the procmgr /
/// bootstrap / death-queue state the `HANDOVER_COMPLETE` →
/// `reconcile_and_launch` path needs to spawn `.svc`-defined services.
fn dispatch_ipc(
    service_ep: u64,
    state: &mut SvcmgrState,
    ctx: &restart::RestartCtx,
    guard: &mut ipc::recv_guard::RecvGuard,
)
{
    let ipc_buf = ctx.ipc_buf;
    // SAFETY: ipc_buf is the registered IPC buffer.
    let msg = match unsafe { ipc::ipc_recv(service_ep, ipc_buf) }
    {
        Ok(msg) => msg,
        Err(e) =>
        {
            guard.on_failure(e);
            return;
        }
    };
    guard.on_success();

    let opcode = msg.label & 0xFFFF;
    match opcode
    {
        svcmgr_labels::HANDOVER_COMPLETE =>
        {
            if !definitions::handover_permitted(msg.badge, state.handover_done)
            {
                let reply = IpcMessage::new(ipc::svcmgr_errors::UNAUTHORIZED);
                // SAFETY: ipc_buf is the registered IPC buffer.
                let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
                return;
            }
            state.handover_done = true;
            // Reply BEFORE reconciliation: init's call returns and it
            // proceeds to teardown / thread_exit; svcmgr then runs the
            // (potentially slow) scan + launch path without holding
            // init blocked on the IPC reply path.
            let reply = IpcMessage::new(ipc::svcmgr_errors::SUCCESS);
            // SAFETY: ipc_buf is the registered IPC buffer.
            let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
            std::os::seraph::log!("handover complete; scanning /config/svcmgr/services/");
            let reconciled = match definitions::reconcile::reconcile_and_launch(
                &mut state.pending,
                &mut state.table,
                ctx,
                &mut state.registry,
            )
            {
                Ok(reconciled) => reconciled,
                Err(exit_reason) =>
                {
                    route_namespace_server_death(state, ctx, exit_reason);
                    return;
                }
            };
            std::os::seraph::log!(
                "monitoring {} service(s) after reconciliation",
                state.table.services.len()
            );
            // A critical service that died during its bootstrap rounds and
            // that svcmgr could not recover: its death was routed during the
            // reconciliation, and the shutdown waits for the actuator to be
            // recorded.
            if reconciled == definitions::reconcile::Reconciled::Unrecoverable
            {
                initiate_graceful_shutdown(state, ctx);
            }
            // A devmgr that died before its bind is recorded with the caps
            // init endowed; route its death now.
            resync_deaths(state, ctx);
        }
        svcmgr_labels::PUBLISH_ENDPOINT =>
        {
            let result = handle_publish_endpoint(&msg, &mut state.registry);
            let reply = IpcMessage::new(result);
            // SAFETY: ipc_buf is the registered IPC buffer.
            let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
        }
        svcmgr_labels::QUERY_ENDPOINT =>
        {
            handle_query_endpoint(&msg, &mut state.registry, ipc_buf);
        }
        ipc::stop_labels::STOP_CANDIDATE => stop::handle_stop_candidate(&msg, state, ctx),
        ipc::stop_labels::LIST_CANDIDATES => stop::handle_list_candidates(&msg, state, ctx),
        svcmgr_labels::LIST_STOP_SOURCES => stop::handle_list_stop_sources(&msg, state, ctx),
        _ =>
        {
            let reply = IpcMessage::new(ipc::svcmgr_errors::UNKNOWN_OPCODE);
            // SAFETY: ipc_buf is the registered IPC buffer.
            let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
        }
    }
}

/// Handle `PUBLISH_ENDPOINT`: add a `name → cap` mapping to the discovery
/// registry. The name is packed into data words 0.. per
/// [`read_name_from_msg`]; the cap arrives as the first received cap.
fn handle_publish_endpoint(msg: &IpcMessage, registry: &mut registry::Registry) -> u64
{
    // IPC delivers caps into svcmgr's CSpace before dispatch — every
    // reject path must release the delivered value cap, otherwise a
    // hostile or buggy publisher can leak a cap per call. The wire
    // only carries one cap; release every trailing slot the caller
    // may have delivered defensively.
    let recv_caps = msg.caps();
    let delivered_cap = recv_caps.first().copied().unwrap_or(0);
    for &extra in recv_caps.iter().skip(1)
    {
        if extra != 0
        {
            let _ = syscall::cap_delete(extra);
        }
    }
    let reject = |code: u64| -> u64 {
        if delivered_cap != 0
        {
            let _ = syscall::cap_delete(delivered_cap);
        }
        code
    };

    if msg.badge & svcmgr_labels::PUBLISH_AUTHORITY == 0
    {
        return reject(ipc::svcmgr_errors::UNAUTHORIZED);
    }
    let name_len = ((msg.label >> 16) & 0xFFFF) as usize;
    let name_buf = read_name_from_msg(msg, name_len);
    let Some(name) = name_buf.as_ref().and_then(|buf| buf.get(..name_len))
    else
    {
        return reject(ipc::svcmgr_errors::INVALID_NAME);
    };
    if delivered_cap == 0
    {
        return ipc::svcmgr_errors::INSUFFICIENT_CAPS;
    }
    if registry
        .publish(name, delivered_cap, Visibility::Public)
        .is_err()
    {
        return reject(ipc::svcmgr_errors::REGISTER_REJECTED);
    }
    ipc::svcmgr_errors::SUCCESS
}

/// Look up `name` in the discovery registry and derive a fresh
/// `RIGHTS_EP_SEND` cap on the published endpoint, `RIGHTS_EP_SEND_GRANT`
/// for a [`Visibility::SeedOnlyGrant`] entry, which only [`Resolver::Seed`]
/// resolves, so `QUERY_ENDPOINT` never yields `GRANT`. Evicts the entry on
/// `cap_derive` failure (publisher's endpoint is gone), so subsequent
/// queries see `UNKNOWN_NAME` instead of looping on
/// `INSUFFICIENT_CAPS`. Returns a `svcmgr_errors::*` code on miss or
/// derivation failure.
///
/// Shared by `QUERY_ENDPOINT` (IPC, [`Resolver::Query`]: seed-only names
/// answer `UNKNOWN_NAME`) and svcmgr's own resolution ([`Resolver::Seed`]:
/// each `.svc` `seed = ...` name on the launch and restart paths).
pub(crate) fn registry_lookup_derived(
    registry: &mut registry::Registry,
    name: &[u8],
    resolver: Resolver,
) -> Result<u64, u64>
{
    let Some(registry::Resolved { cap, grant }) = registry.lookup(name, resolver)
    else
    {
        return Err(ipc::svcmgr_errors::UNKNOWN_NAME);
    };
    let rights = if grant
    {
        syscall::RIGHTS_EP_SEND_GRANT
    }
    else
    {
        syscall::RIGHTS_EP_SEND
    };
    let Ok(derived) = syscall::cap_derive(cap, rights)
    else
    {
        let _ = registry.remove(name);
        let _ = syscall::cap_delete(cap);
        return Err(ipc::svcmgr_errors::INSUFFICIENT_CAPS);
    };
    Ok(derived)
}

/// Handle `QUERY_ENDPOINT`: look up a name in the discovery registry and
/// reply with a derived SEND cap if found.
fn handle_query_endpoint(msg: &IpcMessage, registry: &mut registry::Registry, ipc_buf: *mut u64)
{
    let name_len = ((msg.label >> 16) & 0xFFFF) as usize;
    let name_buf = read_name_from_msg(msg, name_len);
    let Some(name) = name_buf.as_ref().and_then(|buf| buf.get(..name_len))
    else
    {
        let reply = IpcMessage::new(ipc::svcmgr_errors::INVALID_NAME);
        // SAFETY: ipc_buf is the registered IPC buffer.
        let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
        return;
    };
    match registry_lookup_derived(registry, name, Resolver::Query)
    {
        Ok(derived) =>
        {
            let reply = IpcMessage::builder(ipc::svcmgr_errors::SUCCESS)
                .cap(derived)
                .build();
            // SAFETY: ipc_buf is the registered IPC buffer.
            let send_result = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
            if send_result.is_err()
            {
                // ipc_reply did not transfer the cap out of svcmgr's
                // CSpace; delete the freshly-derived slot to avoid
                // cumulative leakage over svcmgr's lifetime.
                let _ = syscall::cap_delete(derived);
            }
        }
        Err(code) =>
        {
            let reply = IpcMessage::new(code);
            // SAFETY: ipc_buf is the registered IPC buffer.
            let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
        }
    }
}

/// Drain all pending death notifications from every death queue. Each
/// death event carries the dying service's [`DeathTag`] (its table slot and
/// instance) as its correlator and the exit reason. The wait-set notifies once
/// per not-empty → empty transition, so a single wakeup may cover several
/// deaths; the try-recv loop runs until every queue empties.
///
/// A drain that takes [`death_queues::DEATHS_EQ_CAPACITY`] events or more
/// from one queue may have followed a full queue, whose dropped posts leave a
/// full queue's worth of events behind them for this drain or the next; the
/// drain that crosses the capacity then runs [`resync_deaths`].
fn dispatch_deaths(state: &mut SvcmgrState, ctx: &restart::RestartCtx)
{
    let full = ctx.deaths.drain(|death| {
        route_death(
            DeathTag::from_correlator(death.correlator),
            death.exit_reason,
            state,
            ctx,
        );
    });
    if full
    {
        std::os::seraph::log!(warn: "a death queue drained full; resyncing services");
        resync_deaths(state, ctx);
    }
}

/// Route one death to its `ServiceEntry` by its tag's slot and run the
/// restart decision, when the entry is active and the tag names its current
/// instance (`svcmgr_defs::death_tag::routes`). Each instance's observers
/// post under its own instance, so a post of an instance already routed (the
/// second of the two posts a main-thread fault or exit that is the address
/// space's first terminal end makes, or a post a resync overtook) is dropped.
///
/// The death of a core member (memmgr, procmgr), which only the resync finds
/// here since its observers are on the core-death queue, is not svcmgr's to
/// route: the shutdown actuator powers the system off on that queue's entry
/// (docs/supervision.md § Core Set and System Death). The entry is marked
/// inactive, so svcmgr calls the dead member no more, and nothing else runs:
/// no line, no restart decision, and no graceful shutdown, each of which
/// could wait on the dead member.
pub(crate) fn route_death(
    tag: DeathTag,
    exit_reason: u64,
    state: &mut SvcmgrState,
    ctx: &restart::RestartCtx,
)
{
    let idx = tag.index();
    let Some(svc) = state.table.services.get(idx)
    else
    {
        std::os::seraph::log!(warn: "death notification with unknown correlator");
        return;
    };
    if !svcmgr_defs::death_tag::routes(tag, svc.active, svc.instance)
    {
        return;
    }
    if svc.aspace_cap != 0
    {
        if let Some(svc) = state.table.services.get_mut(idx)
        {
            svc.active = false;
        }
        return;
    }

    // Split disjoint field borrows so handle_death gets the entry, its
    // restart recipe, and the registry (for seed re-resolution) at once.
    let SvcmgrState {
        table, registry, ..
    } = state;
    let Some(entry) = table.services.get_mut(idx)
    else
    {
        return;
    };
    let outcome = restart::handle_death(
        entry,
        exit_reason,
        ctx,
        tag,
        table.recipes.get(idx).and_then(Option::as_ref),
        registry,
    );
    if matches!(outcome, restart::DeathOutcome::Unrecoverable)
    {
        initiate_graceful_shutdown(state, ctx);
    }
}

/// Route the death of vfsd, the server of svcmgr's namespace root, found
/// before reconciliation recorded it (`endowed_servers::death`): system
/// death, as for any death of vfsd (docs/supervision.md § Core Set and System
/// Death). svcmgr cannot read a recipe through a dead vfsd, so it supervises
/// no service: it releases every substrate registration, whose services run
/// on unsupervised, and takes the path a `critical` service's unrecoverable
/// death takes, [`initiate_graceful_shutdown`]. No shutdown actuator can be
/// recorded, since the actuator's recipe and binary are read through vfsd, so
/// that path logs the degraded state.
fn route_namespace_server_death(
    state: &mut SvcmgrState,
    ctx: &restart::RestartCtx,
    exit_reason: u64,
)
{
    std::os::seraph::log!(
        error: "{} died before reconciliation (exit reason {exit_reason:#x}); \
         no service recipe can be read",
        endowed_servers::VFSD
    );
    definitions::reconcile::release_unsupervised(&mut state.pending, "vfsd is dead");
    initiate_graceful_shutdown(state, ctx);
}

/// The exit reason of `entry`'s current instance when the kernel shows it
/// dead, else `None`, read from the caps svcmgr holds on it: the reason
/// recorded for its main thread when that thread has exited; `EXIT_KILLED`
/// when the thread cap no longer resolves, since procmgr's teardown of the
/// process revokes it; and, for a service init created by raw syscalls
/// (memmgr, procmgr), whose address space svcmgr holds, the retained
/// end when one of its threads has ended it. A fault or exit of a
/// worker thread of a procmgr-created service shows here only once procmgr
/// has torn the service down.
pub(crate) fn observed_death(entry: &service::ServiceEntry) -> Option<u64>
{
    restart::caps_death(entry.thread_cap, entry.aspace_cap)
}

/// Route a death for every active service whose current instance is dead:
/// the recovery for death posts a full queue dropped, and, after
/// reconciliation, for a devmgr whose observers could not be bound because
/// it had already died. The resync is `svcmgr_defs::death_caps::resync` over
/// [`ResyncCtx`]: the deaths svcmgr's own caps show ([`observed_death`])
/// first, then, while memmgr and procmgr are active and alive
/// ([`substrate_alive`]), each service the caps show alive is asked of
/// procmgr (`restart::queried_death`), which reads the space's retained
/// fault of a worker thread. A restart binds the new instance's observers,
/// whose posts go to the queue this drain has emptied. A post for a service
/// routed here that does arrive later carries the dead instance, and
/// [`route_death`] drops it.
fn resync_deaths(state: &mut SvcmgrState, ctx: &restart::RestartCtx)
{
    svcmgr_defs::death_caps::resync(&mut ResyncCtx { state, ctx });
}

/// svcmgr's service table and the calls its death resync makes
/// (`svcmgr_defs::death_caps::ResyncTable`).
struct ResyncCtx<'a>
{
    state: &'a mut SvcmgrState,
    ctx: &'a restart::RestartCtx,
}

impl svcmgr_defs::death_caps::ResyncTable for ResyncCtx<'_>
{
    fn slots(&self) -> usize
    {
        self.state.table.services.len()
    }

    fn slot(&self, idx: usize) -> Option<svcmgr_defs::death_caps::ResyncSlot>
    {
        self.state
            .table
            .services
            .get(idx)
            .map(|svc| svcmgr_defs::death_caps::ResyncSlot {
                active: svc.active,
                instance: svc.instance,
                process_handle: svc.process_handle,
            })
    }

    fn caps_death(&self, idx: usize) -> Option<u64>
    {
        self.state.table.services.get(idx).and_then(observed_death)
    }

    fn route(&mut self, tag: DeathTag, exit_reason: u64)
    {
        route_death(tag, exit_reason, self.state, self.ctx);
    }

    fn substrate_alive(&self) -> bool
    {
        substrate_alive(self.state)
    }

    fn queried_death(&mut self, process_handle: u64) -> Option<u64>
    {
        restart::queried_death(process_handle, self.ctx.ipc_buf)
    }
}

/// Whether every service whose address space svcmgr holds (memmgr and
/// procmgr, which init created by raw syscalls) is active and shown alive by
/// the kernel, so a call into procmgr is answered.
pub(crate) fn substrate_alive(state: &SvcmgrState) -> bool
{
    state
        .table
        .services
        .iter()
        .filter(|svc| svc.aspace_cap != 0)
        .all(|svc| svc.active && observed_death(svc).is_none())
}

/// Ask the shutdown actuator to power the system off: derive a SEND stamped
/// with the badge of the `:auth` provided name its recipe declares
/// (`shutdown_actuator = <name>`) from the actuator's own service endpoint,
/// and call `pwrmgr_labels::SHUTDOWN`, the actuator's request label, through
/// it. The registry is not consulted: its entry for the name may be another
/// publisher's. Called from [`route_death`] when a `system_critical` service
/// dies unrecoverably.
///
/// An actuator whose entry is active but whose current instance the kernel
/// shows dead ([`observed_death`]) has a death not yet routed; that death is
/// routed first, so the actuator restarts under
/// its own policy or ends down. svcmgr then calls only a running actuator
/// (entry active, thread not exited). With no actuator recorded, or the
/// actuator down (its own permanent death included), svcmgr logs the
/// degraded state and returns: the actuator's endpoint outlives it, so a call
/// would block svcmgr with no receiver to answer. An actuator that dies
/// during the call still leaves svcmgr blocked. No fallback raw-shutdown path
/// exists.
fn initiate_graceful_shutdown(state: &mut SvcmgrState, ctx: &restart::RestartCtx)
{
    let Some(actuator) = state.table.shutdown_actuator
    else
    {
        std::os::seraph::log!(
            error: "graceful shutdown impossible: no shutdown actuator; system in degraded state"
        );
        return;
    };
    let Some(entry) = state.table.services.get(actuator.slot)
    else
    {
        std::os::seraph::log!(
            error: "graceful shutdown impossible: shutdown actuator is not in the service table; \
             system in degraded state"
        );
        return;
    };
    if entry.active
        && let Some(exit_reason) = observed_death(entry)
        && let Some(tag) = DeathTag::new(actuator.slot, entry.instance)
    {
        route_death(tag, exit_reason, state, ctx);
    }
    let Some(entry) = state.table.services.get(actuator.slot)
    else
    {
        return;
    };
    if !service_running(entry)
    {
        std::os::seraph::log!(
            error: "graceful shutdown impossible: shutdown actuator {} is down; \
             system in degraded state",
            entry.name_str()
        );
        return;
    }

    let Ok(shutdown_cap) = syscall::cap_derive_badge(
        entry.provided_endpoint,
        syscall::RIGHTS_EP_SEND,
        actuator.badge,
    )
    else
    {
        std::os::seraph::log!(
            error: "graceful shutdown: cannot derive a SEND on shutdown actuator {}",
            entry.name_str()
        );
        return;
    };

    let shutdown_msg = IpcMessage::new(ipc::pwrmgr_labels::SHUTDOWN);
    // SAFETY: `ctx.ipc_buf` is the registered IPC buffer.
    let _ = unsafe { ipc::ipc_call(shutdown_cap, &shutdown_msg, ctx.ipc_buf) };
    // On the success path the actuator powers off and this never returns.
    // On a failure path we surface the cap leak rather than ignore it.
    let _ = syscall::cap_delete(shutdown_cap);
    std::os::seraph::log!(error: "graceful shutdown: SHUTDOWN call returned (failure path)");
}

/// Whether `entry`'s service is running: the entry is active, holds an
/// instance, and the kernel does not show that instance dead
/// ([`observed_death`]).
pub(crate) fn service_running(entry: &service::ServiceEntry) -> bool
{
    entry.active && entry.thread_cap != 0 && observed_death(entry).is_none()
}
