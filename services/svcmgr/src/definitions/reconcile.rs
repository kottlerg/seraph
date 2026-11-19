// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svcmgr/src/definitions/reconcile.rs

//! Post-handover reconciliation between the substrate registrations init
//! delivers in the handover endowment and the on-disk
//! `/config/svcmgr/services/` recipe set.
//!
//! Three outcomes per `.svc` file:
//!
//! 1. **Defined AND registered** — bind death-notification on the
//!    registered thread cap and on the service's address space, through the
//!    cap init endowed with it, record the recipe's fixed fields on the
//!    matching `ServiceEntry` and its argv/env/cwd/seed, log-sink flag,
//!    and scheduling fields in the parallel `RestartRecipe` table.
//! 2. **Defined only** — call [`super::launch::launch`] to spawn the
//!    service (it binds death-notification before `START_PROCESS` when
//!    `restart != never`), then, for a supervised service, persist a
//!    `ServiceEntry`. A supervised service that died during its bootstrap
//!    rounds has its death routed at once, by its restart policy
//!    (`restart::handle_death`), before the next recipe is launched.
//! 3. **Registered without definition** — log a hard error and refuse
//!    to bind. svcmgr cannot restart what it has no recipe for; this
//!    is a configuration error.
//!
//! After reconciliation the supervision loop runs unchanged.

use std::fs;
use std::os::seraph::fs::DirEntryExt;
use std::os::seraph::log;

use super::parse::parse;
use super::{Definition, NamespaceShape, RestartPolicy, SERVICES_DIR, launch, shutdown_actuator};
use svcmgr_defs::DeathTag;
use svcmgr_endowment::SubstrateObserver;

use crate::endowed_servers;
use crate::restart::{DeathOutcome, RestartCtx, bind_fault_observer, handle_death};
use crate::service::{
    Bootstrap, POLICY_ALWAYS, POLICY_NEVER, POLICY_ON_FAILURE, RestartRecipe, ServiceEntry,
    try_string,
};

/// Entry in svcmgr's pending-registration table populated from init's
/// handover endowment (one substrate `SUBSTRATE` round each). Each entry
/// pairs a service name with the thread cap svcmgr will bind
/// death-notification on once the matching `.svc` definition is found, and
/// the cap it binds the observer of the service's address space through.
pub struct PendingRegistration
{
    /// The service name the substrate round carried, at most
    /// `ipc::svcmgr_labels::NAME_MAX` bytes.
    pub name: String,
    pub thread_cap: u64,
    /// The cap svcmgr binds the death observer of the service's address
    /// space through: a `Control`-only address-space cap (memmgr, procmgr) or
    /// the procmgr process handle (devmgr, vfsd).
    pub observer: SubstrateObserver,
    /// Set to `true` once a `.svc` definition has consumed this entry, or
    /// when the scan has no memory for the parsed recipes and releases it
    /// unsupervised (`release_unsupervised`). Entries still `false` after
    /// the file scan get the `registered without definition` error path.
    pub consumed: bool,
}

impl PendingRegistration
{
    pub fn name_str(&self) -> &str
    {
        &self.name
    }

    pub fn matches(&self, name: &str) -> bool
    {
        self.name == name
    }
}

/// The service its recipe declares the system's shutdown actuator
/// (`shutdown_actuator = <name>`), recorded once its supervised entry, and
/// the service endpoint that entry holds, are in the table.
#[derive(Clone, Copy)]
pub struct ShutdownActuator
{
    /// The actuator's slot in [`ServiceTable::services`].
    pub slot: usize,
    /// The badge of the `:auth` `provides` entry `<name>` names, which svcmgr
    /// stamps on the SEND it derives from the actuator's own endpoint to call
    /// the shutdown request. Derived from the endpoint, not resolved by name
    /// from the registry, whose entry for the name may be another
    /// publisher's.
    pub badge: u64,
}

/// The service table and its index-aligned restart recipes, grown together,
/// and the shutdown actuator among them.
///
/// A slot is never reused, so its index names one service in every death
/// post for svcmgr's lifetime ([`DeathTag`]); a launch that fails leaves its
/// reserved slot inactive. Both vectors grow on the heap with no fixed count.
pub struct ServiceTable
{
    pub services: Vec<ServiceEntry>,
    /// `None` for a slot with no recipe (a reserved slot whose launch failed).
    pub recipes: Vec<Option<RestartRecipe>>,
    /// `None` when no recipe declares one, or the declaring service's
    /// supervised entry did not land; graceful shutdown is then impossible.
    pub shutdown_actuator: Option<ShutdownActuator>,
}

impl ServiceTable
{
    pub const fn new() -> Self
    {
        Self {
            services: Vec::new(),
            recipes: Vec::new(),
            shutdown_actuator: None,
        }
    }

    /// Reserve the next slot, inactive, and return its index and the death
    /// tag of its first instance. `None`, changing nothing, when the heap
    /// cannot grow either vector or the index does not fit a tag's slot.
    fn reserve(&mut self) -> Option<(usize, DeathTag)>
    {
        let idx = self.services.len();
        let tag = DeathTag::new(idx, 0)?;
        self.services.try_reserve(1).ok()?;
        self.recipes.try_reserve(1).ok()?;
        self.services.push(ServiceEntry::empty());
        self.recipes.push(None);
        Some((idx, tag))
    }

    /// Store `entry` and `recipe` in the slot `idx` that [`Self::reserve`]
    /// returned. `None` when `idx` is not a slot of the table.
    fn install(&mut self, idx: usize, entry: ServiceEntry, recipe: RestartRecipe) -> Option<()>
    {
        *self.services.get_mut(idx)? = entry;
        *self.recipes.get_mut(idx)? = Some(recipe);
        Some(())
    }
}

/// How a reconciliation left the system: whether the death of a service that
/// died during its bootstrap rounds, routed during it, was unrecoverable (a
/// `critical` service svcmgr cannot recover), so the caller starts the
/// graceful shutdown once every recipe is handled and the shutdown actuator
/// recorded.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Reconciled
{
    /// Every death routed during the reconciliation left the system running.
    Running,
    /// A death routed during the reconciliation was unrecoverable.
    Unrecoverable,
}

/// Whether `name` is a service recipe's file name: it ends in `.svc`, compared
/// case-sensitively.
#[expect(
    clippy::case_sensitive_file_extension_comparisons,
    reason = "`.svc` filenames are ASCII by convention; a case-insensitive compare would obscure \
              typos rather than tolerate them"
)]
fn is_recipe_name(name: &str) -> bool
{
    name.ends_with(".svc")
}

/// Top-level entry called from `dispatch_ipc` on `HANDOVER_COMPLETE`.
///
/// Walks `/config/svcmgr/services/`, parses every `.svc` file, and routes each
/// definition through the right path. `pending` is consumed:
/// entries that match a definition are marked `consumed`; entries
/// left unconsumed after the scan are reported as a configuration
/// error; when the scan has no memory for the parsed recipes they are
/// released to run unsupervised instead.
///
/// The scan reads through vfsd, so vfsd's liveness is read before it and
/// after every read that fails ([`endowed_servers::death`]): a later call
/// through a dead vfsd would wait for good. `Err` carries the exit reason of a
/// vfsd found dead; nothing is then recorded or launched, and `pending` is
/// left as it was, for the caller to route the death.
///
/// A supervised service that dies during its bootstrap rounds has its death
/// routed before the next recipe is launched; [`Reconciled`] reports whether
/// such a death was unrecoverable.
///
/// # Errors
/// vfsd's exit reason when it is dead before or during the scan.
pub fn reconcile_and_launch(
    pending: &mut [PendingRegistration],
    table: &mut ServiceTable,
    ctx: &RestartCtx,
    registry: &mut registry::Registry,
) -> Result<Reconciled, u64>
{
    let server_death = |pending: &[PendingRegistration]| -> Result<(), u64> {
        endowed_servers::death(pending, endowed_servers::VFSD, ctx.ipc_buf).map_or(Ok(()), Err)
    };
    server_death(pending)?;
    log!("svcmgr: scanning {SERVICES_DIR}");

    let read = match fs::read_dir(SERVICES_DIR)
    {
        Ok(r) => r,
        Err(e) =>
        {
            server_death(pending)?;
            log!(warn: "svcmgr: cannot open {SERVICES_DIR}: {e}");
            // Still report pending-without-def errors so a missing
            // /config/svcmgr/services/ does not silently swallow them.
            report_orphans(pending);
            return Ok(Reconciled::Running);
        }
    };

    // The copies and collections this scan and `parse` make are fallible, and
    // both sorts sort in place: a recipe whose name, path or fields the heap
    // cannot hold is dropped with a log line and the others still launch, and
    // with no room for the parsed list none launches. Each entry's name is
    // read borrowed (`DirEntryExt::file_name_ref`); the directory iteration
    // and `fs::read_to_string`, which returns `OutOfMemory`, allocate inside
    // std.
    let mut entries: Vec<String> = Vec::new();
    for ent in read
    {
        let Ok(ent) = ent
        else
        {
            server_death(pending)?;
            continue;
        };
        let Some(name) = ent.file_name_ref().to_str()
        else
        {
            continue;
        };
        if !is_recipe_name(name)
        {
            continue;
        }
        if entries.try_reserve(1).is_err()
        {
            log!(warn: "svcmgr: no memory to list {name}; dropped");
            continue;
        }
        let Some(name) = try_string(name)
        else
        {
            log!(warn: "svcmgr: no memory to list {name}; dropped");
            continue;
        };
        // Within the slot reserved above, so the push cannot grow.
        entries.push(name);
    }
    // A deterministic scan order, so the parse diagnostics repeat from boot
    // to boot; the launch order is `svcmgr_defs::launch_order`'s, below.
    // File names in one directory are unique, so the unstable sort, which
    // needs no scratch allocation, gives the same order a stable one would.
    entries.sort_unstable();

    // Parse every recipe first, then put them in launch order: providers
    // (services that publish their own endpoint via `provides = ...`) ahead
    // of pure consumers, and a provider after each provider whose name it
    // seeds, so a provided name is in the discovery registry before any
    // service launched here resolves it (`svcmgr_defs::launch_order`).
    let Some(mut defs) = parse_recipes(&entries, pending, ctx.ipc_buf)?
    else
    {
        log!(warn: "svcmgr: no memory to parse {} recipes", entries.len());
        release_unsupervised(pending, "no memory for the recipes");
        return Ok(Reconciled::Running);
    };
    svcmgr_defs::launch_order(&mut defs, |def| {
        log!(
            warn: "svcmgr: {} is in a seed cycle; launched before a provider it seeds from",
            def.name
        );
    });

    // One actuator, the first declaration in launch order; any later one is
    // a configuration error, launched as an ordinary service.
    let actuator = shutdown_actuator(&defs);
    let mut reconciled = Reconciled::Running;
    for (i, def) in defs.iter().enumerate()
    {
        let role = if Some(i) == actuator
        {
            launch::Role::ShutdownActuator
        }
        else
        {
            launch::Role::Ordinary
        };
        let slot = handle_definition(def, role, pending, table, ctx, registry, &mut reconciled);
        if let Some(provided) = &def.shutdown_actuator
        {
            if Some(i) == actuator
            {
                record_shutdown_actuator(table, &def.name, provided.badge, slot);
            }
            else
            {
                log!(
                    warn: "svcmgr: {} also declares shutdown_actuator; not recognised",
                    def.name
                );
            }
        }
    }

    report_orphans(pending);
    Ok(reconciled)
}

/// Read and parse the recipe file of each of `entries`, `.svc` file names in
/// [`SERVICES_DIR`]. A recipe that cannot be read or parsed, or whose path
/// the heap cannot hold, is dropped with a log line. `None` when the heap
/// cannot hold the list of parsed recipes. The files are read through vfsd,
/// whose liveness is read from its registration in `pending` after every read
/// that fails ([`endowed_servers::death`]).
///
/// # Errors
/// vfsd's exit reason when a read failed and vfsd is dead.
fn parse_recipes(
    entries: &[String],
    pending: &[PendingRegistration],
    ipc_buf: *mut u64,
) -> Result<Option<Vec<Definition>>, u64>
{
    let mut defs: Vec<Definition> = Vec::new();
    if defs.try_reserve_exact(entries.len()).is_err()
    {
        return Ok(None);
    }
    for filename in entries
    {
        let service_name = filename.strip_suffix(".svc").unwrap_or(filename);
        let Some(path) = recipe_path(filename)
        else
        {
            log!(warn: "svcmgr: no memory for {filename}'s path; dropped");
            continue;
        };

        let contents = match fs::read_to_string(&path)
        {
            Ok(c) => c,
            Err(e) =>
            {
                if let Some(exit_reason) =
                    endowed_servers::death(pending, endowed_servers::VFSD, ipc_buf)
                {
                    return Err(exit_reason);
                }
                log!(warn: "svcmgr: cannot read {path}: {e}");
                continue;
            }
        };
        match parse(service_name, &contents)
        {
            // Within the capacity reserved above, so the push cannot grow.
            Ok(d) => defs.push(d),
            Err(e) => log!(warn: "svcmgr: parse {path}: {e}"),
        }
    }
    Ok(Some(defs))
}

/// Record the shutdown actuator `service` at its supervised `slot`, with the
/// `badge` of the provided name it declares. A `slot` of `None` (its launch or
/// bind did not land), or an entry that holds no service endpoint (a
/// bind-only entry, for which svcmgr creates none), leaves no actuator
/// recorded, logged.
fn record_shutdown_actuator(
    table: &mut ServiceTable,
    service: &str,
    badge: u64,
    slot: Option<usize>,
)
{
    match slot
    {
        Some(slot)
            if table
                .services
                .get(slot)
                .is_some_and(|entry| entry.provided_endpoint != 0) =>
        {
            table.shutdown_actuator = Some(ShutdownActuator { slot, badge });
        }
        _ => log!(
            warn: "svcmgr: shutdown actuator {service} has no supervised endpoint; \
             graceful shutdown unavailable"
        ),
    }
}

/// Route one parsed `Definition` to the bind-only or launch path. Returns
/// the service-table slot of the supervised entry it recorded, or `None`
/// for a one-shot launch or one that did not land. `role` marks the
/// recognised shutdown actuator: a supervised launch of it, and each restart,
/// carries the receive-only derivation of svcmgr's own death queue
/// (`launch::launch`).
///
/// A supervised service that died during its bootstrap rounds
/// (`launch::Launched::died`) is recorded as launched, then its death is
/// routed as any death is, by its restart policy, budget and `critical` flag
/// ([`handle_death`]); an unrecoverable outcome is set in `reconciled`.
/// Routed here, not left to the death queues, so a log sink that died is
/// restarted before svcmgr's next lines and a restart's instance runs before
/// the services launched after it. The death posts of the dead instance carry
/// an instance already routed, and are dropped. A service that died so,
/// one-shot or supervised, is logged at once ([`log_boot_death`]).
fn handle_definition(
    def: &Definition,
    role: launch::Role,
    pending: &mut [PendingRegistration],
    table: &mut ServiceTable,
    ctx: &RestartCtx,
    registry: &mut registry::Registry,
    reconciled: &mut Reconciled,
) -> Option<usize>
{
    // Match against pending registrations parked from init's
    // handover endowment.
    if let Some(slot) = pending
        .iter_mut()
        .find(|p| !p.consumed && p.matches(&def.name))
    {
        slot.consumed = true;
        log!("svcmgr: bind only: {}", def.name);
        // init-created service: init endowed its thread cap and the cap
        // its address space is observed through. Bind happens after the fact
        // (the thread has been running since its bootstrap spawn);
        // `bind_only` states why a death in that window is still delivered.
        return bind_only(def, slot, table, ctx);
    }

    // Not registered by init → svcmgr launches it.
    log!("svcmgr: launching: {}", def.name);

    if matches!(def.restart, RestartPolicy::Never)
    {
        // One-shot launch: no supervision binding, no `ServiceEntry`.
        // procmgr auto-reaps on exit.
        let Some(launched) = launch::launch(def, ctx, registry, None, launch::Role::Ordinary)
        else
        {
            log!(warn: "svcmgr: launch failed: {}", def.name);
            return None;
        };
        match launched.died
        {
            None => log!("svcmgr: launched ephemeral: {}", def.name),
            Some(exit_reason) => log_boot_death(def, exit_reason),
        }
        let _ = syscall::cap_delete(launched.thread_cap);
        let _ = syscall::cap_delete(launched.process_handle);
        for cap in [launched.provided_endpoint, launched.node_handle]
        {
            if cap != 0
            {
                let _ = syscall::cap_delete(cap);
            }
        }
        return None;
    }

    // Supervised launch: reserve the service-table slot BEFORE
    // calling launch so the death-notification binding can land on a
    // committed correlator. Bind happens inside launch.rs between
    // CONFIGURE_NAMESPACE and START_PROCESS (thread still suspended)
    // so any immediate post-start death is captured cleanly.
    // On launch failure the slot is "burned" (stays at default,
    // active=false); dispatch_deaths' `!active` guard skips it. Slots are
    // never reused, so a burned slot costs one heap entry; healthy boots
    // never burn.
    //
    // The correlator is deliberately the service-table index and the
    // instance (`DeathTag`), not a randomized value (#249): it is opaque to
    // the kernel, delivered only to svcmgr's own private death queues (never
    // in an IPC body, cap, or logged value), and consumed directly as
    // `services[idx]` on death dispatch. With no untrusted observer there is
    // nothing to enumerate, and a random epoch would buy nothing.
    let Some((idx, tag)) = table.reserve()
    else
    {
        log!(
            warn: "svcmgr: no memory for a service-table slot; dropping {}",
            def.name
        );
        return None;
    };

    // Build the entry before launching, so a heap that cannot hold its name
    // and paths launches nothing rather than an instance svcmgr could not
    // supervise.
    let (Some(mut entry), Some(mut recipe)) = (build_entry(def), recipe_from(def))
    else
    {
        log!(warn: "svcmgr: no memory for {}'s entry; not launched", def.name);
        return None;
    };
    recipe.observes_svcmgr = role == launch::Role::ShutdownActuator;

    let Some(launched) = launch::launch(def, ctx, registry, Some(tag), role)
    else
    {
        log!(warn: "svcmgr: launch failed: {}", def.name);
        return None;
    };

    entry.thread_cap = launched.thread_cap;
    entry.process_handle = launched.process_handle;
    entry.provided_endpoint = launched.provided_endpoint;
    entry.node_handle = launched.node_handle;
    entry.launched = true;
    if launched.died.is_none()
    {
        entry.bootstrap = Bootstrap::Served;
    }
    table.install(idx, entry, recipe)?;
    if let Some(exit_reason) = launched.died
        && let Some(entry) = table.services.get_mut(idx)
    {
        log_boot_death(def, exit_reason);
        let recipe = table.recipes.get(idx).and_then(Option::as_ref);
        if handle_death(entry, exit_reason, ctx, tag, recipe, registry)
            == DeathOutcome::Unrecoverable
        {
            *reconciled = Reconciled::Unrecoverable;
        }
    }
    Some(idx)
}

/// Log the death of a service launched from `def` before its bootstrap
/// request. The line reaches the serial line through whichever logger serves
/// the log endpoint: a dead log sink's first launch leaves init-logd serving
/// it. `cargo xtask test-core-death` matches the line's `died during its
/// bootstrap`.
fn log_boot_death(def: &Definition, exit_reason: u64)
{
    log!(
        warn: "svcmgr: {} died during its bootstrap (exit reason {exit_reason:#x})",
        def.name
    );
}

/// Bind-only path: bind death-notification on a thread init already
/// started in Phase 1/2/3, and the observer of its address space through the
/// cap init endowed with it, and record the `ServiceEntry`. For memmgr and
/// procmgr, which init created by raw syscalls, that cap is a `Control`-only
/// address-space cap, bound directly and kept for the resync; for devmgr and
/// vfsd, which init created through procmgr, it is the process handle,
/// through which procmgr binds the observer
/// (`procmgr_labels::BIND_DEATH_OBSERVER`) and which the entry keeps.
///
/// Binding after the thread was started loses no death: the kernel retains a
/// thread's `exit_reason` past death and `thread_bind_notification`
/// serialises on the thread's `sched_lock`, and it retains the address
/// space's first terminal fault and replays it to a later address-space bind,
/// so a death in the window between init's spawn and this bind is delivered
/// to the death queues when the bind lands (#106 Window 2). A devmgr or vfsd
/// that died in that window and that procmgr has already torn down has had its
/// thread cap revoked, so both binds fail; the entry is recorded with that cap
/// all the same, and the resync that follows reconciliation reads the revoked
/// cap as `EXIT_KILLED` and routes the death. A vfsd found dead before or
/// during the recipe scan, which reads through vfsd, never reaches this path:
/// [`reconcile_and_launch`] ends there and returns its death. A thread bind that
/// fails on a live service (the death set out of memory) leaves the main
/// thread's exit to a later resync. A failed address-space bind on a live
/// service is logged and leaves the main thread's observer standing: init
/// cannot be asked again, and the service is still supervised for its main
/// thread's death.
///
/// Returns the slot of the recorded entry, or `None` when none is recorded;
/// the registration's caps are then released.
fn bind_only(
    def: &Definition,
    pending: &PendingRegistration,
    table: &mut ServiceTable,
    ctx: &RestartCtx,
) -> Option<usize>
{
    let release = || release_registration(pending);
    let Some((idx, tag)) = table.reserve()
    else
    {
        log!(
            warn: "svcmgr: no memory for a service-table slot; dropping {}",
            def.name
        );
        release();
        return None;
    };
    let (Some(mut entry), Some(recipe)) = (build_entry(def), recipe_from(def))
    else
    {
        log!(
            warn: "svcmgr: no memory for {}'s entry; running unsupervised",
            def.name
        );
        release();
        return None;
    };
    if ctx
        .deaths
        .bind_thread(pending.thread_cap, tag.correlator())
        .is_err()
    {
        // Recorded all the same: a revoked thread cap is a death the resync
        // after reconciliation routes.
        log!(warn: "svcmgr: bind death-notification failed for {}", def.name);
    }
    entry.thread_cap = pending.thread_cap;
    let bound = match pending.observer
    {
        SubstrateObserver::AddressSpace(aspace) =>
        {
            entry.aspace_cap = aspace;
            ctx.deaths.bind_aspace(aspace, tag.correlator()).is_ok()
        }
        SubstrateObserver::ProcessHandle(handle) =>
        {
            entry.process_handle = handle;
            bind_fault_observer(&ctx.deaths, handle, tag.correlator(), ctx.ipc_buf)
        }
        SubstrateObserver::None => false,
    };
    if !bound
    {
        log!(
            warn: "svcmgr: no address-space observer for {}; only its main thread's death is seen",
            def.name
        );
    }
    table.install(idx, entry, recipe)?;
    Some(idx)
}

/// Release every cap of a pending registration svcmgr does not supervise.
fn release_registration(pending: &PendingRegistration)
{
    let observer = match pending.observer
    {
        SubstrateObserver::AddressSpace(cap) | SubstrateObserver::ProcessHandle(cap) => cap,
        SubstrateObserver::None => 0,
    };
    for cap in [pending.thread_cap, observer]
    {
        if cap != 0
        {
            let _ = syscall::cap_delete(cap);
        }
    }
}

/// Clone the launch surfaces the restart path replays from a parsed
/// definition: argv/env/cwd/seed byte-for-byte, the log-sink,
/// debug-authority, `oom_stop`, stop-authority and reserve flags, the
/// `stop_source` class, and the
/// scheduling fields. The name, binary, policy and namespace live on the
/// `ServiceEntry` instead ([`build_entry`]). `None` when the heap cannot hold
/// the copies.
fn recipe_from(def: &Definition) -> Option<RestartRecipe>
{
    let cwd = match &def.cwd
    {
        Some(cwd) => Some(try_string(cwd)?),
        None => None,
    };
    Some(RestartRecipe {
        argv: try_strings(&def.argv)?,
        env: try_strings(&def.env)?,
        cwd,
        seed: try_strings(&def.seed)?,
        log_sink: def.log_sink,
        debug_authority: def.debug_authority,
        oom_stop: def.oom_stop,
        stop_authority: def.stop_authority,
        reserve: def.reserve,
        stop_source: def.stop_source,
        observes_svcmgr: false,
        priority: def.priority.unwrap_or(0),
        sched_max: def.sched_max.unwrap_or(0),
    })
}

/// Copy every string of `strings`, or `None` when the heap cannot hold them.
fn try_strings(strings: &[String]) -> Option<Vec<String>>
{
    let mut out = Vec::new();
    out.try_reserve_exact(strings.len()).ok()?;
    for s in strings
    {
        out.push(try_string(s)?);
    }
    Some(out)
}

/// `SERVICES_DIR/<filename>`, or `None` when the heap cannot hold it.
fn recipe_path(filename: &str) -> Option<String>
{
    let mut path = String::new();
    path.try_reserve_exact(
        SERVICES_DIR
            .len()
            .saturating_add(1)
            .saturating_add(filename.len()),
    )
    .ok()?;
    path.push_str(SERVICES_DIR);
    path.push('/');
    path.push_str(filename);
    Some(path)
}

/// Construct a `ServiceEntry` from the parsed definition, with no caps yet:
/// the caller fills the thread cap, process handle and provided endpoint.
/// Maps the `.svc` `restart`/`critical`/`namespace` values onto the
/// in-memory `ServiceEntry` representation `restart::handle_death`
/// reads. `None` when the heap cannot hold the entry's name or paths.
fn build_entry(def: &Definition) -> Option<ServiceEntry>
{
    let mut entry = ServiceEntry::empty();

    entry.name = try_string(&def.name)?;

    entry.vfs_path = try_string(&def.binary)?;

    entry.restart_policy = match def.restart
    {
        RestartPolicy::Never => POLICY_NEVER,
        RestartPolicy::Always => POLICY_ALWAYS,
        RestartPolicy::OnFailure => POLICY_ON_FAILURE,
    };
    entry.system_critical = def.system_critical;
    entry.active = true;

    match &def.namespace
    {
        NamespaceShape::None =>
        {
            entry.ns_policy_kind = ipc::svcmgr_labels::NS_POLICY_NONE;
        }
        NamespaceShape::Universal =>
        {
            entry.ns_policy_kind = ipc::svcmgr_labels::NS_POLICY_UNIVERSAL;
        }
        NamespaceShape::Subtree { path, rights } =>
        {
            entry.ns_policy_kind = ipc::svcmgr_labels::NS_POLICY_SUBTREE;
            entry.ns_subtree_path = try_string(path)?;
            entry.ns_subtree_rights = *rights;
        }
    }

    Some(entry)
}

/// Release the caps of every pending registration not yet consumed when
/// svcmgr can supervise none of them, for `reason`, which the log line for
/// each names: the scan has no memory to parse the recipes, or vfsd, through
/// which they are read, is dead. The init-spawned services run on,
/// unsupervised, and none is reported as a configuration error.
pub fn release_unsupervised(pending: &mut [PendingRegistration], reason: &str)
{
    for slot in pending.iter_mut().filter(|p| !p.consumed)
    {
        log!(
            warn: "svcmgr: {reason}; {} runs unsupervised",
            slot.name_str()
        );
        release_registration(slot);
        slot.consumed = true;
    }
}

/// Log every entry in `pending` that was never matched by a `.svc`
/// definition and release its caps. Per the reconciliation
/// contract these are hard errors but non-fatal — svcmgr keeps
/// running for the services that did resolve cleanly. Releasing the
/// caps here avoids leaking a slot per orphaned registration
/// over svcmgr's lifetime.
fn report_orphans(pending: &[PendingRegistration])
{
    for slot in pending
    {
        if !slot.consumed
        {
            log!(
                warn: "svcmgr: registered without definition: {} (refusing to bind)",
                slot.name_str()
            );
            release_registration(slot);
        }
    }
}
