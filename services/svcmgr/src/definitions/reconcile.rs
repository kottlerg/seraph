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
//!    registered thread cap, record the recipe's fixed fields on the
//!    matching `ServiceEntry` and its argv/env/cwd/seed, log-sink flag,
//!    and scheduling fields in the parallel `RestartRecipe` table.
//! 2. **Defined only** — call [`super::launch::launch`] to spawn the
//!    service (it binds death-notification before `START_PROCESS` when
//!    `restart != never`), then, for a supervised service, persist a
//!    `ServiceEntry`.
//! 3. **Registered without definition** — log a hard error and refuse
//!    to bind. svcmgr cannot restart what it has no recipe for; this
//!    is a configuration error.
//!
//! After reconciliation the supervision loop runs unchanged.

use std::fs;
use std::os::seraph::log;

use super::parse::parse;
use super::{Definition, NamespaceShape, RestartPolicy, SERVICES_DIR, launch};
use crate::restart::RestartCtx;
use crate::service::{POLICY_ALWAYS, POLICY_NEVER, POLICY_ON_FAILURE, RestartRecipe, ServiceEntry};

/// Entry in svcmgr's pending-registration table populated from init's
/// handover endowment (one substrate `SUBSTRATE` round each). Each entry
/// pairs a service name with the thread cap svcmgr will bind
/// death-notification on once the matching `.svc` definition is found.
pub struct PendingRegistration
{
    /// The service name the substrate round carried, at most
    /// `ipc::svcmgr_labels::NAME_MAX` bytes.
    pub name: String,
    pub thread_cap: u32,
    /// Cleared to `true` once a `.svc` definition has consumed this
    /// entry. Entries still `false` after the file scan get the
    /// `registered without definition` error path.
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

/// The service table and its index-aligned restart recipes, grown together.
///
/// A slot is never reused, so its index is a stable death correlator for
/// every instance the slot supervises; a launch that fails leaves its
/// reserved slot inactive. Both vectors grow on the heap with no fixed count.
pub struct ServiceTable
{
    pub services: Vec<ServiceEntry>,
    /// `None` for a slot with no recipe (a reserved slot whose launch failed).
    pub recipes: Vec<Option<RestartRecipe>>,
}

impl ServiceTable
{
    pub const fn new() -> Self
    {
        Self {
            services: Vec::new(),
            recipes: Vec::new(),
        }
    }

    /// Reserve the next slot, inactive, and return its index and the death
    /// correlator that names it. `None`, changing nothing, when the heap
    /// cannot grow either vector or the index does not fit the kernel's
    /// 32-bit correlator.
    fn reserve(&mut self) -> Option<(usize, u32)>
    {
        let idx = self.services.len();
        let correlator = u32::try_from(idx).ok()?;
        self.services.try_reserve(1).ok()?;
        self.recipes.try_reserve(1).ok()?;
        self.services.push(ServiceEntry::empty());
        self.recipes.push(None);
        Some((idx, correlator))
    }
}

/// Top-level entry called from `dispatch_ipc` on `HANDOVER_COMPLETE`.
///
/// Walks `/config/svcmgr/services/`, parses every `.svc` file, and routes each
/// definition through the right path. `pending` is consumed:
/// entries that match a definition are marked `consumed`; entries
/// left unconsumed after the scan are reported as a configuration
/// error.
#[allow(clippy::too_many_arguments)]
pub fn reconcile_and_launch(
    pending: &mut [PendingRegistration],
    table: &mut ServiceTable,
    deaths_eq: u32,
    ctx: &RestartCtx,
    registry: &mut registry::Registry,
)
{
    log!("svcmgr: scanning {SERVICES_DIR}");

    let read = match fs::read_dir(SERVICES_DIR)
    {
        Ok(r) => r,
        Err(e) =>
        {
            log!("svcmgr: cannot open {SERVICES_DIR}: {e}");
            // Still report pending-without-def errors so a missing
            // /config/svcmgr/services/ does not silently swallow them.
            report_orphans(pending);
            return;
        }
    };

    let mut entries: Vec<String> = Vec::new();
    for ent in read
    {
        let Ok(ent) = ent
        else
        {
            continue;
        };
        let path = ent.path();
        let Some(name) = path.file_name().and_then(|s| s.to_str()).map(str::to_owned)
        else
        {
            continue;
        };
        // `.svc` filenames are ASCII by convention; a case-insensitive
        // compare would obscure typos rather than tolerate them.
        #[allow(clippy::case_sensitive_file_extension_comparisons)]
        let is_svc = name.ends_with(".svc");
        if !is_svc
        {
            continue;
        }
        entries.push(name);
    }
    // Deterministic launch order — purely for grep-ability of the
    // boot log; svcmgr makes no policy claim about start sequencing
    // across /config/svcmgr/services/ (services that depend on each other use
    // discovery-registry lookups, not file-system ordering).
    entries.sort();

    // Parse every recipe first, then order providers (services that
    // publish their own endpoint via `provides = ...`) ahead of pure
    // consumers, so a provided name is in the discovery registry before
    // any consumer launched here resolves it. `sort_by_key` is stable, so
    // alphabetical order is preserved within each group.
    let mut defs: Vec<Definition> = Vec::with_capacity(entries.len());
    for filename in &entries
    {
        let service_name = filename.trim_end_matches(".svc");
        let mut path = String::from(SERVICES_DIR);
        path.push('/');
        path.push_str(filename);

        let contents = match fs::read_to_string(&path)
        {
            Ok(c) => c,
            Err(e) =>
            {
                log!("svcmgr: cannot read {path}: {e}");
                continue;
            }
        };
        match parse(service_name, &contents)
        {
            Ok(d) => defs.push(d),
            Err(e) => log!("svcmgr: parse {path}: {e}"),
        }
    }
    defs.sort_by_key(|d| d.provides.is_empty());

    for def in &defs
    {
        handle_definition(def, pending, table, deaths_eq, ctx, registry);
    }

    report_orphans(pending);
}

/// Route one parsed `Definition` to the bind-only or launch path.
fn handle_definition(
    def: &Definition,
    pending: &mut [PendingRegistration],
    table: &mut ServiceTable,
    deaths_eq: u32,
    ctx: &RestartCtx,
    registry: &mut registry::Registry,
)
{
    // Match against pending registrations parked from init's
    // handover endowment.
    if let Some(slot) = pending
        .iter_mut()
        .find(|p| !p.consumed && p.matches(&def.name))
    {
        slot.consumed = true;
        log!("svcmgr: bind only: {}", def.name);
        // init-created service: svcmgr has no process_handle (init
        // didn't share it). First death cannot DESTROY_PROCESS — see
        // `restart::restart_process`. Bind happens after the fact (the
        // thread has been running since its bootstrap spawn); `bind_only`
        // states why a death in that window is still delivered.
        bind_only(def, slot.thread_cap, table, deaths_eq);
        return;
    }

    // Not registered by init → svcmgr launches it.
    log!("svcmgr: launching: {}", def.name);

    if matches!(def.restart, RestartPolicy::Never)
    {
        // One-shot launch: no supervision binding, no `ServiceEntry`.
        // procmgr auto-reaps on exit.
        let Some(launched) = launch::launch(def, ctx, registry, None)
        else
        {
            log!("svcmgr: launch failed: {}", def.name);
            return;
        };
        log!("svcmgr: launched ephemeral: {}", def.name);
        let _ = syscall::cap_delete(launched.thread_cap);
        let _ = syscall::cap_delete(launched.process_handle);
        if launched.provided_endpoint != 0
        {
            let _ = syscall::cap_delete(launched.provided_endpoint);
        }
        return;
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
    // The correlator is deliberately the service-table index, not a
    // randomized value (#249): it is opaque to the kernel, delivered only to
    // svcmgr's own private death EQ (never in an IPC body, cap, or logged
    // value), and consumed directly as `services[idx]` on death dispatch.
    // With no untrusted observer there is nothing to enumerate, and a
    // (random-epoch, index) split would buy nothing.
    let Some((idx, correlator)) = table.reserve()
    else
    {
        log!(
            "svcmgr: no memory for a service-table slot; dropping {}",
            def.name
        );
        return;
    };

    let Some(launched) = launch::launch(def, ctx, registry, Some((deaths_eq, correlator)))
    else
    {
        log!("svcmgr: launch failed: {}", def.name);
        return;
    };

    table.services[idx] = build_entry(
        def,
        launched.thread_cap,
        launched.process_handle,
        launched.provided_endpoint,
    );
    table.recipes[idx] = Some(recipe_from(def));
}

/// Bind-only path: bind death-notification on a thread init already
/// started in Phase 1/2/3, record the `ServiceEntry`. `process_handle`
/// is `0` for these services (init never shared its handle); first
/// death cannot `DESTROY_PROCESS` — see `restart::restart_process`.
///
/// Race-free despite binding after the thread was started: the kernel
/// retains a thread's `exit_reason` past death and `thread_bind_notification`
/// serialises on the thread's `sched_lock`. A death in the window between
/// init's spawn and this bind is therefore delivered to `deaths_eq` when the
/// bind lands on the already-exited thread, not dropped (#106 Window 2).
fn bind_only(def: &Definition, thread_cap: u32, table: &mut ServiceTable, deaths_eq: u32)
{
    let Some((idx, correlator)) = table.reserve()
    else
    {
        log!(
            "svcmgr: no memory for a service-table slot; dropping {}",
            def.name
        );
        let _ = syscall::cap_delete(thread_cap);
        return;
    };
    if syscall::thread_bind_notification(thread_cap, deaths_eq, correlator).is_err()
    {
        log!("svcmgr: bind death-notification failed for {}", def.name);
        let _ = syscall::cap_delete(thread_cap);
        return;
    }
    table.services[idx] = build_entry(def, thread_cap, 0, 0);
    table.recipes[idx] = Some(recipe_from(def));
}

/// Clone the launch surfaces the fixed record cannot hold from a parsed
/// definition so the restart path can replay them: argv/env/cwd/seed
/// byte-for-byte, the log-sink flag, and the scheduling fields. The fixed
/// fields (name/binary/policy/namespace) live on the `ServiceEntry`.
fn recipe_from(def: &Definition) -> RestartRecipe
{
    RestartRecipe {
        argv: def.argv.clone(),
        env: def.env.clone(),
        cwd: def.cwd.clone(),
        seed: def.seed.clone(),
        log_sink: def.log_sink,
        priority: def.priority.unwrap_or(0),
        sched_max: def.sched_max.unwrap_or(0),
    }
}

/// Construct a `ServiceEntry` from the parsed definition.
/// Maps the `.svc` `restart`/`critical`/`namespace` values onto the
/// in-memory `ServiceEntry` representation `restart::handle_death`
/// reads.
fn build_entry(
    def: &Definition,
    thread_cap: u32,
    process_handle: u32,
    provided_endpoint: u32,
) -> ServiceEntry
{
    let mut entry = ServiceEntry::empty();

    entry.name.clone_from(&def.name);

    entry.thread_cap = thread_cap;
    entry.provided_endpoint = provided_endpoint;
    entry.process_handle = process_handle;

    entry.vfs_path.clone_from(&def.binary);

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
            entry.ns_subtree_path.clone_from(path);
            entry.ns_subtree_rights = *rights;
        }
    }

    entry
}

/// Log every entry in `pending` that was never matched by a `.svc`
/// definition and release its thread cap. Per the reconciliation
/// contract these are hard errors but non-fatal — svcmgr keeps
/// running for the services that did resolve cleanly. Releasing the
/// thread cap here avoids leaking a slot per orphaned registration
/// over svcmgr's lifetime.
fn report_orphans(pending: &[PendingRegistration])
{
    for slot in pending
    {
        if !slot.consumed
        {
            log!(
                "svcmgr: registered without definition: {} (refusing to bind)",
                slot.name_str()
            );
            if slot.thread_cap != 0
            {
                let _ = syscall::cap_delete(slot.thread_cap);
            }
        }
    }
}
