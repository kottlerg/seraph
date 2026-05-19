// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// svcmgr/src/definitions/reconcile.rs

//! Post-handover reconciliation between init's `REGISTER_SERVICE`
//! announcements and the on-disk `/etc/svcmgr/services.d/` recipe
//! set.
//!
//! Three outcomes per `.svc` file:
//!
//! 1. **Defined AND registered** — bind death-notification on the
//!    registered thread cap and persist the parsed `Definition` on
//!    the matching `ServiceEntry`.
//! 2. **Defined only** — call [`super::launch::launch`] to spawn the
//!    service, then (if `restart != never`) bind death-notification
//!    and persist a `ServiceEntry`.
//! 3. **Registered without definition** — log a hard error and refuse
//!    to bind. svcmgr cannot restart what it has no recipe for; this
//!    is a configuration error.
//!
//! After reconciliation the supervision loop runs unchanged.

use std::fs;
use std::os::seraph::log;

use super::parse::parse;
use super::{Criticality, Definition, NamespaceShape, RestartPolicy, SERVICES_DIR, launch};
use crate::REGISTRY_CAPACITY;
use crate::restart::RestartCtx;
use crate::service::{
    CRITICALITY_FATAL, CRITICALITY_NORMAL, MAX_SERVICES, POLICY_ALWAYS, POLICY_ON_FAILURE,
    ServiceEntry,
};

/// Entry in init's pending-registration table populated by
/// `REGISTER_SERVICE`. Each entry pairs a service name with the
/// thread cap svcmgr will bind death-notification on once the
/// matching `.svc` definition is found.
pub struct PendingRegistration
{
    pub name: [u8; 32],
    pub name_len: u8,
    pub thread_cap: u32,
    /// Cleared to `true` once a `.svc` definition has consumed this
    /// entry. Entries still `false` after the file scan get the
    /// `registered without definition` error path.
    pub consumed: bool,
}

impl PendingRegistration
{
    pub const fn empty() -> Self
    {
        Self {
            name: [0; 32],
            name_len: 0,
            thread_cap: 0,
            consumed: false,
        }
    }

    pub fn name_str(&self) -> &str
    {
        core::str::from_utf8(&self.name[..self.name_len as usize]).unwrap_or("???")
    }

    pub fn matches(&self, name: &str) -> bool
    {
        self.name_str() == name
    }
}

/// Top-level entry called from `dispatch_ipc` on `HANDOVER_COMPLETE`.
///
/// Walks `services.d/`, parses every `.svc` file, and routes each
/// definition through the right path. `pending` is consumed:
/// entries that match a definition are marked `consumed`; entries
/// left unconsumed after the scan are reported as a configuration
/// error.
pub fn reconcile_and_launch(
    pending: &mut [PendingRegistration],
    pending_count: usize,
    services: &mut [ServiceEntry; MAX_SERVICES],
    service_count: &mut usize,
    deaths_eq: u32,
    ctx: &RestartCtx,
    registry: &mut registry::Registry<REGISTRY_CAPACITY>,
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
            // services.d/ does not silently swallow them.
            report_orphans(pending, pending_count);
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
    // across services.d/ (services that depend on each other use
    // discovery-registry lookups, not file-system ordering).
    entries.sort();

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
        let def = match parse(service_name, &contents)
        {
            Ok(d) => d,
            Err(e) =>
            {
                log!("svcmgr: parse {path}: {e}");
                continue;
            }
        };

        handle_definition(
            &def,
            pending,
            pending_count,
            services,
            service_count,
            deaths_eq,
            ctx,
            registry,
        );
    }

    report_orphans(pending, pending_count);
}

/// Route one parsed `Definition` to the bind-only or launch path.
#[allow(clippy::too_many_arguments)]
fn handle_definition(
    def: &Definition,
    pending: &mut [PendingRegistration],
    pending_count: usize,
    services: &mut [ServiceEntry; MAX_SERVICES],
    service_count: &mut usize,
    deaths_eq: u32,
    ctx: &RestartCtx,
    registry: &mut registry::Registry<REGISTRY_CAPACITY>,
)
{
    // Match against pending registrations from init's
    // REGISTER_SERVICE pass.
    if let Some(slot) = pending
        .iter_mut()
        .take(pending_count)
        .find(|p| !p.consumed && p.matches(&def.name))
    {
        slot.consumed = true;
        log!("svcmgr: bind only: {}", def.name);
        bind_and_record(def, slot.thread_cap, services, service_count, deaths_eq);
        return;
    }

    // Not registered by init → svcmgr launches it.
    log!("svcmgr: launching: {}", def.name);
    let Some(launched) = launch::launch(def, ctx, registry)
    else
    {
        log!("svcmgr: launch failed: {}", def.name);
        return;
    };

    if matches!(def.restart, RestartPolicy::Never)
    {
        log!("svcmgr: launched ephemeral: {}", def.name);
        // Drop the thread cap — no supervision binding to make.
        let _ = syscall::cap_delete(launched.thread_cap);
        // Keep the process handle around so a future death notification
        // would be observable if we ever bind one; for `never` we
        // intentionally don't.
        return;
    }

    bind_and_record(def, launched.thread_cap, services, service_count, deaths_eq);
}

/// Bind death-notification on `thread_cap` and record a `ServiceEntry`
/// with the parsed recipe so the supervision loop can restart the
/// service later.
fn bind_and_record(
    def: &Definition,
    thread_cap: u32,
    services: &mut [ServiceEntry; MAX_SERVICES],
    service_count: &mut usize,
    deaths_eq: u32,
)
{
    if *service_count >= MAX_SERVICES
    {
        log!("svcmgr: service table full; dropping {}", def.name);
        return;
    }
    let idx = *service_count;
    if syscall::thread_bind_notification(thread_cap, deaths_eq, idx as u32).is_err()
    {
        log!("svcmgr: bind death-notification failed for {}", def.name);
        return;
    }
    services[idx] = build_entry(def, thread_cap);
    *service_count += 1;
}

/// Construct a fixed-size `ServiceEntry` from the parsed definition.
/// Maps the `.svc` `restart`/`critical`/`namespace` values onto the
/// in-memory `ServiceEntry` representation `restart::handle_death`
/// reads.
fn build_entry(def: &Definition, thread_cap: u32) -> ServiceEntry
{
    let mut entry = ServiceEntry::empty();

    let name_bytes = def.name.as_bytes();
    let copy_len = name_bytes.len().min(entry.name.len());
    entry.name[..copy_len].copy_from_slice(&name_bytes[..copy_len]);
    entry.name_len = copy_len as u8;

    entry.thread_cap = thread_cap;
    entry.module_cap = 0;

    let bin_bytes = def.binary.as_bytes();
    let bin_copy = bin_bytes.len().min(entry.vfs_path.len());
    entry.vfs_path[..bin_copy].copy_from_slice(&bin_bytes[..bin_copy]);
    entry.vfs_path_len = bin_copy as u8;

    entry.restart_policy = match def.restart
    {
        // `Never` maps to a sentinel value `should_restart` does
        // not match; the existing `_ => false` arm rejects restart.
        RestartPolicy::Never => 0xFF,
        RestartPolicy::Always => POLICY_ALWAYS,
        RestartPolicy::OnFailure => POLICY_ON_FAILURE,
    };
    entry.criticality = match def.criticality
    {
        // `Low` maps to a sentinel `restart::handle_death` reads as
        // "informational"; restart's existing FATAL/NORMAL arms
        // continue to drive the other two cases.
        Criticality::Low => 0xFF,
        Criticality::Normal => CRITICALITY_NORMAL,
        Criticality::High => CRITICALITY_FATAL,
    };
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
            let pb = path.as_bytes();
            let plen = pb.len().min(entry.ns_subtree_path.len());
            entry.ns_subtree_path[..plen].copy_from_slice(&pb[..plen]);
            entry.ns_subtree_path_len = plen as u8;
            entry.ns_subtree_rights = *rights;
        }
    }

    entry
}

/// Log every entry in `pending` that was never matched by a `.svc`
/// definition. Per the reconciliation contract these are hard errors
/// but non-fatal — svcmgr keeps running for the services that did
/// resolve cleanly.
fn report_orphans(pending: &[PendingRegistration], pending_count: usize)
{
    for slot in pending.iter().take(pending_count)
    {
        if !slot.consumed
        {
            log!(
                "svcmgr: registered without definition: {} (refusing to bind)",
                slot.name_str()
            );
        }
    }
}
