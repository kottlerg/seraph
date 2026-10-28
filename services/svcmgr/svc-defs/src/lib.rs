// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svcmgr/svc-defs/src/lib.rs

//! Pure `.svc` service-definition types and parser for svcmgr.
//!
//! Holds the plain-data recipe record ([`Definition`] and its component
//! enums), the `key = value` parser ([`parse`]), the argv/env wire-blob
//! encoder ([`build_blob`]) the parser validates against procmgr's
//! `CREATE_FROM_FILE` limits, and two decisions svcmgr applies at runtime:
//! the rights of a recipe's `cwd` cap ([`cwd_rights`]) and the
//! `HANDOVER_COMPLETE` gate ([`handover_permitted`]). Nothing here touches a syscall, IPC, or
//! `std::os::seraph` surface, so the whole crate is host-reachable and
//! host-tested — the `.svc` files are external input and their parser
//! carries unit tests per
//! [coding-standards.md](../../../../docs/coding-standards.md#d-testing-invariants).
//! The impure launch/restart machinery that consumes a parsed [`Definition`]
//! stays in `svcmgr` (`definitions::launch` / `definitions::reconcile`).

pub mod parse;

use namespace_protocol::rights as ns_rights;

/// Rights svcmgr requests when it walks a recipe's `cwd`: what a child needs
/// for relative `std::fs` operations (`LOOKUP | READDIR | STAT | READ`),
/// intersected with the subtree's rights mask under `namespace = subtree:`
/// so the cwd cap never carries a right the namespace cap withholds.
/// `subtree_rights` is `None` for a universal namespace.
#[must_use]
pub fn cwd_rights(subtree_rights: Option<u32>) -> u32
{
    let wanted = ns_rights::LOOKUP | ns_rights::READDIR | ns_rights::STAT | ns_rights::READ;
    subtree_rights.map_or(wanted, |mask| wanted & mask)
}

/// Whether svcmgr honours a `HANDOVER_COMPLETE` from a caller whose cap
/// carries `badge`, given whether an earlier call was honoured
/// (`handover_done`): only the first call, and only through a SEND carrying
/// the [`HANDOVER_AUTHORITY`](ipc::svcmgr_labels::HANDOVER_AUTHORITY) verb
/// bit, which init alone mints.
#[must_use]
pub fn handover_permitted(badge: u64, handover_done: bool) -> bool
{
    badge & ipc::svcmgr_labels::HANDOVER_AUTHORITY != 0 && !handover_done
}

/// Build the NUL-separated, NUL-terminated wire blob procmgr's
/// stack-envelope writer expects from a list of tokens. Returns
/// `(blob, count)`. Empty input yields an empty blob with `count = 0`,
/// matching the "no argv / no env" wire shape. [`parse::parse`] bounds a
/// recipe's blobs so the count fits the label's 8-bit field and guarantees
/// every token is NUL-free, which this encoder relies on: the blob's NUL
/// boundaries are then exactly the `count` token boundaries the label
/// declares.
#[must_use]
pub fn build_blob(tokens: &[String]) -> (Vec<u8>, u32)
{
    if tokens.is_empty()
    {
        return (Vec::new(), 0);
    }
    let mut blob: Vec<u8> = Vec::with_capacity(tokens.iter().map(|t| t.len() + 1).sum());
    for tok in tokens
    {
        blob.extend_from_slice(tok.as_bytes());
        blob.push(0);
    }
    // cast_possible_truncation: the parser bounds a recipe's token count to
    // `u8::MAX`, so the count fits.
    #[allow(clippy::cast_possible_truncation)]
    let count = tokens.len() as u32;
    (blob, count)
}

/// Restart-policy values parsed from the `restart = ...` line.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RestartPolicy
{
    /// Service is one-shot; never restart, even on fault. Used for
    /// integration-test fixtures whose exit is the success notification
    /// (e.g. `svctest`).
    Never,
    /// Restart only on a fault exit (`exit_reason >= EXIT_FAULT_BASE`).
    /// Clean exits are treated as intentional.
    OnFailure,
    /// Restart on every exit, clean or faulty. Default for daemons
    /// that should never terminate during normal operation.
    Always,
}

/// Namespace shape parsed from the `namespace = ...` line.
///
/// One of:
///   * `namespace = none` → no namespace cap at all.
///   * `namespace = universal` → `cap_copy` of svcmgr's universal
///     `system_root_cap`.
///   * `namespace = subtree:<path>:<rights>` → walk `path` from
///     svcmgr's root requesting `<rights>` per hop.
#[derive(Clone, Debug)]
pub enum NamespaceShape
{
    None,
    Universal,
    Subtree
    {
        path: String,
        rights: u32,
    },
}

/// One parsed `.svc` definition.
///
/// Storage uses heap-allocated `String` / `Vec` because svcmgr is
/// std-built and parsing happens once at handover. Reconciliation
/// either consumes the definition into a fixed-size `ServiceEntry`
/// (for supervision) or hands it straight to svcmgr's launch path for
/// one-shot spawn.
pub struct Definition
{
    pub name: String,
    pub binary: String,
    /// Each element is one argv token. The wire blob is built at
    /// launch time as NUL-separated, NUL-terminated bytes.
    pub argv: Vec<String>,
    /// Each element is one `KEY=VAL` entry. The wire blob is built at
    /// launch time as NUL-separated, NUL-terminated bytes.
    pub env: Vec<String>,
    pub restart: RestartPolicy,
    /// Whether the system is viable without this service once it is
    /// permanently down (restart not attempted, or budget exhausted).
    /// `true` (`critical = yes`) → svcmgr issues `pwrmgr_labels::SHUTDOWN`
    /// on unrecoverable death; `false` (`critical = no`) → the system
    /// continues degraded. Orthogonal to [`Definition::restart`], which
    /// alone decides whether/when to respawn.
    pub system_critical: bool,
    pub namespace: NamespaceShape,
    /// Optional cwd path, walked from svcmgr's universal root on launch and
    /// restart. It must lie inside the namespace: under `namespace =
    /// subtree:` the parser rejects a path outside the subtree, under
    /// `namespace = universal` it rejects the root itself (the cwd walk
    /// cannot narrow it), and under `namespace = none` it rejects any
    /// `cwd`. See
    /// `services/svcmgr/docs/service-definitions.md` § cwd.
    pub cwd: Option<String>,
    /// Published-registry names svcmgr resolves at launch time and
    /// injects positionally into the child's bootstrap round.
    pub seed: Vec<String>,
    /// Registry names this service's own service endpoint is published
    /// under. When non-empty, svcmgr's launch path creates a service
    /// endpoint, serves its RECV half as bootstrap cap[0] (ahead of the
    /// `seed` caps), and publishes one SEND half per entry — each stamped
    /// with that entry's [`ProvidedName::badge`] — into the discovery
    /// registry. The endpoint persists across restarts (svcmgr holds the
    /// source), so cached client caps survive a crash-restart cycle and no
    /// re-publish is needed. Empty for pure-consumer services that only
    /// receive `seed` caps. A provider also launches ahead of pure
    /// consumers during reconciliation so its names resolve before any
    /// consumer queries them.
    pub provides: Vec<ProvidedName>,
    /// `log_sink = yes` marks the service as the system log sink (real-logd).
    /// svcmgr mints its bootstrap round — master-log RECV, the first-launch
    /// `HANDOVER_PULL` SEND, a `DEATH_EQ_AUTHORITY` `SEND|GRANT`, and a
    /// `devmgr.registry` query cap — from the reserved log-sink sources and
    /// the `devmgr.registry` source it holds, rather than from `seed` /
    /// `provides` (which the parser rejects in combination). Exactly one
    /// recipe carries this; supervision/restart otherwise follow the normal
    /// `restart`/`critical` fields.
    pub log_sink: bool,
    /// Priority level the service's initial thread is created at
    /// (`priority = ...`, range `1..=30`). `None` = unspecified: procmgr
    /// applies its default (`sched_policy::DEFAULT_SPAWN_PRIORITY` clamped
    /// to the band). Must not exceed svcmgr's own band ceiling or procmgr
    /// rejects the spawn.
    pub priority: Option<u8>,
    /// Upper bound of the baseline `SchedControl` band delegated to the
    /// service (`sched_max = ...`, range `1..=30`, must be ≥ `priority`
    /// when both are present). `None` = unspecified: the service inherits
    /// a copy of svcmgr's own band.
    pub sched_max: Option<u8>,
}

/// One published name in a service's `provides = ...` list, with the
/// badge svcmgr stamps on the SEND it publishes.
///
/// The badge rides through publish → registry → lookup unchanged
/// (`cap_derive` inherits a source cap's badge), so a consumer that
/// resolves the name receives a SEND already carrying it. The verb the
/// server gates on is `badge & (1 << 63)`, the first verb bit; a name
/// carrying it is seed-only (`QUERY_ENDPOINT` refuses it).
#[derive(Clone, Debug)]
pub struct ProvidedName
{
    pub name: String,
    /// `1 << 63` for an `:auth` entry (carries the verb-authority bit),
    /// `1` for a `:deny` entry (present but gate-failing), `0` for a bare
    /// entry (unbadged — published via `cap_derive`, not
    /// `cap_derive_badge`).
    pub badge: u64,
}

/// Directory svcmgr scans for service definitions. Absolute path
/// against svcmgr's `system_root_cap`. That cap is universal, so
/// absolute lookups via `std::fs` resolve normally.
pub const SERVICES_DIR: &str = "/config/svcmgr/services";

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn populated_tokens_pack_nul_separated_and_terminated_with_their_count()
    {
        let tokens = [String::from("a"), String::from("bc")];
        assert_eq!(build_blob(&tokens), (b"a\0bc\0".to_vec(), 2));
    }

    #[test]
    fn no_tokens_pack_to_the_empty_blob_and_zero_count()
    {
        assert_eq!(build_blob(&[]), (Vec::new(), 0));
    }

    #[test]
    fn cwd_rights_never_exceed_the_subtree_mask()
    {
        let wanted = ns_rights::LOOKUP | ns_rights::READDIR | ns_rights::STAT | ns_rights::READ;
        assert_eq!(cwd_rights(None), wanted);
        assert_eq!(cwd_rights(Some(ns_rights::LOOKUP)), ns_rights::LOOKUP);
        assert_eq!(
            cwd_rights(Some(ns_rights::LOOKUP | ns_rights::WRITE)),
            ns_rights::LOOKUP
        );
    }

    #[test]
    fn handover_needs_the_authority_bit()
    {
        let auth = ipc::svcmgr_labels::HANDOVER_AUTHORITY;
        assert!(handover_permitted(auth, false));
        assert!(handover_permitted(auth | 0x10, false));
        assert!(!handover_permitted(0, false));
        assert!(!handover_permitted(
            ipc::svcmgr_labels::PUBLISH_AUTHORITY,
            false
        ));
    }

    #[test]
    fn handover_is_honoured_only_once()
    {
        assert!(!handover_permitted(
            ipc::svcmgr_labels::HANDOVER_AUTHORITY,
            true
        ));
    }
}
