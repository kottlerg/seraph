// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svcmgr/svc-defs/src/lib.rs

//! Pure `.svc` service-definition types and parser for svcmgr.
//!
//! Holds the plain-data recipe record ([`Definition`] and its component
//! enums), the `key = value` parser ([`parse`]) and that of the device
//! class files svcmgr configures devmgr's classes from ([`class`]), the
//! argv/env wire-blob encoder ([`build_blob`]) whose output the parser
//! bounds by the child's argv/env region, and the policies svcmgr applies at
//! runtime: the rights of a recipe's `cwd` cap ([`cwd_rights`]), the
//! `HANDOVER_COMPLETE` gate ([`handover_permitted`]), whether a restarted log
//! sink is owed the handover SEND ([`log_sink_handover_owed`]), the
//! death-observer correlator and the rule that routes a death post by it
//! ([`death_tag`]), the reading of a service's death from the caps svcmgr holds
//! on it ([`death_caps`]), the eligibility rule of a stop ([`stop`]), the order of
//! the `SET_DRIVERS_DIR` step and its liveness reads ([`drivers_dir`]), what
//! follows a restart whose create failed and when one that waits for memory is
//! retried ([`memory_wait`]), and the create flags a recipe asks procmgr for
//! ([`create_flags`]). Nothing here touches a syscall, IPC, or `std::os::seraph` surface, so the whole crate
//! is host-reachable and host-tested — the `.svc` and class files are
//! external input and their parsers carry unit tests per
//! [coding-standards.md](../../../../docs/coding-standards.md#d-testing-invariants).
//! The impure launch/restart machinery that consumes a parsed [`Definition`]
//! stays in `svcmgr` (`definitions::launch` / `definitions::reconcile`).

pub mod class;
pub mod death_caps;
pub mod death_tag;
pub mod drivers_dir;
pub mod memory_wait;
pub mod parse;
pub mod stop;

pub use death_tag::DeathTag;

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
#[expect(
    clippy::fn_params_excessive_bools,
    reason = "`handover_done` is whether an earlier handover was honoured, which the check \
              compares"
)]
pub fn handover_permitted(badge: u64, handover_done: bool) -> bool
{
    badge & ipc::svcmgr_labels::HANDOVER_AUTHORITY != 0 && !handover_done
}

/// Whether a restarted log sink is minted the `HANDOVER_PULL` SEND, from
/// procmgr's reply to `QUERY_INIT_REAP`: its label and data word 0, or
/// `None` when the call failed. Only a `SUCCESS` reply that says the reap
/// has run answers no: procmgr reaps init once init-logd has exited, so
/// init-logd no longer receives on the master log endpoint and there is no
/// handover source. Any other answer leaves init-logd possibly serving, and
/// the new instance must pull from it and release it, or init-logd would go
/// on writing the UART beside it
/// (`services/logd/docs/handover-protocol.md`). Erring that way
/// costs at most the bound of logd's handover calls, which end on an
/// endpoint with no receiver.
#[must_use]
pub fn log_sink_handover_owed(reap_reply: Option<(u64, u64)>) -> bool
{
    !matches!(
        reap_reply,
        Some((label, reaped)) if label & 0xFFFF == ipc::procmgr_errors::SUCCESS && reaped == 1
    )
}

/// The procmgr create flags svcmgr adds to a service's `CREATE_FROM_FILE`
/// label, on its launch and on every restart:
/// [`CREATE_RESERVE`](ipc::procmgr_labels::CREATE_RESERVE) for a recipe that
/// sets `reserve = yes` ([`Definition::reserve`]), so the service's budget
/// node is in the system reserve, which procmgr grants svcmgr since svcmgr's
/// own node is a reserve node;
/// [`CREATE_NODE_HANDLE`](ipc::procmgr_labels::CREATE_NODE_HANDLE) for one
/// that sets `oom_stop = yes` ([`Definition::oom_stop`]), whose usage svcmgr
/// reads through the handle for `stop_labels::LIST_CANDIDATES`; and
/// [`CREATE_CONTAIN`](ipc::procmgr_labels::CREATE_CONTAIN) for one that sets
/// `stop_source` ([`Definition::stop_source`]), so no process the source
/// started outlives it: a candidate it lists ends with it, and a restarted
/// source starts with none.
#[must_use]
#[expect(
    clippy::fn_params_excessive_bools,
    reason = "each argument is the recipe key that asks for one flag"
)]
pub const fn create_flags(reserve: bool, oom_stop: bool, stop_source: bool) -> u64
{
    let mut flags = 0;
    if reserve
    {
        flags |= ipc::procmgr_labels::CREATE_RESERVE;
    }
    if oom_stop
    {
        flags |= ipc::procmgr_labels::CREATE_NODE_HANDLE;
    }
    if stop_source
    {
        flags |= ipc::procmgr_labels::CREATE_CONTAIN;
    }
    flags
}

/// The byte length of the blob [`build_blob`] packs from `tokens`: each token
/// and its NUL terminator.
#[must_use]
pub fn blob_len(tokens: &[String]) -> usize
{
    tokens.iter().map(|t| t.len().saturating_add(1)).sum()
}

/// Build the NUL-separated, NUL-terminated wire blob procmgr's create
/// requests carry (`procmgr_labels::CREATE_ARGV_ENV`) from a list of tokens.
/// Returns `(blob, count)`. Empty input yields an empty blob with
/// `count = 0`, matching the "no argv / no env" wire shape. [`parse::parse`]
/// guarantees every token is NUL-free, which this encoder relies on: the
/// blob's NUL boundaries are then exactly the `count` token boundaries the
/// request's header declares, which procmgr checks.
#[must_use]
pub fn build_blob(tokens: &[String]) -> (Vec<u8>, u64)
{
    let mut blob: Vec<u8> = Vec::with_capacity(blob_len(tokens));
    for tok in tokens
    {
        blob.extend_from_slice(tok.as_bytes());
        blob.push(0);
    }
    (blob, tokens.len() as u64)
}

/// The index in `defs` of the system's shutdown actuator: the first
/// definition, in `defs`' order, that declares
/// [`Definition::shutdown_actuator`]. `None` when none declares it. svcmgr
/// passes its scan in launch order, and reports every later declaration as
/// a configuration error and recognises only this one.
#[must_use]
pub fn shutdown_actuator(defs: &[Definition]) -> Option<usize>
{
    defs.iter().position(|d| d.shutdown_actuator.is_some())
}

/// Keep [`Definition::entropy_authority`] on the first definition, in
/// `defs`' order, that sets it, and clear it on every later one, calling
/// `on_extra` with each definition it clears before clearing it. svcmgr
/// passes its scan in launch order, so one service holds the entropy
/// authority, and every later declaration is a configuration error, launched
/// without the cap. Returns the index of the holder, `None` when no
/// definition sets the key.
pub fn keep_one_entropy_holder(
    defs: &mut [Definition],
    mut on_extra: impl FnMut(&Definition),
) -> Option<usize>
{
    let holder = defs.iter().position(|d| d.entropy_authority)?;
    for def in defs.iter_mut().skip(holder.saturating_add(1))
    {
        if def.entropy_authority
        {
            on_extra(def);
            def.entropy_authority = false;
        }
    }
    Some(holder)
}

/// Put `defs` in launch order: providers (a non-empty
/// [`Definition::provides`]) ahead of pure consumers, so a provided name is
/// published before any consumer launched in the same scan resolves it; each
/// group in service-name order; and, among the providers, a provider whose
/// [`Definition::seed`] names a name another provider provides after that
/// provider. svcmgr publishes a provided name only once its provider has
/// launched, so this is what lets one provider seed another's name.
///
/// The order is a stable topological order: each place takes the first
/// provider, in name order, that seeds no name of a provider not yet placed
/// (its own names aside). When none can (a seed cycle), the first in name
/// order takes the place, `on_cycle` is called with it, and its seeds from
/// the providers still unplaced resolve to nothing at its launch. A seed
/// naming a name no recipe provides orders nothing.
///
/// The order says only which launch is attempted first. A provider launches
/// whether or not the launch of a provider it seeds from succeeded; a seed of
/// a provider whose launch failed is unresolved, as any unresolved seed is.
/// A service init already runs (bind only) is not launched, so its place
/// does nothing. A restarted service's seeds are resolved again at its
/// restart, from what the registry then holds.
pub fn launch_order(defs: &mut [Definition], mut on_cycle: impl FnMut(&Definition))
{
    // Service names are unique (one `.svc` suffix stripped from unique file
    // names), so the allocation-free unstable sort gives the order a stable
    // one would.
    defs.sort_unstable_by(|a, b| {
        (a.provides.is_empty(), &a.name).cmp(&(b.provides.is_empty(), &b.name))
    });
    let providers = defs.iter().take_while(|d| !d.provides.is_empty()).count();
    let mut rest: &mut [Definition] = defs.get_mut(..providers).unwrap_or_default();
    while !rest.is_empty()
    {
        // The first provider, in name order, seeding no name of another
        // unplaced provider, takes the place at the head of `rest`.
        let ready = (0..rest.len()).find(|&j| {
            rest.get(j).is_some_and(|c| {
                !rest
                    .iter()
                    .enumerate()
                    .any(|(k, p)| k != j && seeds_from(c, p))
            })
        });
        match ready.and_then(|j| rest.get_mut(..=j))
        {
            Some(head) => head.rotate_right(1),
            None =>
            {
                if let Some(first) = rest.first()
                {
                    on_cycle(first);
                }
            }
        }
        let Some((_, tail)) = core::mem::take(&mut rest).split_first_mut()
        else
        {
            break;
        };
        rest = tail;
    }
}

/// Whether `consumer` seeds a name `provider` provides.
fn seeds_from(consumer: &Definition, provider: &Definition) -> bool
{
    consumer
        .seed
        .iter()
        .any(|s| provider.provides.iter().any(|p| p.name == *s))
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
#[expect(
    clippy::struct_excessive_bools,
    reason = "each bool is one independent `yes | no` recipe key: `critical`, `log_sink`, \
              `debug_authority`, `oom_stop`, `stop_authority`, `entropy_authority` and \
              `reserve`"
)]
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
    /// permanently down (restart not attempted, budget exhausted, or
    /// restart failed).
    /// `true` (`critical = yes`) → svcmgr asks the shutdown actuator
    /// ([`Definition::shutdown_actuator`]) to power the system off on
    /// unrecoverable death; `false` (`critical = no`) → the system
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
    /// injects positionally into the child's bootstrap rounds.
    pub seed: Vec<String>,
    /// Registry names this service's own service endpoint is published
    /// under. When non-empty, svcmgr's launch path creates a service
    /// endpoint, serves its RECV half as bootstrap cap[0] (ahead of the
    /// `seed` caps), and publishes one SEND half per entry — each stamped
    /// with that entry's [`ProvidedName::badge`] — into the discovery
    /// registry. The endpoint persists across restarts (svcmgr holds the
    /// source), so cached client caps survive a crash-restart cycle and no
    /// re-publish is needed. Empty for pure-consumer services that only
    /// receive `seed` caps. Reconciliation launches a provider ahead of pure
    /// consumers, and after each provider whose name it seeds
    /// ([`launch_order`]), so its names resolve before they are queried.
    pub provides: Vec<ProvidedName>,
    /// `log_sink = yes` marks the service as the system log sink (real-logd).
    /// svcmgr mints its bootstrap round — master-log RECV, the
    /// `HANDOVER_PULL` SEND (on the first launch, and on a restart until
    /// procmgr reports init reaped: [`log_sink_handover_owed`]), a `DEATH_EQ_AUTHORITY` `SEND|GRANT`, and the
    /// `serial` and `framebuffer` class SENDs — from the reserved log-sink
    /// sources and its `devmgr.class.serial` and `devmgr.class.framebuffer`
    /// publications, rather than from `seed` /
    /// `provides` (which the parser rejects in combination). Exactly one
    /// recipe carries this; supervision/restart otherwise follow the normal
    /// `restart`/`critical` fields.
    pub log_sink: bool,
    /// `debug_authority = yes` endows the service with procmgr's debug
    /// authority: svcmgr mints a `DEBUG_AUTHORITY`-badged `SEND|GRANT` on
    /// procmgr and delivers it in the bootstrap slot after the `seed` caps.
    /// Exclusive of `log_sink`.
    pub debug_authority: bool,
    /// `shutdown_actuator = <name>` marks the service as the system's shutdown
    /// actuator; this holds the `:auth` [`Definition::provides`] entry `<name>`
    /// names. When a `critical = yes` service is permanently down, svcmgr
    /// derives a SEND stamped with that entry's badge from the actuator's own
    /// service endpoint and calls the shutdown request through it. The parser
    /// requires a supervised service (`restart` other than `never`). `None`
    /// for every other service; [`shutdown_actuator`] picks one actuator from
    /// a scan.
    pub shutdown_actuator: Option<ProvidedName>,
    /// `oom_stop = yes` lets svcmgr stop the service when a stop-authority
    /// holder asks (`stop_labels::STOP_CANDIDATE` on svcmgr's endpoint),
    /// routing the death through [`Definition::restart`]; svcmgr asks procmgr
    /// for a handle to its budget node, through which it reads the usage
    /// `stop_labels::LIST_CANDIDATES` reports. The parser rejects it on a
    /// recipe [`stop::stop_refusal`] would refuse: `critical = yes`,
    /// `restart = never`, or a core role ([`stop::core_role`]).
    pub oom_stop: bool,
    /// `stop_authority = yes` endows the service with svcmgr's stop
    /// authority: svcmgr mints a `STOP_AUTHORITY`-badged SEND on its own
    /// service endpoint and delivers it in the bootstrap slot after the
    /// `seed` caps and the debug-authority cap. Exclusive of `log_sink`.
    pub stop_authority: bool,
    /// `entropy_authority = yes` endows the service with the kernel's
    /// entropy-contribution authority: svcmgr derives a copy of its
    /// `EntropyControl` source carrying `Contribute` and delivers it in the
    /// bootstrap slot after the `seed` caps, the debug-authority cap and the
    /// stop-authority cap. One service holds it: [`keep_one_entropy_holder`]
    /// clears the key on every later declaration in launch order. Exclusive of
    /// `log_sink`. A core role ([`stop::core_role`]).
    pub entropy_authority: bool,
    /// `reserve = yes` creates the service in the system reserve
    /// (`procmgr_labels::CREATE_RESERVE`, [`create_flags`]), on its launch
    /// and on every restart, so it may take the pages memmgr keeps in reserve.
    pub reserve: bool,
    /// `stop_source = <class>` makes the service a stop source of that class:
    /// while it runs, svcmgr lists it to a stop-authority holder
    /// (`svcmgr_labels::LIST_STOP_SOURCES`) with the class and a SEND on its
    /// service endpoint badged with `stop_labels::STOP_AUTHORITY`. Each
    /// instance is created contained (`procmgr_labels::CREATE_CONTAIN`,
    /// [`create_flags`]), so what it started ends with it. A core role
    /// ([`stop::core_role`]). The parser requires `provides` with every entry
    /// badged and a supervised service. `None` for every other service.
    pub stop_source: Option<stop::StopClass>,
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
    /// `1 << 63` for an `:auth` or `:grant` entry (carries the
    /// verb-authority bit), `1` for a `:deny` entry (present but
    /// gate-failing), `0` for a bare entry (unbadged — published via
    /// `cap_derive`, not `cap_derive_badge`).
    pub badge: u64,
    /// `true` for a `:grant` entry: svcmgr publishes its SEND with
    /// `GRANT`, so a recipe seeding the name can move caps to the provider.
    /// Such a name is seed-only, as every verb-bit name is, so
    /// `QUERY_ENDPOINT` never yields `GRANT`.
    pub grant: bool,
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

    /// A recipe named `name`, declaring a shutdown actuator when `actuator`.
    #[expect(
        clippy::fn_params_excessive_bools,
        reason = "`actuator` is the recipe's shutdown-actuator field"
    )]
    fn recipe(name: &str, actuator: bool) -> Definition
    {
        let mut contents = String::from(
            "binary = /services/x\nrestart = on_failure\ncritical = no\nnamespace = none\n\
             provides = p:auth\n",
        );
        if actuator
        {
            contents.push_str("shutdown_actuator = p\n");
        }
        parse::parse(name, &contents).expect("valid recipe")
    }

    #[test]
    fn the_first_declared_shutdown_actuator_is_the_one_recognised()
    {
        let defs = [recipe("a", false), recipe("b", true), recipe("c", true)];
        assert_eq!(shutdown_actuator(&defs), Some(1));
        assert_eq!(shutdown_actuator(&[recipe("a", false)]), None);
        assert_eq!(shutdown_actuator(&[]), None);
    }

    /// A recipe named `name` that sets `entropy_authority` to `holds`.
    #[expect(
        clippy::fn_params_excessive_bools,
        reason = "`holds` is the recipe's entropy_authority key"
    )]
    fn entropy(name: &str, holds: bool) -> Definition
    {
        let value = if holds { "yes" } else { "no" };
        let contents = format!(
            "binary = /services/x\nrestart = on_failure\ncritical = no\nnamespace = none\n\
             entropy_authority = {value}\n"
        );
        parse::parse(name, &contents).expect("valid recipe")
    }

    // A second holder would be a second contributor the design does not have:
    // every declaration after the first loses the key, and each is reported.
    #[test]
    fn only_the_first_entropy_authority_declaration_keeps_the_key()
    {
        let mut defs = [
            entropy("a", false),
            entropy("b", true),
            entropy("c", false),
            entropy("d", true),
            entropy("e", true),
        ];
        let mut extra = Vec::new();
        let holder = keep_one_entropy_holder(&mut defs, |def| extra.push(def.name.clone()));
        assert_eq!(holder, Some(1));
        assert_eq!(extra, ["d", "e"]);
        let kept: Vec<bool> = defs.iter().map(|d| d.entropy_authority).collect();
        assert_eq!(kept, [false, true, false, false, false]);
    }

    #[test]
    fn no_entropy_authority_declaration_leaves_no_holder()
    {
        let mut defs = [entropy("a", false), entropy("b", false)];
        assert_eq!(
            keep_one_entropy_holder(&mut defs, |_| panic!("no extra")),
            None
        );
        assert_eq!(
            keep_one_entropy_holder(&mut [], |_| panic!("no extra")),
            None
        );
    }

    /// A recipe named `name` providing the names `provides` (a consumer when
    /// empty) and seeding `seed`.
    fn ordered(name: &str, provides: &str, seed: &str) -> Definition
    {
        let line = |key: &str, value: &str| {
            if value.is_empty()
            {
                String::new()
            }
            else
            {
                format!("{key} = {value}\n")
            }
        };
        let contents = format!(
            "binary = /services/x\nrestart = on_failure\ncritical = no\nnamespace = none\n{}{}",
            line("provides", provides),
            line("seed", seed)
        );
        parse::parse(name, &contents).expect("valid recipe")
    }

    fn order(mut defs: Vec<Definition>) -> (Vec<String>, Vec<String>)
    {
        let mut cycles = Vec::new();
        launch_order(&mut defs, |d| cycles.push(d.name.clone()));
        (defs.into_iter().map(|d| d.name).collect(), cycles)
    }

    #[test]
    fn providers_launch_first_in_name_order_and_after_the_providers_they_seed_from()
    {
        // pwrmgr seeds acpid's name; zz's provider sorts last, so the order
        // follows the seed, not the name.
        let (names, cycles) = order(vec![
            ordered("cons", "", "a.x zz.x"),
            ordered(
                "pwrmgr",
                "pwrmgr.shutdown:auth",
                "devmgr.shutdown acpid.power",
            ),
            ordered("acpid", "acpid.power:auth acpid.deny:deny", "devmgr.acpi"),
            ordered("a", "a.x", "zz.x"),
            ordered("m", "m.x", ""),
            ordered("zz", "zz.x", ""),
        ]);
        assert_eq!(names, ["acpid", "m", "pwrmgr", "zz", "a", "cons"]);
        assert_eq!(cycles, Vec::<String>::new());
    }

    #[test]
    fn a_seed_no_recipe_provides_and_a_seed_of_its_own_name_order_nothing()
    {
        // b seeds a name nobody provides (as a provider whose launch fails
        // provides none): it keeps its name-order place and launches with
        // that seed unresolved. c seeds its own name.
        let (names, cycles) = order(vec![
            ordered("c", "c.x", "c.x"),
            ordered("b", "b.x", "gone.x"),
            ordered("a", "a.x", ""),
        ]);
        assert_eq!(names, ["a", "b", "c"]);
        assert_eq!(cycles, Vec::<String>::new());
    }

    #[test]
    fn a_seed_cycle_launches_its_first_member_in_name_order_and_is_reported()
    {
        // b and c seed each other, d seeds c, a is free.
        let (names, cycles) = order(vec![
            ordered("d", "d.x", "c.x"),
            ordered("c", "c.x", "b.x"),
            ordered("b", "b.x", "c.x"),
            ordered("a", "a.x", ""),
            ordered("cons", "", "b.x"),
        ]);
        assert_eq!(names, ["a", "b", "c", "d", "cons"]);
        assert_eq!(cycles, ["b"]);
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
    fn only_a_reaped_init_ends_the_log_sinks_handover()
    {
        use ipc::procmgr_errors::SUCCESS;
        // The reap has run: init-logd has exited, no SEND.
        assert!(!log_sink_handover_owed(Some((SUCCESS, 1))));
        // The reap has not run: init-logd may still serve.
        assert!(log_sink_handover_owed(Some((SUCCESS, 0))));
        // A refused or failed query does not say init-logd is gone.
        assert!(log_sink_handover_owed(Some((
            ipc::procmgr_errors::UNKNOWN_OPCODE,
            1
        ))));
        assert!(log_sink_handover_owed(None));
        // An unexpected word is not read as a reap.
        assert!(log_sink_handover_owed(Some((SUCCESS, 2))));
        // The label's upper bits carry no status.
        assert!(!log_sink_handover_owed(Some((SUCCESS | (8 << 16), 1))));
    }

    #[test]
    fn each_recipe_key_asks_for_its_own_create_flag()
    {
        use ipc::procmgr_labels::{CREATE_CONTAIN, CREATE_NODE_HANDLE, CREATE_RESERVE};
        assert_eq!(create_flags(false, false, false), 0);
        assert_eq!(create_flags(true, false, false), CREATE_RESERVE);
        assert_eq!(create_flags(false, true, false), CREATE_NODE_HANDLE);
        assert_eq!(create_flags(false, false, true), CREATE_CONTAIN);
        assert_eq!(
            create_flags(true, true, true),
            CREATE_RESERVE | CREATE_NODE_HANDLE | CREATE_CONTAIN
        );
        // Never a flag procmgr refuses from svcmgr: the charge-node flag, with
        // which procmgr refuses CREATE_RESERVE.
        assert_eq!(
            create_flags(true, true, true) & ipc::procmgr_labels::CREATE_CHARGE_NODE,
            0
        );
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
