// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svcmgr/svc-defs/src/parse.rs

//! Bespoke `key = value` parser for `.svc` service-definition files.
//!
//! The grammar is deliberately small: line-oriented, `#` introduces a
//! comment, whitespace around `=` is tolerated, and unknown keys are
//! a hard error so a typo can never silently degrade a service.
//!
//! See [`super`] for the [`Definition`] consumers and
//! `services/svcmgr/docs/service-definitions.md` for the authoritative
//! spec.

use namespace_protocol::rights as ns_rights;

use super::{Definition, NamespaceShape, ProvidedName, RestartPolicy, blob_len};

/// Badge stamped on an `:auth` provider SEND — the first verb bit
/// (`1 << 63`), the one a server's primary `*_AUTHORITY` gate tests; a
/// provider name carrying it is published seed-only.
const PROVIDES_AUTH_BADGE: u64 = 1 << 63;
/// Badge stamped on a `:deny` provider SEND — present so the cap
/// resolves, but lacking the authority bit, so the server's
/// `badge & (1 << 63)` gate fails. Distinct from a bare (unbadged)
/// entry only in intent; both are rejected by an authority gate.
const PROVIDES_DENY_BADGE: u64 = 1;

/// Reasons a `.svc` file is rejected. Stringified into the boot log so
/// an operator can find the bad line at a glance.
#[derive(Debug)]
pub enum ParseError
{
    /// A non-comment, non-blank line had no `=` separator.
    MissingEquals(usize),
    /// A recognised key appeared more than once in the same file.
    DuplicateKey(usize, &'static str),
    /// The key text did not match any known key.
    UnknownKey(usize, String),
    /// A mandatory key was missing.
    MissingKey(&'static str),
    /// The value parsed but failed a semantic check (range,
    /// combination with another field, …).
    InvalidValue(usize, &'static str),
    /// `restart` was not one of `never | on_failure | always`.
    BadRestart(usize, String),
    /// `critical` was not one of `yes | no`.
    BadCriticality(usize, String),
    /// `namespace` form was unrecognised. Expected `none`,
    /// `universal`, or `subtree:<path>:<rights>`.
    BadNamespace(usize, String),
    /// A right name in `subtree:…:<rights>` was not one of the
    /// known tokens.
    BadRights(usize, String),
    /// `argv` / `env` would not fit the child's argv/env region: both
    /// NUL-packed blobs together over `process_abi::ARGV_ENV_MAX_BYTES`
    /// (line `0`).
    TooLarge(usize, &'static str),
    /// The heap could not hold a copy of a recipe field (or of the text an
    /// error reports); the scan drops the recipe.
    OutOfMemory,
}

/// Reserve room for `additional` more bytes in `s`, or
/// [`ParseError::OutOfMemory`] when the heap cannot provide it.
fn reserve_str(s: &mut String, additional: usize) -> Result<(), ParseError>
{
    s.try_reserve_exact(additional)
        .map_err(|_| ParseError::OutOfMemory)
}

/// Copy `s` into a new `String`, or [`ParseError::OutOfMemory`].
fn owned(s: &str) -> Result<String, ParseError>
{
    let mut out = String::new();
    reserve_str(&mut out, s.len())?;
    out.push_str(s);
    Ok(out)
}

/// Append `item` to `v`, or [`ParseError::OutOfMemory`] when `v` cannot grow.
fn push<T>(v: &mut Vec<T>, item: T) -> Result<(), ParseError>
{
    v.try_reserve(1).map_err(|_| ParseError::OutOfMemory)?;
    v.push(item);
    Ok(())
}

/// Copy every whitespace-separated token of `value`, or
/// [`ParseError::OutOfMemory`].
fn owned_tokens(value: &str) -> Result<Vec<String>, ParseError>
{
    let mut out = Vec::new();
    for tok in value.split_whitespace()
    {
        push(&mut out, owned(tok)?)?;
    }
    Ok(out)
}

/// Bound a recipe's `argv` and `env` against the child's argv/env region:
/// the two NUL-packed blobs together must fit `max_bytes`
/// (`process_abi::ARGV_ENV_MAX_BYTES`, the bound `std::process::Command`
/// applies to its own spawns and procmgr to every create), else
/// [`ParseError::TooLarge`] on line `0`. No token count or per-blob bound
/// applies below it.
fn check_startup_blobs(argv: &[String], env: &[String], max_bytes: u64) -> Result<(), ParseError>
{
    let total = blob_len(argv).saturating_add(blob_len(env));
    if u64::try_from(total).map_or(true, |t| t > max_bytes)
    {
        return Err(ParseError::TooLarge(
            0,
            "argv and env together exceed the process ABI's argv/env region",
        ));
    }
    Ok(())
}

/// Bound a `binary` or `subtree:<path>` value against `ipc::MAX_PATH_LEN`,
/// the one recipe path limit (`services/svcmgr/docs/service-definitions.md`
/// § Keys).
fn check_path_len(lineno: usize, path: &str, too_long: &'static str) -> Result<(), ParseError>
{
    if path.len() > ipc::MAX_PATH_LEN
    {
        return Err(ParseError::InvalidValue(lineno, too_long));
    }
    Ok(())
}

/// Whether `cwd` names `subtree` itself or a directory below it, compared
/// component-wise so `/data2` does not pass for `/data`. svcmgr walks `cwd`
/// from its universal root, so this check is what keeps a subtree-confined
/// child's working-directory cap at a directory inside its namespace;
/// [`crate::cwd_rights`] bounds that cap's rights. Namespace servers
/// reject `.` and `..` components (docs/namespace-model.md), so a path that
/// passes cannot walk back out.
fn cwd_within_subtree(cwd: &str, subtree: &str) -> bool
{
    let root = subtree.trim_end_matches('/');
    cwd == root
        || cwd
            .strip_prefix(root)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// Parse a `priority = ` / `sched_max = ` value: a decimal priority level
/// within the kernel's assignable userspace range
/// `[PRIORITY_MIN, PRIORITY_MAX]`.
fn parse_priority_value(lineno: usize, value: &str, key: &'static str) -> Result<u8, ParseError>
{
    let level: u8 = value
        .parse()
        .map_err(|_| ParseError::InvalidValue(lineno, key))?;
    if !(syscall_abi::PRIORITY_MIN..=syscall_abi::PRIORITY_MAX).contains(&level)
    {
        return Err(ParseError::InvalidValue(lineno, key));
    }
    Ok(level)
}

/// Parse the contents of a single `.svc` file. `name` is the filename
/// without the `.svc` suffix; it becomes the `Definition::name` value
/// and the key under which the service registers with svcmgr.
///
/// # Errors
///
/// Returns a [`ParseError`] naming the offending line when the contents
/// violate the grammar or a semantic rule: a service `name` that is empty or
/// over `ipc::svcmgr_labels::NAME_MAX` bytes ([`ParseError::InvalidValue`]
/// on line 0), a missing `=`, an unknown or
/// duplicated key, a missing mandatory key, a malformed value, an
/// inconsistent combination (`cwd` with `namespace = none`, a `cwd` of the
/// root under `namespace = universal`, a `cwd` outside a
/// `namespace = subtree:` path or under one whose rights lack `LOOKUP`,
/// `log_sink` with `seed`/`provides` or with `debug_authority`,
/// `sched_max` below `priority`), a `binary` or
/// subtree path over `ipc::MAX_PATH_LEN` or with no path components
/// ([`ParseError::InvalidValue`]), or
/// `argv` and `env` that together would not fit the child's argv/env region
/// ([`ParseError::TooLarge`]). Every copy it makes is fallible: a heap that
/// cannot hold one returns [`ParseError::OutOfMemory`].
// too_many_lines: one pass over the `key = value` grammar whose per-key
// `match` is a flat table of short arms sharing the duplicate-key and
// mandatory-key bookkeeping locals; moving arms into helpers would thread
// those locals through every helper without buying structural clarity.
#[allow(clippy::too_many_lines)]
pub fn parse(name: &str, contents: &str) -> Result<Definition, ParseError>
{
    if name.is_empty() || name.len() > ipc::svcmgr_labels::NAME_MAX
    {
        return Err(ParseError::InvalidValue(
            0,
            "service name exceeds NAME_MAX bytes",
        ));
    }
    let mut binary: Option<String> = None;
    let mut argv: Vec<String> = Vec::new();
    let mut env: Vec<String> = Vec::new();
    let mut restart: Option<RestartPolicy> = None;
    let mut system_critical: Option<bool> = None;
    let mut namespace: Option<NamespaceShape> = None;
    let mut cwd: Option<String> = None;
    let mut seed: Vec<String> = Vec::new();
    let mut provides: Vec<ProvidedName> = Vec::new();
    let mut log_sink: Option<bool> = None;
    let mut debug_authority: Option<bool> = None;
    let mut priority: Option<u8> = None;
    let mut sched_max: Option<u8> = None;

    let mut seen_argv = false;
    let mut seen_env = false;
    let mut seen_cwd = false;
    let mut seen_seed = false;
    let mut seen_provides = false;

    for (idx, raw) in contents.lines().enumerate()
    {
        let lineno = idx + 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#')
        {
            continue;
        }

        let (key, value) = match line.split_once('=')
        {
            Some((k, v)) => (k.trim(), v.trim()),
            None => return Err(ParseError::MissingEquals(lineno)),
        };

        match key
        {
            "binary" =>
            {
                if binary.is_some()
                {
                    return Err(ParseError::DuplicateKey(lineno, "binary"));
                }
                if value.is_empty() || !value.starts_with('/')
                {
                    return Err(ParseError::InvalidValue(lineno, "binary must be absolute"));
                }
                check_path_len(lineno, value, "binary path exceeds MAX_PATH_LEN bytes")?;
                binary = Some(owned(value)?);
            }
            "argv" =>
            {
                if seen_argv
                {
                    return Err(ParseError::DuplicateKey(lineno, "argv"));
                }
                seen_argv = true;
                argv = owned_tokens(value)?;
                // The blob is NUL-delimited, so an embedded NUL would split
                // one token into two on the child's side while the label
                // still carries the parser's count.
                if argv.iter().any(|tok| tok.contains('\0'))
                {
                    return Err(ParseError::InvalidValue(
                        lineno,
                        "argv tokens must not contain NUL",
                    ));
                }
            }
            "env" =>
            {
                if seen_env
                {
                    return Err(ParseError::DuplicateKey(lineno, "env"));
                }
                seen_env = true;
                for tok in value.split_whitespace()
                {
                    if !tok.contains('=')
                    {
                        return Err(ParseError::InvalidValue(
                            lineno,
                            "env tokens must be KEY=VAL",
                        ));
                    }
                    if tok.contains('\0')
                    {
                        return Err(ParseError::InvalidValue(
                            lineno,
                            "env tokens must not contain NUL",
                        ));
                    }
                    push(&mut env, owned(tok)?)?;
                }
            }
            "restart" =>
            {
                if restart.is_some()
                {
                    return Err(ParseError::DuplicateKey(lineno, "restart"));
                }
                restart = Some(match value
                {
                    "never" => RestartPolicy::Never,
                    "on_failure" => RestartPolicy::OnFailure,
                    "always" => RestartPolicy::Always,
                    other => return Err(ParseError::BadRestart(lineno, owned(other)?)),
                });
            }
            "critical" =>
            {
                if system_critical.is_some()
                {
                    return Err(ParseError::DuplicateKey(lineno, "critical"));
                }
                system_critical = Some(match value
                {
                    "yes" => true,
                    "no" => false,
                    other => return Err(ParseError::BadCriticality(lineno, owned(other)?)),
                });
            }
            "namespace" =>
            {
                if namespace.is_some()
                {
                    return Err(ParseError::DuplicateKey(lineno, "namespace"));
                }
                namespace = Some(parse_namespace(lineno, value)?);
            }
            "cwd" =>
            {
                if seen_cwd
                {
                    return Err(ParseError::DuplicateKey(lineno, "cwd"));
                }
                seen_cwd = true;
                if value.is_empty()
                {
                    return Err(ParseError::InvalidValue(lineno, "cwd must be non-empty"));
                }
                cwd = Some(owned(value)?);
            }
            "seed" =>
            {
                if seen_seed
                {
                    return Err(ParseError::DuplicateKey(lineno, "seed"));
                }
                seen_seed = true;
                seed = owned_tokens(value)?;
            }
            "provides" =>
            {
                if seen_provides
                {
                    return Err(ParseError::DuplicateKey(lineno, "provides"));
                }
                seen_provides = true;
                for tok in value.split_whitespace()
                {
                    let (name, badge) = match tok.split_once(':')
                    {
                        Some((n, "auth")) => (n, PROVIDES_AUTH_BADGE),
                        Some((n, "deny")) => (n, PROVIDES_DENY_BADGE),
                        Some((_, _)) =>
                        {
                            return Err(ParseError::InvalidValue(
                                lineno,
                                "provides suffix must be :auth or :deny",
                            ));
                        }
                        None => (tok, 0),
                    };
                    if name.is_empty() || name.len() > ipc::svcmgr_labels::NAME_MAX
                    {
                        return Err(ParseError::InvalidValue(
                            lineno,
                            "provides name must be non-empty and <= NAME_MAX bytes",
                        ));
                    }
                    push(
                        &mut provides,
                        ProvidedName {
                            name: owned(name)?,
                            badge,
                        },
                    )?;
                }
                if provides.is_empty()
                {
                    return Err(ParseError::InvalidValue(
                        lineno,
                        "provides must list at least one name",
                    ));
                }
            }
            "log_sink" =>
            {
                if log_sink.is_some()
                {
                    return Err(ParseError::DuplicateKey(lineno, "log_sink"));
                }
                log_sink = Some(match value
                {
                    "yes" => true,
                    "no" => false,
                    _ =>
                    {
                        return Err(ParseError::InvalidValue(
                            lineno,
                            "log_sink must be yes or no",
                        ));
                    }
                });
            }
            "debug_authority" =>
            {
                if debug_authority.is_some()
                {
                    return Err(ParseError::DuplicateKey(lineno, "debug_authority"));
                }
                debug_authority = Some(match value
                {
                    "yes" => true,
                    "no" => false,
                    _ =>
                    {
                        return Err(ParseError::InvalidValue(
                            lineno,
                            "debug_authority must be yes or no",
                        ));
                    }
                });
            }
            "priority" =>
            {
                if priority.is_some()
                {
                    return Err(ParseError::DuplicateKey(lineno, "priority"));
                }
                priority = Some(parse_priority_value(
                    lineno,
                    value,
                    "priority must be a level in [1, 30]",
                )?);
            }
            "sched_max" =>
            {
                if sched_max.is_some()
                {
                    return Err(ParseError::DuplicateKey(lineno, "sched_max"));
                }
                sched_max = Some(parse_priority_value(
                    lineno,
                    value,
                    "sched_max must be a level in [1, 30]",
                )?);
            }
            other => return Err(ParseError::UnknownKey(lineno, owned(other)?)),
        }
    }

    let binary = binary.ok_or(ParseError::MissingKey("binary"))?;
    let restart = restart.ok_or(ParseError::MissingKey("restart"))?;
    let system_critical = system_critical.ok_or(ParseError::MissingKey("critical"))?;
    let namespace = namespace.ok_or(ParseError::MissingKey("namespace"))?;

    match (&namespace, &cwd)
    {
        (NamespaceShape::None, Some(_)) =>
        {
            return Err(ParseError::InvalidValue(
                0,
                "cwd is forbidden when namespace = none",
            ));
        }
        (NamespaceShape::Universal, Some(dir)) if names_root(dir) =>
        {
            return Err(ParseError::InvalidValue(
                0,
                "cwd must not be the root: the cwd walk cannot narrow it",
            ));
        }
        (NamespaceShape::Subtree { path, rights }, Some(dir)) =>
        {
            if !cwd_within_subtree(dir, path)
            {
                return Err(ParseError::InvalidValue(
                    0,
                    "cwd must be the namespace subtree path or a path below it",
                ));
            }
            // The cwd cap takes only the subtree's rights (`cwd_rights`);
            // without LOOKUP it could not resolve a relative path.
            if rights & ns_rights::LOOKUP == 0
            {
                return Err(ParseError::InvalidValue(
                    0,
                    "cwd under a subtree namespace needs LOOKUP in the subtree rights",
                ));
            }
        }
        _ =>
        {}
    }

    let log_sink = log_sink.unwrap_or(false);
    if log_sink && (!seed.is_empty() || !provides.is_empty())
    {
        // A log-sink service's bootstrap caps are minted by svcmgr from the
        // reserved log-sink sources, so registry-resolved seeds / provided
        // endpoints have no slot in its round.
        return Err(ParseError::InvalidValue(
            0,
            "log_sink is exclusive of seed and provides",
        ));
    }
    let debug_authority = debug_authority.unwrap_or(false);
    if log_sink && debug_authority
    {
        // The log sink's round is minted from the log-sink sources and has
        // no slot for the authority cap.
        return Err(ParseError::InvalidValue(
            0,
            "log_sink is exclusive of debug_authority",
        ));
    }

    // The service's own band must cover its starting level, so it can
    // always restore its initial priority. procmgr enforces the same
    // invariant on the wire; rejecting here surfaces the recipe error at
    // parse time instead of as a spawn failure.
    if let (Some(p), Some(m)) = (priority, sched_max)
        && m < p
    {
        return Err(ParseError::InvalidValue(0, "sched_max must be >= priority"));
    }

    check_startup_blobs(&argv, &env, process_abi::ARGV_ENV_MAX_BYTES)?;

    Ok(Definition {
        name: owned(name)?,
        binary,
        argv,
        env,
        restart,
        system_critical,
        namespace,
        cwd,
        seed,
        provides,
        log_sink,
        debug_authority,
        priority,
        sched_max,
    })
}

/// Parse the `namespace = …` value. Accepts the three documented
/// forms; everything else is [`ParseError::BadNamespace`].
fn parse_namespace(lineno: usize, value: &str) -> Result<NamespaceShape, ParseError>
{
    if value == "none"
    {
        return Ok(NamespaceShape::None);
    }
    if value == "universal"
    {
        return Ok(NamespaceShape::Universal);
    }
    if let Some(rest) = value.strip_prefix("subtree:")
    {
        let Some((path, rights_str)) = rest.rsplit_once(':')
        else
        {
            return Err(ParseError::BadNamespace(lineno, owned(value)?));
        };
        if path.is_empty() || !path.starts_with('/')
        {
            return Err(ParseError::BadNamespace(lineno, owned(value)?));
        }
        // A path with no components walks no NS_LOOKUP hop, so no namespace
        // server attenuates the cap to `<rights>` (see `names_root`): the
        // walk would fail for narrower rights or hand over the full root,
        // which `universal` already names.
        if names_root(path)
        {
            return Err(ParseError::InvalidValue(
                lineno,
                "namespace subtree path must name a directory below the root (use universal)",
            ));
        }
        check_path_len(
            lineno,
            path,
            "namespace subtree path exceeds MAX_PATH_LEN bytes",
        )?;
        let rights = parse_rights(lineno, rights_str)?;
        return Ok(NamespaceShape::Subtree {
            path: owned(path)?,
            rights,
        });
    }
    Err(ParseError::BadNamespace(lineno, owned(value)?))
}

/// A path with no components names the walk's anchor, the root, which
/// `std::os::seraph::namespace_lookup_dir` returns only for a request of
/// every right: no hop narrows it.
fn names_root(path: &str) -> bool
{
    path.split('/').all(str::is_empty)
}

/// Parse a `+`-joined list of named rights tokens (LOOKUP, STAT, …)
/// into a `namespace-protocol` rights mask. Unknown tokens fail loud.
fn parse_rights(lineno: usize, value: &str) -> Result<u32, ParseError>
{
    if value.is_empty()
    {
        return Err(ParseError::BadRights(lineno, owned(value)?));
    }
    let mut mask: u32 = 0;
    for tok in value.split('+')
    {
        let tok = tok.trim();
        let bit = match tok
        {
            "LOOKUP" => ns_rights::LOOKUP,
            "READDIR" => ns_rights::READDIR,
            "STAT" => ns_rights::STAT,
            "READ" => ns_rights::READ,
            "WRITE" => ns_rights::WRITE,
            "EXEC" => ns_rights::EXEC,
            "MUTATE_DIR" => ns_rights::MUTATE_DIR,
            "ADMIN" => ns_rights::ADMIN,
            other => return Err(ParseError::BadRights(lineno, owned(other)?)),
        };
        mask |= bit;
    }
    Ok(mask)
}

impl core::fmt::Display for ParseError
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
    {
        match self
        {
            Self::MissingEquals(l) => write!(f, "line {l}: missing `=` separator"),
            Self::DuplicateKey(l, k) => write!(f, "line {l}: duplicate key `{k}`"),
            Self::UnknownKey(l, k) => write!(f, "line {l}: unknown key `{k}`"),
            Self::MissingKey(k) => write!(f, "missing required key `{k}`"),
            Self::InvalidValue(l, why) => write!(f, "line {l}: {why}"),
            Self::BadRestart(l, v) =>
            {
                write!(
                    f,
                    "line {l}: bad restart value `{v}` (want never|on_failure|always)"
                )
            }
            Self::BadCriticality(l, v) =>
            {
                write!(f, "line {l}: bad critical value `{v}` (want yes|no)")
            }
            Self::BadNamespace(l, v) =>
            {
                write!(
                    f,
                    "line {l}: bad namespace `{v}` (want none|universal|subtree:<path>:<rights>)"
                )
            }
            Self::BadRights(l, v) => write!(f, "line {l}: bad rights `{v}`"),
            Self::TooLarge(l, why) => write!(f, "line {l}: {why} (argv/env region limit)"),
            Self::OutOfMemory => write!(f, "no memory to copy the recipe"),
        }
    }
}

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::build_blob;

    #[test]
    fn a_reservation_the_heap_cannot_meet_is_out_of_memory()
    {
        // The one way a host test can make a reservation fail: a request no
        // allocator can meet. The parser's string copies reserve through here.
        let mut s = String::new();
        assert!(matches!(
            reserve_str(&mut s, usize::MAX),
            Err(ParseError::OutOfMemory)
        ));
    }

    /// Minimal valid recipe body; tests append the lines under test.
    const BASE: &str = "binary = /services/x\nrestart = never\ncritical = no\nnamespace = none\n";

    fn parse_with(extra: &str) -> Result<Definition, ParseError>
    {
        let mut contents = String::from(BASE);
        contents.push_str(extra);
        parse("x", &contents)
    }

    #[test]
    fn full_recipe_parses_every_surface()
    {
        let contents = "\
# comment\n\
binary    = /programs/terminal\n\
argv      = terminal /programs/shell\n\
env       = KEY=VAL\n\
restart   = on_failure\n\
critical  = yes\n\
namespace = subtree:/tests:LOOKUP+READ\n\
cwd       = /tests\n\
seed      = devmgr.registry\n\
priority  = 10\n\
sched_max = 12\n";
        let def = parse("terminal", contents).expect("valid recipe");
        assert_eq!(def.binary, "/programs/terminal");
        assert_eq!(def.argv, ["terminal", "/programs/shell"]);
        assert_eq!(def.restart, RestartPolicy::OnFailure);
        assert!(def.system_critical);
        assert!(matches!(def.namespace, NamespaceShape::Subtree { .. }));
        assert_eq!(def.cwd.as_deref(), Some("/tests"));
        assert_eq!(def.seed, ["devmgr.registry"]);
        assert_eq!(def.priority, Some(10));
        assert_eq!(def.sched_max, Some(12));
    }

    #[test]
    fn scheduling_keys_default_to_unspecified()
    {
        let def = parse_with("").expect("valid recipe");
        assert_eq!(def.priority, None);
        assert_eq!(def.sched_max, None);
    }

    #[test]
    fn priority_accepts_the_kernel_range_bounds()
    {
        assert_eq!(
            parse_with("priority = 1\n").expect("floor").priority,
            Some(1)
        );
        assert_eq!(
            parse_with("priority = 30\nsched_max = 30\n")
                .expect("ceiling")
                .priority,
            Some(30)
        );
    }

    #[test]
    fn priority_rejects_out_of_range_and_non_numeric_values()
    {
        assert!(matches!(
            parse_with("priority = 0\n"),
            Err(ParseError::InvalidValue(_, _))
        ));
        assert!(matches!(
            parse_with("priority = 31\n"),
            Err(ParseError::InvalidValue(_, _))
        ));
        assert!(matches!(
            parse_with("priority = high\n"),
            Err(ParseError::InvalidValue(_, _))
        ));
        assert!(matches!(
            parse_with("sched_max = 256\n"),
            Err(ParseError::InvalidValue(_, _))
        ));
    }

    #[test]
    fn sched_max_below_priority_is_rejected()
    {
        assert!(matches!(
            parse_with("priority = 10\nsched_max = 5\n"),
            Err(ParseError::InvalidValue(_, _))
        ));
        // Equal is the boundary case and must pass.
        let def = parse_with("priority = 5\nsched_max = 5\n").expect("equal band");
        assert_eq!((def.priority, def.sched_max), (Some(5), Some(5)));
    }

    #[test]
    fn sched_max_alone_is_accepted()
    {
        // Band without a starting level: procmgr clamps its default into
        // the band, so the combination is meaningful and must parse.
        let def = parse_with("sched_max = 5\n").expect("band only");
        assert_eq!((def.priority, def.sched_max), (None, Some(5)));
    }

    #[test]
    fn duplicate_scheduling_keys_are_rejected()
    {
        assert!(matches!(
            parse_with("priority = 5\npriority = 6\n"),
            Err(ParseError::DuplicateKey(_, "priority"))
        ));
        assert!(matches!(
            parse_with("sched_max = 5\nsched_max = 6\n"),
            Err(ParseError::DuplicateKey(_, "sched_max"))
        ));
    }

    #[test]
    fn debug_authority_is_off_unless_the_recipe_sets_it()
    {
        assert!(!parse_with("").expect("default").debug_authority);
        assert!(
            parse_with("debug_authority = yes\n")
                .expect("set")
                .debug_authority
        );
        assert!(
            !parse_with("debug_authority = no\n")
                .expect("cleared")
                .debug_authority
        );
        assert!(matches!(
            parse_with("debug_authority = maybe\n"),
            Err(ParseError::InvalidValue(_, _))
        ));
        assert!(matches!(
            parse_with("debug_authority = yes\ndebug_authority = yes\n"),
            Err(ParseError::DuplicateKey(_, "debug_authority"))
        ));
    }

    #[test]
    fn the_log_sink_cannot_hold_the_debug_authority()
    {
        assert!(matches!(
            parse_with("log_sink = yes\ndebug_authority = yes\n"),
            Err(ParseError::InvalidValue(_, _))
        ));
    }

    #[test]
    fn unknown_key_remains_a_hard_error()
    {
        assert!(matches!(
            parse_with("priorty = 5\n"),
            Err(ParseError::UnknownKey(_, _))
        ));
    }

    #[test]
    fn startup_tokens_containing_nul_are_rejected()
    {
        // A NUL inside a token would add a string boundary to the packed
        // blob without adding to the label's count; both keys refuse it.
        assert!(matches!(
            parse_with("argv = a\0b\n"),
            Err(ParseError::InvalidValue(5, why)) if why.starts_with("argv tokens")
        ));
        assert!(matches!(
            parse_with("env = K=v\0w\n"),
            Err(ParseError::InvalidValue(5, why)) if why.starts_with("env tokens must not")
        ));
    }

    /// An `argv` line with one token whose NUL-packed blob is `bytes` long.
    fn argv_line(bytes: usize) -> String
    {
        format!("argv = {}\n", "a".repeat(bytes - 1))
    }

    /// An `env` line with one `K=...` token whose NUL-packed blob is `bytes`
    /// long.
    fn env_line(bytes: usize) -> String
    {
        format!("env = K={}\n", "v".repeat(bytes - 3))
    }

    // Defect guarded: a parser that still refuses a recipe at the former
    // inline wire limits (255 tokens, 256 B per blob, 64 words together),
    // which the argv/env region no longer has.
    #[test]
    fn startup_blobs_past_the_former_inline_limits_are_accepted()
    {
        let tokens = format!("argv = {}\n", vec!["t"; 300].join(" "));
        let many = parse_with(&tokens).expect("300 argv tokens");
        assert_eq!(build_blob(&many.argv), (b"t\0".repeat(300), 300));
        let both = format!("{}{}", argv_line(9000), env_line(5000));
        let big = parse_with(&both).expect("argv and env past 256 B each");
        assert_eq!(
            build_blob(&big.argv).0.len() + build_blob(&big.env).0.len(),
            14_000
        );
    }

    // Defect guarded: a bound that counts one blob alone, or excludes the
    // NULs, so a recipe procmgr would refuse reaches svcmgr's launch path.
    #[test]
    fn startup_blobs_are_bounded_together_by_the_region()
    {
        let argv = vec![String::from("abc")];
        let env = vec![String::from("K=v")];
        assert!(check_startup_blobs(&argv, &env, 8).is_ok());
        assert!(matches!(
            check_startup_blobs(&argv, &env, 7),
            Err(ParseError::TooLarge(0, why)) if why.starts_with("argv and env together")
        ));
        assert!(check_startup_blobs(&[], &[], 0).is_ok());
    }

    /// Recipe whose `binary` is an absolute path of exactly `len` bytes.
    fn recipe_with_binary_len(len: usize) -> String
    {
        format!(
            "binary = /{}\nrestart = never\ncritical = no\nnamespace = none\n",
            "b".repeat(len - 1)
        )
    }

    /// Recipe whose `namespace` is a subtree of an absolute path of exactly
    /// `len` bytes.
    fn recipe_with_subtree_len(len: usize) -> String
    {
        format!(
            "binary = /services/x\nrestart = never\ncritical = no\n\
             namespace = subtree:/{}:LOOKUP\n",
            "s".repeat(len - 1)
        )
    }

    #[test]
    fn binary_path_is_bounded_by_max_path_len()
    {
        let at = parse("x", &recipe_with_binary_len(ipc::MAX_PATH_LEN)).expect("at MAX_PATH_LEN");
        assert_eq!(at.binary.len(), ipc::MAX_PATH_LEN);
        assert!(matches!(
            parse("x", &recipe_with_binary_len(ipc::MAX_PATH_LEN + 1)),
            Err(ParseError::InvalidValue(1, why)) if why.starts_with("binary path")
        ));
    }

    #[test]
    fn namespace_subtree_path_is_bounded_by_max_path_len()
    {
        let at = parse("x", &recipe_with_subtree_len(ipc::MAX_PATH_LEN)).expect("at MAX_PATH_LEN");
        assert!(matches!(
            at.namespace,
            NamespaceShape::Subtree { ref path, .. } if path.len() == ipc::MAX_PATH_LEN
        ));
        assert!(matches!(
            parse("x", &recipe_with_subtree_len(ipc::MAX_PATH_LEN + 1)),
            Err(ParseError::InvalidValue(4, why)) if why.starts_with("namespace subtree path")
        ));
    }

    /// Recipe confined to `subtree:/data` with the given `cwd`.
    fn subtree_recipe_with_cwd(cwd: &str) -> String
    {
        format!(
            "binary = /services/x\nrestart = never\ncritical = no\n\
             namespace = subtree:/data:LOOKUP\ncwd = {cwd}\n"
        )
    }

    #[test]
    fn subtree_cwd_at_or_below_the_subtree_is_accepted()
    {
        for cwd in ["/data", "/data/", "/data/logs"]
        {
            let def = parse("x", &subtree_recipe_with_cwd(cwd)).expect("cwd inside subtree");
            assert_eq!(def.cwd.as_deref(), Some(cwd));
        }
    }

    #[test]
    fn subtree_path_trailing_slash_is_normalised_for_the_cwd_check()
    {
        let recipe = |subtree: &str, cwd: &str| {
            format!(
                "binary = /services/x\nrestart = never\ncritical = no\n\
                 namespace = subtree:{subtree}:LOOKUP\ncwd = {cwd}\n"
            )
        };
        for (subtree, cwd) in [("/data/", "/data"), ("/data/", "/data/logs")]
        {
            parse("x", &recipe(subtree, cwd)).expect("cwd inside subtree");
        }
        assert!(matches!(
            parse("x", &recipe("/data/", "/data2")),
            Err(ParseError::InvalidValue(0, why)) if why.starts_with("cwd must be")
        ));
    }

    #[test]
    fn subtree_path_with_no_components_is_rejected()
    {
        for path in ["/", "//"]
        {
            let recipe = format!(
                "binary = /services/x\nrestart = never\ncritical = no\n\
                 namespace = subtree:{path}:LOOKUP\n"
            );
            assert!(matches!(
                parse("x", &recipe),
                Err(ParseError::InvalidValue(4, why)) if why.starts_with("namespace subtree path must")
            ));
        }
    }

    #[test]
    fn subtree_cwd_needs_lookup_in_the_subtree_rights()
    {
        let recipe = "binary = /services/x\nrestart = never\ncritical = no\n\
                      namespace = subtree:/data:READ+STAT\ncwd = /data\n";
        assert!(matches!(
            parse("x", recipe),
            Err(ParseError::InvalidValue(0, why)) if why.starts_with("cwd under a subtree")
        ));
    }

    #[test]
    fn subtree_cwd_outside_the_subtree_is_rejected()
    {
        // `/` would hand the child a cap on svcmgr's universal root;
        // `/data2` shares the subtree's byte prefix but not its directory.
        for cwd in ["/", "/etc", "/data2", "data"]
        {
            assert!(matches!(
                parse("x", &subtree_recipe_with_cwd(cwd)),
                Err(ParseError::InvalidValue(0, why)) if why.starts_with("cwd must be")
            ));
        }
    }

    // svcmgr serves seeds over as many bootstrap rounds as they need, so a
    // seed list longer than one round's cap slots is a valid recipe.
    #[test]
    fn seeds_past_one_bootstrap_round_parse_in_order()
    {
        let provider = parse_with("provides = p\nseed = a b c d e f\n")
            .expect("RECV + 6 seeds span two rounds");
        assert_eq!(provider.seed, ["a", "b", "c", "d", "e", "f"]);
    }

    #[test]
    fn cwd_of_the_root_under_universal_is_rejected()
    {
        for cwd in ["/", "//"]
        {
            let recipe = format!(
                "binary = /services/x\nrestart = never\ncritical = no\n\
                 namespace = universal\ncwd = {cwd}\n"
            );
            assert!(matches!(
                parse("x", &recipe),
                Err(ParseError::InvalidValue(0, why)) if why.starts_with("cwd must not be the root")
            ));
        }
    }

    #[test]
    fn service_name_is_bounded_by_the_one_name_limit()
    {
        let recipe = "binary = /x\nrestart = never\ncritical = no\nnamespace = none\n";
        let at = "a".repeat(ipc::svcmgr_labels::NAME_MAX);
        assert_eq!(parse(&at, recipe).expect("name at NAME_MAX").name, at);
        let over = "a".repeat(ipc::svcmgr_labels::NAME_MAX + 1);
        assert!(matches!(
            parse(&over, recipe),
            Err(ParseError::InvalidValue(0, _))
        ));
        assert!(matches!(
            parse("", recipe),
            Err(ParseError::InvalidValue(0, _))
        ));
    }
}
