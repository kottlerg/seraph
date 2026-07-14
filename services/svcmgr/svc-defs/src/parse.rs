// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// svcmgr/svc-defs/src/parse.rs

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

use super::{Definition, NamespaceShape, ProvidedName, RestartPolicy};

/// Badge stamped on an `:auth` provider SEND — the universal
/// verb-authority bit (`1 << 63`), shared by every `*_AUTHORITY`
/// constant the various services gate on.
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
/// violate the grammar or a semantic rule: a missing `=`, an unknown or
/// duplicated key, a missing mandatory key, a malformed value, or an
/// inconsistent combination (`cwd` with `namespace = none`, `log_sink`
/// with `seed`/`provides`, `sched_max` below `priority`).
#[allow(clippy::too_many_lines)]
pub fn parse(name: &str, contents: &str) -> Result<Definition, ParseError>
{
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
                binary = Some(value.to_owned());
            }
            "argv" =>
            {
                if seen_argv
                {
                    return Err(ParseError::DuplicateKey(lineno, "argv"));
                }
                seen_argv = true;
                argv = value.split_whitespace().map(str::to_owned).collect();
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
                    env.push(tok.to_owned());
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
                    other => return Err(ParseError::BadRestart(lineno, other.to_owned())),
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
                    other => return Err(ParseError::BadCriticality(lineno, other.to_owned())),
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
                cwd = Some(value.to_owned());
            }
            "seed" =>
            {
                if seen_seed
                {
                    return Err(ParseError::DuplicateKey(lineno, "seed"));
                }
                seen_seed = true;
                seed = value.split_whitespace().map(str::to_owned).collect();
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
                    if name.is_empty() || name.len() > registry::NAME_MAX
                    {
                        return Err(ParseError::InvalidValue(
                            lineno,
                            "provides name must be non-empty and <= NAME_MAX bytes",
                        ));
                    }
                    provides.push(ProvidedName {
                        name: name.to_owned(),
                        badge,
                    });
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
            other => return Err(ParseError::UnknownKey(lineno, other.to_owned())),
        }
    }

    let binary = binary.ok_or(ParseError::MissingKey("binary"))?;
    let restart = restart.ok_or(ParseError::MissingKey("restart"))?;
    let system_critical = system_critical.ok_or(ParseError::MissingKey("critical"))?;
    let namespace = namespace.ok_or(ParseError::MissingKey("namespace"))?;

    if matches!(namespace, NamespaceShape::None) && cwd.is_some()
    {
        return Err(ParseError::InvalidValue(
            0,
            "cwd is forbidden when namespace = none",
        ));
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

    // The service's own band must cover its starting level, so it can
    // always restore its initial priority. procmgr enforces the same
    // invariant on the wire; rejecting here surfaces the recipe error at
    // parse time with a line-level diagnostic instead of a spawn failure.
    if let (Some(p), Some(m)) = (priority, sched_max)
        && m < p
    {
        return Err(ParseError::InvalidValue(0, "sched_max must be >= priority"));
    }

    Ok(Definition {
        name: name.to_owned(),
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
        let (path, rights_str) = rest
            .rsplit_once(':')
            .ok_or_else(|| ParseError::BadNamespace(lineno, value.to_owned()))?;
        if path.is_empty() || !path.starts_with('/')
        {
            return Err(ParseError::BadNamespace(lineno, value.to_owned()));
        }
        let rights = parse_rights(lineno, rights_str)?;
        return Ok(NamespaceShape::Subtree {
            path: path.to_owned(),
            rights,
        });
    }
    Err(ParseError::BadNamespace(lineno, value.to_owned()))
}

/// Parse a `+`-joined list of named rights tokens (LOOKUP, STAT, …)
/// into a `namespace-protocol` rights mask. Unknown tokens fail loud.
fn parse_rights(lineno: usize, value: &str) -> Result<u32, ParseError>
{
    if value.is_empty()
    {
        return Err(ParseError::BadRights(lineno, value.to_owned()));
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
            other => return Err(ParseError::BadRights(lineno, other.to_owned())),
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
        }
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

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
    fn unknown_key_remains_a_hard_error()
    {
        assert!(matches!(
            parse_with("priorty = 5\n"),
            Err(ParseError::UnknownKey(_, _))
        ));
    }
}
