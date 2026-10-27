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
use syscall_abi::{MSG_CAP_SLOTS_MAX, MSG_DATA_WORDS_MAX};

use super::{Definition, NamespaceShape, ProvidedName, RestartPolicy, build_blob};

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
    /// `argv` / `env` would not fit procmgr's `CREATE_FROM_FILE` message:
    /// more than `u8::MAX` tokens or a packed blob over `ipc::ARGS_BLOB_MAX`
    /// bytes on the key's line, or (line `0`) both blobs together over
    /// `MSG_DATA_WORDS_MAX` words.
    TooLarge(usize, &'static str),
}

/// Bound one `argv` / `env` token list against the `CREATE_FROM_FILE` wire
/// format: the token count fits the label's 8-bit count field (else
/// `too_many`) and the NUL-packed blob fits `ipc::ARGS_BLOB_MAX` (else
/// `too_long`). Returns the blob's length in data words for the combined
/// check in [`parse`]. These are the limits `std::process::Command` applies
/// to its own spawns; svcmgr's launch path hands the packed words to an
/// asserting message builder, so an oversize recipe must fail here, at parse
/// time.
fn check_blob(
    lineno: usize,
    tokens: &[String],
    too_many: &'static str,
    too_long: &'static str,
) -> Result<usize, ParseError>
{
    if tokens.len() > usize::from(u8::MAX)
    {
        return Err(ParseError::TooLarge(lineno, too_many));
    }
    let (blob, _) = build_blob(tokens);
    if blob.len() > ipc::ARGS_BLOB_MAX
    {
        return Err(ParseError::TooLarge(lineno, too_long));
    }
    Ok(blob.len().div_ceil(8))
}

/// Bound a `binary` or `subtree:<path>` value against `ipc::MAX_PATH_LEN`.
/// svcmgr keeps both paths in fixed `MAX_PATH_LEN` buffers on the
/// `ServiceEntry` it restarts from (see
/// `services/svcmgr/docs/restart-protocol.md` § Recipe storage); a longer path
/// would launch once from the recipe string and then restart along a
/// truncated path, so the recipe is refused here instead.
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
/// child's working-directory cap inside its namespace. Namespace servers
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
/// violate the grammar or a semantic rule: a missing `=`, an unknown or
/// duplicated key, a missing mandatory key, a malformed value, an
/// inconsistent combination (`cwd` with `namespace = none`, a `cwd` outside
/// a `namespace = subtree:` path, `log_sink` with `seed`/`provides`, more
/// `seed` names than the bootstrap caps left after a provider's RECV,
/// `sched_max` below `priority`), a `binary` or
/// subtree path over `ipc::MAX_PATH_LEN` ([`ParseError::InvalidValue`]), or
/// `argv` / `env` that would not fit procmgr's `CREATE_FROM_FILE` message
/// ([`ParseError::TooLarge`]).
// too_many_lines: one pass over the `key = value` grammar whose per-key
// `match` is a flat table of short arms sharing the duplicate-key and
// mandatory-key bookkeeping locals; moving arms into helpers would thread
// those locals through every helper without buying structural clarity.
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
    let mut argv_words: usize = 0;
    let mut env_words: usize = 0;

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
                argv_words = check_blob(
                    lineno,
                    &argv,
                    "argv has more than 255 tokens",
                    "argv exceeds ARGS_BLOB_MAX bytes once NUL-packed",
                )?;
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
                    env.push(tok.to_owned());
                }
                env_words = check_blob(
                    lineno,
                    &env,
                    "env has more than 255 tokens",
                    "env exceeds ARGS_BLOB_MAX bytes once NUL-packed",
                )?;
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

    if let (NamespaceShape::Subtree { path, .. }, Some(dir)) = (&namespace, &cwd)
        && !cwd_within_subtree(dir, path)
    {
        return Err(ParseError::InvalidValue(
            0,
            "cwd must be the namespace subtree path or a path below it",
        ));
    }

    // One bootstrap round carries at most MSG_CAP_SLOTS_MAX caps, and a
    // provider's own service-endpoint RECV takes cap[0] ahead of the seeds.
    if seed.len() + usize::from(!provides.is_empty()) > MSG_CAP_SLOTS_MAX
    {
        return Err(ParseError::InvalidValue(
            0,
            "seed names (plus the provider RECV) exceed MSG_CAP_SLOTS_MAX bootstrap caps",
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
    // parse time instead of as a spawn failure.
    if let (Some(p), Some(m)) = (priority, sched_max)
        && m < p
    {
        return Err(ParseError::InvalidValue(0, "sched_max must be >= priority"));
    }

    // The CREATE_FROM_FILE body is one file-size word, the argv words, one
    // env-length word, and the env words; each blob fits ARGS_BLOB_MAX on
    // its own, but two full blobs do not fit the message together.
    if 1 + argv_words + 1 + env_words > MSG_DATA_WORDS_MAX
    {
        return Err(ParseError::TooLarge(
            0,
            "argv and env together exceed the CREATE_FROM_FILE message",
        ));
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
        check_path_len(
            lineno,
            path,
            "namespace subtree path exceeds MAX_PATH_LEN bytes",
        )?;
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
            Self::TooLarge(l, why) => write!(f, "line {l}: {why} (CREATE_FROM_FILE wire limit)"),
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

    /// Blob length that packs to half the data words left after the
    /// file-size and env-length words: two of these fill the message exactly.
    const HALF_BODY_BYTES: usize = (MSG_DATA_WORDS_MAX / 2 - 1) * 8;

    #[test]
    fn startup_blobs_at_the_wire_bounds_are_accepted()
    {
        let argv_full = parse_with(&argv_line(ipc::ARGS_BLOB_MAX)).expect("argv at ARGS_BLOB_MAX");
        assert_eq!(build_blob(&argv_full.argv).0.len(), ipc::ARGS_BLOB_MAX);
        let env_full = parse_with(&env_line(ipc::ARGS_BLOB_MAX)).expect("env at ARGS_BLOB_MAX");
        assert_eq!(build_blob(&env_full.env).0.len(), ipc::ARGS_BLOB_MAX);
        let both = format!(
            "{}{}",
            argv_line(HALF_BODY_BYTES),
            env_line(HALF_BODY_BYTES)
        );
        parse_with(&both).expect("argv + env filling the message exactly");
    }

    #[test]
    fn startup_blobs_over_the_wire_bounds_are_rejected()
    {
        assert!(matches!(
            parse_with(&argv_line(ipc::ARGS_BLOB_MAX + 1)),
            Err(ParseError::TooLarge(5, why)) if why.starts_with("argv exceeds")
        ));
        assert!(matches!(
            parse_with(&env_line(ipc::ARGS_BLOB_MAX + 1)),
            Err(ParseError::TooLarge(5, why)) if why.starts_with("env exceeds")
        ));
        // Each blob within ARGS_BLOB_MAX, together one word over the message.
        let both = format!(
            "{}{}",
            argv_line(HALF_BODY_BYTES + 8),
            env_line(HALF_BODY_BYTES)
        );
        assert!(matches!(
            parse_with(&both),
            Err(ParseError::TooLarge(0, why)) if why.starts_with("argv and env together")
        ));
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

    #[test]
    fn seeds_are_bounded_by_the_bootstrap_cap_slots_left_after_the_provider_recv()
    {
        let consumer = parse_with("seed = a b c d\n").expect("4 seeds fill a consumer round");
        assert_eq!(consumer.seed.len(), MSG_CAP_SLOTS_MAX);
        let provider = parse_with("provides = p\nseed = a b c\n").expect("RECV + 3 seeds");
        assert_eq!(provider.seed.len(), MSG_CAP_SLOTS_MAX - 1);
        for extra in ["seed = a b c d e\n", "provides = p\nseed = a b c d\n"]
        {
            assert!(matches!(
                parse_with(extra),
                Err(ParseError::InvalidValue(0, why)) if why.starts_with("seed names")
            ));
        }
    }

    #[test]
    fn more_than_255_startup_tokens_are_rejected()
    {
        // 256 one-byte tokens: the count field overflows before the blob
        // (512 bytes) is even considered.
        let argv = format!("argv = {}\n", "a ".repeat(256));
        assert!(matches!(
            parse_with(&argv),
            Err(ParseError::TooLarge(5, why)) if why.ends_with("255 tokens")
        ));
        let env = format!("env = {}\n", "k=v ".repeat(256));
        assert!(matches!(
            parse_with(&env),
            Err(ParseError::TooLarge(5, why)) if why.ends_with("255 tokens")
        ));
    }
}
