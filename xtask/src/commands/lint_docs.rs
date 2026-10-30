// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/commands/lint_docs.rs

//! Lint-docs command: mechanical checks of the documentation and source-header
//! rules in `docs/coding-standards.md` and `docs/documentation-standards.md`.
//!
//! Each rule prints `error <rule>: <path>:<line>: <message>` (or `warning`)
//! per violation; any error-level diagnostic fails the command. The rules
//! check only what a script can decide: column widths, header layout, the
//! `## Summarized By` section's shape and forward links, document
//! reachability, and that every name docs/testing.md § Coverage tiers lists
//! for its surface screens still names code or a file in the tree. Whether a
//! passage is a summary, or any other statement matches the code, stays with
//! the pre-merge review.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::path::{Component, Path};
use std::process::Command;

use anyhow::{Context, Result, bail};
use regex::Regex;

use crate::cli::LintDocsArgs;
use crate::context::Context as BuildContext;
use crate::util::{run_cmd_capture, step};

/// Project column limit for Markdown source (docs/coding-standards.md § Markdown).
const COLUMN_LIMIT: usize = 100;

/// Rule severity. A warning is printed and counted but does not fail the run.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Level
{
    Error,
    Warning,
}

impl fmt::Display for Level
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        f.write_str(match self
        {
            Level::Error => "error",
            Level::Warning => "warning",
        })
    }
}

/// The rules, with the level each runs at. `md-bare-cite` stays a warning
/// because its pattern also matches legitimate prose.
const RULES: &[(&str, Level)] = &[
    ("md-columns", Level::Error),
    ("src-header", Level::Error),
    ("md-summarized-by", Level::Error),
    ("md-backlink-forward", Level::Error),
    ("md-reachable", Level::Error),
    ("md-coverage-symbols", Level::Error),
    ("md-bare-cite", Level::Warning),
];

fn level_of(rule: &str) -> Level
{
    RULES
        .iter()
        .find(|(name, _)| *name == rule)
        .map_or(Level::Error, |(_, level)| *level)
}

/// One violation.
struct Diagnostic
{
    rule: &'static str,
    path: String,
    line: usize,
    message: String,
}

impl Diagnostic
{
    fn new(rule: &'static str, path: &str, line: usize, message: impl Into<String>) -> Self
    {
        Self {
            rule,
            path: path.to_owned(),
            line,
            message: message.into(),
        }
    }
}

/// A tracked file with its repository-relative path and contents.
struct SourceFile
{
    path: String,
    text: String,
}

/// Entry point for `cargo xtask lint-docs`.
pub fn run(ctx: &BuildContext, _args: &LintDocsArgs) -> Result<()>
{
    step("Linting documentation and source headers");
    let paths = tracked_files(&ctx.root)?;
    let files = read_files(&ctx.root, &paths)?;
    let markdown: Vec<&SourceFile> = files.iter().filter(|f| is_markdown(&f.path)).collect();
    let sources: Vec<&SourceFile> = files.iter().filter(|f| is_source(&f.path)).collect();

    let pat = Patterns::new()?;
    let mut diags = Vec::new();
    for file in &markdown
    {
        diags.extend(check_columns(&pat, file));
        diags.extend(check_bare_cites(&pat, file));
    }
    for file in &sources
    {
        diags.extend(check_header(file));
    }
    diags.extend(check_summarized_by(&pat, &markdown));
    diags.extend(check_reachable(&pat, &markdown));
    diags.extend(check_coverage_symbols(&markdown, &sources, &paths));

    report(&diags)
}

fn report(diags: &[Diagnostic]) -> Result<()>
{
    let mut errors = 0;
    let mut warnings = 0;
    for d in diags
    {
        let level = level_of(d.rule);
        match level
        {
            Level::Error => errors += 1,
            Level::Warning => warnings += 1,
        }
        println!("{level} {}: {}:{}: {}", d.rule, d.path, d.line, d.message);
    }
    step(&format!(
        "lint-docs: {errors} error(s), {warnings} warning(s)"
    ));
    if errors > 0
    {
        bail!("lint-docs found {errors} error(s)");
    }
    Ok(())
}

// ── File enumeration ──────────────────────────────────────────────────────────

fn tracked_files(root: &Path) -> Result<Vec<String>>
{
    let out = run_cmd_capture(
        Command::new("git")
            .args(["ls-files", "-z"])
            .current_dir(root),
    )?;
    Ok(out
        .split('\0')
        .filter(|p| !p.is_empty())
        .map(str::to_owned)
        .collect())
}

fn read_files(root: &Path, paths: &[String]) -> Result<Vec<SourceFile>>
{
    let mut files = Vec::new();
    for path in paths
    {
        if !(is_markdown(path) || is_source(path))
        {
            continue;
        }
        let text =
            std::fs::read_to_string(root.join(path)).with_context(|| format!("reading {path}"))?;
        files.push(SourceFile {
            path: path.clone(),
            text,
        });
    }
    Ok(files)
}

fn has_ext(path: &str, ext: &str) -> bool
{
    Path::new(path).extension().is_some_and(|e| e == ext)
}

fn is_markdown(path: &str) -> bool
{
    has_ext(path, "md")
}

fn is_source(path: &str) -> bool
{
    ["rs", "ld", "S", "sh"].iter().any(|ext| has_ext(path, ext))
}

/// Authoritative documents carry a `## Summarized By` section and must be
/// reachable from the root README (docs/documentation-standards.md § Document
/// Hierarchy and § Backlinks and Change Propagation). The root README is the
/// routing document; `.claude/` and `.github/` are outside the hierarchy;
/// per-tag release notes and their template are release records.
fn is_authoritative(path: &str) -> bool
{
    if path == "README.md" || path.starts_with(".claude/") || path.starts_with(".github/")
    {
        return false;
    }
    if path.starts_with("docs/releases/") && path != "docs/releases/README.md"
    {
        return false;
    }
    true
}

// ── md-columns ────────────────────────────────────────────────────────────────

/// The regular expressions the rules share, compiled once per run.
struct Patterns
{
    /// A line that is one link, image, or badge construct (optionally a list
    /// item, optionally followed by sentence punctuation or closing
    /// parentheses): the URL cannot break, so the column limit exempts it
    /// (docs/coding-standards.md § Markdown).
    link_only: Regex,
    /// A `(see <name>.md)` citation outside link syntax.
    bare_cite: Regex,
    /// A Markdown inline link, including a badge whose text is an image; group 1
    /// is the outer target.
    md_link: Regex,
}

impl Patterns
{
    fn new() -> Result<Self>
    {
        Ok(Self {
            link_only: Regex::new(
                r"^\s*(?:[-*+]\s+|\d+[.)]\s+)?(?:!?\[!?\[[^\]]*\]\([^)]*\)\]\([^)]*\)|!?\[[^\]]*\]\([^)]*\)|<?https?://\S+>?)[.,;:!?)]*\s*$",
            )?,
            bare_cite: Regex::new(r"\(see [A-Za-z0-9_./-]+\.md\)")?,
            md_link: Regex::new(r"\[(?:!\[[^\]]*\]\([^)]*\)|[^\]]*)\]\(([^)\s]+)\)")?,
        })
    }
}

fn check_columns(pat: &Patterns, file: &SourceFile) -> Vec<Diagnostic>
{
    let mut diags = Vec::new();
    let skip = front_matter_len(&file.text);
    for (idx, line) in file.text.lines().enumerate().skip(skip)
    {
        let width = line.chars().count();
        if width <= COLUMN_LIMIT
            || line.trim_start().starts_with('|')
            || pat.link_only.is_match(line)
        {
            continue;
        }
        diags.push(Diagnostic::new(
            "md-columns",
            &file.path,
            idx + 1,
            format!("{width} columns exceeds the {COLUMN_LIMIT}-column limit"),
        ));
    }
    diags
}

// ── md-bare-cite ──────────────────────────────────────────────────────────────

fn check_bare_cites(pat: &Patterns, file: &SourceFile) -> Vec<Diagnostic>
{
    let mut diags = Vec::new();
    for (idx, line) in prose_lines(&file.text)
    {
        if let Some(m) = pat.bare_cite.find(line)
        {
            diags.push(Diagnostic::new(
                "md-bare-cite",
                &file.path,
                idx + 1,
                format!("`{}` cites a document without linking it", m.as_str()),
            ));
        }
    }
    diags
}

/// Lines outside fenced code blocks, with their zero-based index. A fence
/// opens with a run of three or more backticks or tildes (a backtick run whose
/// info string contains a backtick is not a fence) and closes only on a run of
/// the same character at least as long with nothing after it but whitespace (a
/// line carrying an info string is content).
fn prose_lines(text: &str) -> impl Iterator<Item = (usize, &str)>
{
    let mut open: Option<(char, usize)> = None;
    text.lines().enumerate().filter(move |(_, line)| {
        let trimmed = line.trim_start();
        let fence = trimmed
            .chars()
            .next()
            .filter(|c| *c == '`' || *c == '~')
            .map(|c| (c, trimmed.chars().take_while(|x| *x == c).count()));
        match (open, fence)
        {
            (None, Some((c, n))) if n >= 3 && (c != '`' || !trimmed[n..].contains('`')) =>
            {
                open = Some((c, n));
                false
            }
            (Some((oc, on)), Some((c, n)))
                if c == oc && n >= on && trimmed[n..].trim().is_empty() =>
            {
                open = None;
                false
            }
            (Some(_), _) => false,
            (None, _) => true,
        }
    })
}

/// Number of leading lines a YAML front-matter block occupies (`---` on the
/// first line through the next `---` line); zero when there is none. Front
/// matter is metadata, not Markdown source.
fn front_matter_len(text: &str) -> usize
{
    let mut lines = text.lines();
    if lines.next() != Some("---")
    {
        return 0;
    }
    lines.position(|l| l == "---").map_or(0, |i| i + 2)
}

// ── src-header ────────────────────────────────────────────────────────────────

/// Comment syntax of a source file's header (docs/coding-standards.md § File Headers).
enum CommentStyle
{
    /// `// ...` lines; the description is `//!` (Rust) or `//` (assembly).
    Line,
    /// `/* ... */` block; header lines are ` * ...`.
    Block,
    /// `# ...` lines, after an optional shebang.
    Hash,
}

fn comment_style(path: &str) -> CommentStyle
{
    if has_ext(path, "ld")
    {
        CommentStyle::Block
    }
    else if has_ext(path, "sh")
    {
        CommentStyle::Hash
    }
    else
    {
        CommentStyle::Line
    }
}

fn check_header(file: &SourceFile) -> Vec<Diagnostic>
{
    match header_violation(&file.path, &file.text)
    {
        Some((line, message)) => vec![Diagnostic::new("src-header", &file.path, line, message)],
        None => Vec::new(),
    }
}

/// The first header violation in `text`, as (1-based line, message).
fn header_violation(path: &str, text: &str) -> Option<(usize, String)>
{
    let lines: Vec<&str> = text.lines().collect();
    let (prefix, start) = match comment_style(path)
    {
        CommentStyle::Line => ("//", 0),
        CommentStyle::Block =>
        {
            if lines.first().map(|l| l.trim()) != Some("/*")
            {
                return Some((1, "block-comment header must open with `/*`".into()));
            }
            (" *", 1)
        }
        CommentStyle::Hash =>
        {
            let shebang = lines.first().is_some_and(|l| l.starts_with("#!"));
            ("#", usize::from(shebang))
        }
    };
    let spdx = format!("{prefix} SPDX-License-Identifier:");
    if !lines.get(start).is_some_and(|l| l.starts_with(&spdx))
    {
        return Some((
            start + 1,
            "file must open with the SPDX license line".into(),
        ));
    }
    // The license block ends at the first blank line (a bare ` *` for blocks).
    let blank = |l: &str| l.trim().is_empty() || (prefix == " *" && l.trim() == "*");
    let Some(end) = lines[start..]
        .iter()
        .position(|l| blank(l))
        .map(|i| start + i)
    else
    {
        return Some((
            lines.len(),
            "license block is not followed by a blank line".into(),
        ));
    };
    // The path line follows the license block after exactly one blank line.
    let expected = format!("{prefix} {path}");
    let path_idx = end + 1;
    let Some(path_line) = lines.get(path_idx)
    else
    {
        return Some((end + 1, format!("missing path line `{expected}`")));
    };
    if blank(path_line)
    {
        return Some((
            path_idx + 1,
            "exactly one blank line separates the license block from the path line".into(),
        ));
    }
    if lines[path_idx] != expected
    {
        return Some((path_idx + 1, format!("expected path line `{expected}`")));
    }
    if has_ext(path, "rs")
    {
        if !lines.get(path_idx + 1).is_some_and(|l| l.trim().is_empty())
        {
            return Some((
                path_idx + 2,
                "path line must be followed by a blank line".into(),
            ));
        }
        // The description opens the line after the blank.
        match lines.get(path_idx + 2)
        {
            Some(l) if l.starts_with("//!") =>
            {}
            Some(l) if l.starts_with("#![") =>
            {
                return Some((
                    path_idx + 3,
                    "crate attribute precedes the `//!` block".into(),
                ));
            }
            Some(l) if l.trim().is_empty() =>
            {
                return Some((
                    path_idx + 3,
                    "exactly one blank line separates the path line from the `//!` block".into(),
                ));
            }
            _ => return Some((path_idx + 3, "missing `//!` description".into())),
        }
    }
    None
}

// ── md-summarized-by, md-backlink-forward ────────────────────────────────────

/// Prose paragraphs of `text` outside fenced code: each maximal run of
/// consecutive non-blank prose lines joined with single spaces, so a link whose
/// text wraps across lines is matched whole.
fn prose_paragraphs(text: &str) -> Vec<String>
{
    let mut paragraphs: Vec<String> = Vec::new();
    let mut last: Option<usize> = None;
    for (idx, line) in prose_lines(text)
    {
        if line.trim().is_empty()
        {
            last = None;
            continue;
        }
        match (last, paragraphs.last_mut())
        {
            (Some(prev), Some(paragraph)) if prev + 1 == idx =>
            {
                paragraph.push(' ');
                paragraph.push_str(line.trim());
            }
            _ => paragraphs.push(line.trim().to_owned()),
        }
        last = Some(idx);
    }
    paragraphs
}

/// A link target resolved against `dir`, the directory of the document holding
/// it: `None` for an external URL, an in-page anchor, or a `..` that climbs past
/// the repository root.
fn resolve_link(dir: &Path, raw: &str) -> Option<String>
{
    let target = raw.split('#').next().unwrap_or("");
    if target.is_empty() || target.contains("://") || target.starts_with("mailto:")
    {
        return None;
    }
    normalize(&dir.join(target))
}

/// Link targets in `text` outside fenced code that [`resolve_link`] resolves to
/// repository-relative paths; the rest are omitted.
fn link_targets(pat: &Patterns, path: &str, text: &str) -> BTreeSet<String>
{
    let dir = Path::new(path).parent().unwrap_or_else(|| Path::new(""));
    let mut out = BTreeSet::new();
    for paragraph in prose_paragraphs(text)
    {
        for cap in pat.md_link.captures_iter(&paragraph)
        {
            if let Some(resolved) = resolve_link(dir, &cap[1])
            {
                out.insert(resolved);
            }
        }
    }
    out
}

/// Collapse `.` and `..` components without touching the filesystem; `None` when a `..`
/// climbs past the repository root.
fn normalize(path: &Path) -> Option<String>
{
    let mut parts: Vec<String> = Vec::new();
    for component in path.components()
    {
        match component
        {
            Component::ParentDir =>
            {
                parts.pop()?;
            }
            Component::Normal(s) => parts.push(s.to_string_lossy().into_owned()),
            _ =>
            {}
        }
    }
    Some(parts.join("/"))
}

/// A section violation: the 1-based line it anchors to and the message.
type Violation = (usize, String);

/// The body of the document's `## Summarized By` section, joined into one line,
/// with the heading's 1-based line number; `Err` when the section is missing,
/// does not follow a `---` separator, or is not the last section.
fn summarized_by_section(text: &str) -> std::result::Result<(usize, String), Violation>
{
    let lines: Vec<(usize, &str)> = prose_lines(text).collect();
    let heading = lines
        .iter()
        .rposition(|(_, l)| l.trim_end() == "## Summarized By")
        .ok_or((
            text.lines().count(),
            "missing `## Summarized By` section".to_owned(),
        ))?;
    let line = lines[heading].0 + 1;
    let before = lines[..heading]
        .iter()
        .rev()
        .map(|(_, l)| *l)
        .find(|l| !l.trim().is_empty());
    if before != Some("---")
    {
        return Err((
            line,
            "`## Summarized By` must follow a `---` separator".into(),
        ));
    }
    let body: Vec<&str> = lines[heading + 1..]
        .iter()
        .map(|(_, l)| *l)
        .filter(|l| !l.trim().is_empty())
        .collect();
    if body.iter().any(|l| l.starts_with('#'))
    {
        return Err((line, "`## Summarized By` must be the last section".into()));
    }
    Ok((line, body.join(" ")))
}

/// The entries of the document's `## Summarized By` section, resolved to
/// repository-relative paths; empty for `None`. `Err` describes the first
/// violation: a missing or misplaced section, a body holding neither links nor
/// `None`, text other than links, or an entry [`resolve_link`] cannot resolve.
fn summarized_by(
    pat: &Patterns,
    path: &str,
    text: &str,
) -> std::result::Result<BTreeSet<String>, Violation>
{
    let (line, body) = summarized_by_section(text)?;
    let body = body.trim();
    if body == "None"
    {
        return Ok(BTreeSet::new());
    }
    if pat.md_link.find(body).is_none()
    {
        return Err((
            line,
            "`## Summarized By` holds neither links nor `None`".into(),
        ));
    }
    if !pat
        .md_link
        .replace_all(body, "")
        .replace(',', "")
        .trim()
        .is_empty()
    {
        return Err((
            line,
            "`## Summarized By` holds text other than links or `None`".into(),
        ));
    }
    let dir = Path::new(path).parent().unwrap_or_else(|| Path::new(""));
    pat.md_link
        .captures_iter(body)
        .map(|cap| {
            resolve_link(dir, &cap[1]).ok_or_else(|| {
                (
                    line,
                    format!(
                        "Summarized By entry `{}` does not resolve to a repository document",
                        &cap[1]
                    ),
                )
            })
        })
        .collect()
}

fn check_summarized_by(pat: &Patterns, markdown: &[&SourceFile]) -> Vec<Diagnostic>
{
    let links: BTreeMap<&str, BTreeSet<String>> = markdown
        .iter()
        .map(|f| (f.path.as_str(), link_targets(pat, &f.path, &f.text)))
        .collect();
    let mut diags = Vec::new();
    for file in markdown.iter().filter(|f| is_authoritative(&f.path))
    {
        let entries = match summarized_by(pat, &file.path, &file.text)
        {
            Ok(entries) => entries,
            Err((line, message)) =>
            {
                diags.push(Diagnostic::new(
                    "md-summarized-by",
                    &file.path,
                    line,
                    message,
                ));
                continue;
            }
        };
        let line = file.text.lines().count();
        for entry in entries
        {
            match links.get(entry.as_str())
            {
                None => diags.push(Diagnostic::new(
                    "md-backlink-forward",
                    &file.path,
                    line,
                    format!("Summarized By entry `{entry}` is not a tracked document"),
                )),
                Some(targets) if !targets.contains(&file.path) => diags.push(Diagnostic::new(
                    "md-backlink-forward",
                    &file.path,
                    line,
                    format!("Summarized By entry `{entry}` does not link this document"),
                )),
                Some(_) =>
                {}
            }
        }
    }
    diags
}

// ── md-reachable ──────────────────────────────────────────────────────────────

fn check_reachable(pat: &Patterns, markdown: &[&SourceFile]) -> Vec<Diagnostic>
{
    let links: BTreeMap<&str, BTreeSet<String>> = markdown
        .iter()
        .filter(|f| f.path == "README.md" || is_authoritative(&f.path))
        .map(|f| (f.path.as_str(), link_targets(pat, &f.path, &f.text)))
        .collect();
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let mut queue: VecDeque<&str> = VecDeque::from(["README.md"]);
    while let Some(path) = queue.pop_front()
    {
        if !seen.insert(path)
        {
            continue;
        }
        for target in links.get(path).into_iter().flatten()
        {
            if let Some((key, _)) = links.get_key_value(target.as_str())
            {
                queue.push_back(key);
            }
        }
    }
    let mut diags = Vec::new();
    for file in markdown.iter().filter(|f| is_authoritative(&f.path))
    {
        if !seen.contains(file.path.as_str())
        {
            diags.push(Diagnostic::new(
                "md-reachable",
                &file.path,
                1,
                "not reachable by links from the root README.md",
            ));
        }
    }
    diags.extend(check_direct_links(markdown, &links));
    diags
}

/// The root README links every `docs/*.md`; a component README links every
/// document in its own `docs/` (docs/documentation-standards.md
/// § Discoverability and Linking).
fn check_direct_links(
    markdown: &[&SourceFile],
    links: &BTreeMap<&str, BTreeSet<String>>,
) -> Vec<Diagnostic>
{
    let mut diags = Vec::new();
    let readmes: Vec<&str> = markdown
        .iter()
        .map(|f| f.path.as_str())
        .filter(|p| *p == "README.md" || p.ends_with("/README.md"))
        .collect();
    for readme in readmes
    {
        let dir = readme.trim_end_matches("README.md");
        let docs_dir = format!("{dir}docs/");
        for doc in markdown.iter().filter(|f| is_authoritative(&f.path))
        {
            let in_docs = doc.path.starts_with(&docs_dir)
                && !doc.path[docs_dir.len()..].contains('/')
                && doc.path != readme;
            if in_docs && !links.get(readme).is_some_and(|t| t.contains(&doc.path))
            {
                diags.push(Diagnostic::new(
                    "md-reachable",
                    readme,
                    1,
                    format!("does not link `{}` in its docs/ directory", doc.path),
                ));
            }
        }
    }
    diags
}

// ── md-coverage-symbols ───────────────────────────────────────────────────────

/// The document whose § Coverage tiers lists the CPU-count and memory surfaces
/// by name (docs/testing.md § Coverage tiers).
const COVERAGE_DOC: &str = "docs/testing.md";

/// The section heading and the paragraph leads that bound the surface list: from
/// the Boundary surface paragraph through the Memory surface screen, up to the
/// Repeat count paragraph.
const COVERAGE_HEADING: &str = "## Coverage tiers";
const SURFACE_START: &str = "**Boundary surface.**";
const SURFACE_END: &str = "**Repeat count.**";

/// What a listed name must resolve to.
#[derive(Debug, PartialEq, Eq)]
enum NameKind
{
    /// A Rust item or field path, as a regular expression over source text.
    Symbol,
    /// A tracked file path, `*` matching within one path component.
    Path,
}

/// One name the surface list states.
#[derive(Debug)]
struct ListedName
{
    /// 1-based line of `COVERAGE_DOC` the name is stated on.
    line: usize,
    /// The name as the diagnostic shows it.
    shown: String,
    /// For a symbol, the regular expression the name stands for; for a path,
    /// the path pattern.
    pattern: String,
    kind: NameKind,
}

/// The 0-based line range `[start, end)` of the surface list in `text`, or a
/// message naming the bound that is missing.
fn surface_range(text: &str) -> std::result::Result<(usize, usize), String>
{
    let lines: Vec<&str> = text.lines().collect();
    let heading = lines
        .iter()
        .position(|l| l.trim_end() == COVERAGE_HEADING)
        .ok_or_else(|| format!("no `{COVERAGE_HEADING}` heading"))?;
    let section_end = lines[heading + 1..]
        .iter()
        .position(|l| l.starts_with("## "))
        .map_or(lines.len(), |i| heading + 1 + i);
    let find = |from: usize, lead: &str| {
        lines[from..section_end]
            .iter()
            .position(|l| l.starts_with(lead))
            .map(|i| from + i)
            .ok_or_else(|| format!("no paragraph starting `{lead}` in `{COVERAGE_HEADING}`"))
    };
    let start = find(heading + 1, SURFACE_START)?;
    let end = find(start + 1, SURFACE_END)?;
    Ok((start, end))
}

/// Split `s` on `|` outside parentheses and brackets.
fn split_alternation(s: &str) -> Vec<&str>
{
    let mut parts = Vec::new();
    let mut depth = 0usize;
    let mut in_class = false;
    let mut escaped = false;
    let mut begin = 0;
    for (i, c) in s.char_indices()
    {
        if escaped
        {
            escaped = false;
            continue;
        }
        match c
        {
            '\\' => escaped = true,
            '[' if !in_class => in_class = true,
            ']' if in_class => in_class = false,
            '(' if !in_class => depth += 1,
            ')' if !in_class => depth = depth.saturating_sub(1),
            '|' if !in_class && depth == 0 =>
            {
                parts.push(&s[begin..i]);
                begin = i + 1;
            }
            _ =>
            {}
        }
    }
    parts.push(&s[begin..]);
    parts
}

/// Expand the groups of one screen alternative into the concrete patterns it
/// lists: `(a|b)` into each option, `(x)?` into the pattern with and without it.
/// Character classes stay as they are, so `IPI_VECTOR_[A-Z_]+` stays one
/// pattern that some name must match.
fn expand_groups(alt: &str) -> Vec<String>
{
    let bytes = alt.as_bytes();
    let mut open = None;
    let mut depth = 0usize;
    let mut in_class = false;
    let mut i = 0;
    while i < bytes.len()
    {
        match bytes[i]
        {
            b'\\' => i += 1,
            b'[' if !in_class => in_class = true,
            b']' if in_class => in_class = false,
            b'(' if !in_class =>
            {
                if depth == 0
                {
                    open = Some(i);
                }
                depth += 1;
            }
            b')' if !in_class && depth > 0 =>
            {
                depth -= 1;
                if depth == 0
                {
                    let start = open.unwrap_or(0);
                    let prefix = &alt[..start];
                    let inner = &alt[start + 1..i];
                    let optional = bytes.get(i + 1) == Some(&b'?');
                    let suffix = &alt[i + 1 + usize::from(optional)..];
                    let mut options: Vec<&str> = split_alternation(inner);
                    if optional
                    {
                        options.insert(0, "");
                    }
                    return options
                        .into_iter()
                        .flat_map(|o| expand_groups(&format!("{prefix}{o}{suffix}")))
                        .collect();
                }
            }
            _ =>
            {}
        }
        i += 1;
    }
    vec![alt.to_owned()]
}

/// The names a screen-variable line (`S='a|b'`, `S="$S|c"`, and the same for
/// `M`) lists, or `None` when the line assigns no screen variable.
fn screen_names(line: &str) -> Option<Vec<String>>
{
    let (var, rest) = line.trim().split_once('=')?;
    if var != "S" && var != "M"
    {
        return None;
    }
    let quote = rest.chars().next().filter(|c| *c == '\'' || *c == '"')?;
    let value = rest.strip_prefix(quote)?.strip_suffix(quote)?;
    let value = value.strip_prefix(&format!("${var}|")).unwrap_or(value);
    Some(
        split_alternation(value)
            .into_iter()
            .filter(|a| !a.is_empty())
            .flat_map(expand_groups)
            .collect(),
    )
}

/// Whether `s` is a Rust item or field path as the prose names one
/// (`frame_map::init`, `info.cpu_count`), optionally ending in the `_*`
/// family glob (`init_ap_*`).
fn is_symbol_span(s: &str) -> bool
{
    let s = s.strip_suffix("_*").unwrap_or(s);
    !s.is_empty()
        && s.replace("::", ".").split('.').all(|seg| {
            seg.chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
                && seg.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        })
}

/// Whether `s` is a path to a Rust source, possibly with `*`: a repository
/// path, or a bare file name (`idt.rs`).
fn is_path_span(s: &str) -> bool
{
    has_ext(s, "rs")
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "_-./*".contains(c))
}

/// The regular expression a prose symbol span stands for.
fn prose_symbol_pattern(s: &str) -> String
{
    match s.strip_suffix("_*")
    {
        Some(stem) => format!("{}_[A-Za-z0-9_]+", regex::escape(stem)),
        None => regex::escape(s),
    }
}

/// Every name the surface list of `text` states, from the prose code spans,
/// the screen variables, and the whole-surface file paths inside the screens.
fn listed_names(text: &str) -> std::result::Result<Vec<ListedName>, String>
{
    let (start, end) = surface_range(text)?;
    let mut names = Vec::new();
    let mut in_fence = false;
    let mut spans = CodeSpans::default();
    for (idx, line) in text.lines().enumerate().take(end).skip(start)
    {
        if line.trim_start().starts_with("```")
        {
            in_fence = !in_fence;
        }
        else if in_fence
        {
            names.extend(fenced_names(idx + 1, line));
        }
        else
        {
            names.extend(
                spans
                    .read(idx + 1, line)
                    .into_iter()
                    .filter_map(|(at, content)| prose_name(at, &content)),
            );
        }
    }
    Ok(names)
}

/// The names one line inside a screen fence states: a screen variable's
/// alternatives, or the `.rs` paths among its words.
fn fenced_names(line_no: usize, line: &str) -> Vec<ListedName>
{
    if let Some(found) = screen_names(line)
    {
        return found
            .into_iter()
            .map(|p| ListedName {
                line: line_no,
                shown: p.clone(),
                pattern: p,
                kind: NameKind::Symbol,
            })
            .collect();
    }
    line.split_whitespace()
        .map(|token| token.trim_matches(|c| c == '\'' || c == '"'))
        .filter(|token| is_path_span(token))
        .map(|token| ListedName {
            line: line_no,
            shown: token.to_owned(),
            pattern: token.to_owned(),
            kind: NameKind::Path,
        })
        .collect()
}

/// Inline code spans of prose read line by line; a span may wrap across lines
/// but not across a paragraph break.
#[derive(Default)]
struct CodeSpans
{
    /// The open span: its 1-based start line and its text so far.
    open: Option<(usize, String)>,
}

impl CodeSpans
{
    /// Feed one prose line; returns the spans it closes, each with its start line.
    fn read(&mut self, line_no: usize, line: &str) -> Vec<(usize, String)>
    {
        let mut closed = Vec::new();
        if line.trim().is_empty()
        {
            self.open = None;
            return closed;
        }
        for (i, piece) in line.split('`').enumerate()
        {
            if i > 0
            {
                // A backtick: close the open span, or open one.
                match self.open.take()
                {
                    Some(span) => closed.push(span),
                    None => self.open = Some((line_no, String::new())),
                }
            }
            if let Some((_, content)) = self.open.as_mut()
            {
                if i == 0 && !content.is_empty()
                {
                    content.push(' ');
                }
                content.push_str(piece);
            }
        }
        closed
    }
}

/// The listed name a prose code span states, if it is one.
fn prose_name(line: usize, content: &str) -> Option<ListedName>
{
    let content = content.trim();
    let (kind, pattern) = if is_path_span(content)
    {
        (NameKind::Path, content.to_owned())
    }
    else if is_symbol_span(content)
    {
        (NameKind::Symbol, prose_symbol_pattern(content))
    }
    else
    {
        return None;
    };
    Some(ListedName {
        line,
        shown: content.to_owned(),
        pattern,
        kind,
    })
}

/// `text` with every `//` comment removed, from the `//` to the end of its line.
/// A `//` inside a string literal (a URL) also cuts the line; that can only hide
/// a name and fail the check, never pass a name that is gone.
fn strip_line_comments(text: &str) -> String
{
    let mut out = String::with_capacity(text.len());
    for line in text.lines()
    {
        out.push_str(line.split_once("//").map_or(line, |(code, _)| code));
        out.push('\n');
    }
    out
}

/// Whether the path pattern `pattern` (`*` within one component) names a
/// tracked file; a pattern without `/` is a file name in any directory.
fn path_resolves(pattern: &str, tracked: &[String]) -> bool
{
    let want: Vec<&str> = pattern.split('/').collect();
    tracked.iter().any(|path| {
        let have: Vec<&str> = path.split('/').collect();
        if want.len() == 1
        {
            have.last().is_some_and(|name| glob_matches(want[0], name))
        }
        else
        {
            want.len() == have.len() && want.iter().zip(&have).all(|(w, h)| glob_matches(w, h))
        }
    })
}

/// Whether `name` matches `glob`, where `*` matches any run of characters and
/// every other character matches itself.
fn glob_matches(glob: &str, name: &str) -> bool
{
    match glob.split_once('*')
    {
        None => glob == name,
        Some((head, rest)) => name.strip_prefix(head).is_some_and(|tail| {
            tail.char_indices()
                .map(|(i, _)| i)
                .chain(std::iter::once(tail.len()))
                .any(|i| glob_matches(rest, &tail[i..]))
        }),
    }
}

/// Whether the symbol pattern `pattern` matches, as a whole word, in `code`.
fn symbol_resolves(pattern: &str, code: &str) -> std::result::Result<bool, regex::Error>
{
    Ok(Regex::new(&format!(r"(?-u:\b)(?:{pattern})(?-u:\b)"))?.is_match(code))
}

/// Why `name` fails to resolve, or `None` when it resolves.
fn unresolved(name: &ListedName, code: &str, tracked: &[String]) -> Option<String>
{
    match name.kind
    {
        NameKind::Path =>
        {
            (!path_resolves(&name.pattern, tracked)).then(|| "names no tracked file".to_owned())
        }
        NameKind::Symbol => match symbol_resolves(&name.pattern, code)
        {
            Ok(true) => None,
            Ok(false) => Some("names nothing in the code of a tracked Rust source".to_owned()),
            // A syntax error renders as the pattern, a caret line, and the
            // reason; the reason is the last line.
            Err(err) => Some(format!(
                "is not a valid regular expression ({})",
                err.to_string().lines().last().unwrap_or_default().trim()
            )),
        },
    }
}

/// The listed names of docs/testing.md § Coverage tiers resolve: every symbol
/// the surface list names matches, as a whole word, the code of a tracked Rust
/// source outside `xtask/` with `//` comments stripped, and every listed path
/// names a tracked file. A name left only in a `//` comment, or in a file that
/// is gone, is one the screen can no longer find.
fn check_coverage_symbols(
    markdown: &[&SourceFile],
    sources: &[&SourceFile],
    tracked: &[String],
) -> Vec<Diagnostic>
{
    let rule = "md-coverage-symbols";
    let Some(doc) = markdown.iter().find(|f| f.path == COVERAGE_DOC)
    else
    {
        return vec![Diagnostic::new(
            rule,
            COVERAGE_DOC,
            1,
            "not a tracked document",
        )];
    };
    let names = match listed_names(&doc.text)
    {
        Ok(names) => names,
        Err(message) => return vec![Diagnostic::new(rule, COVERAGE_DOC, 1, message)],
    };
    let code: String = sources
        .iter()
        .filter(|f| has_ext(&f.path, "rs") && !f.path.starts_with("xtask/"))
        .map(|f| strip_line_comments(&f.text))
        .collect();
    names
        .iter()
        .filter_map(|name| {
            unresolved(name, &code, tracked).map(|why| {
                Diagnostic::new(
                    rule,
                    &doc.path,
                    name.line,
                    format!("`{}`, listed in § Coverage tiers, {why}", name.shown),
                )
            })
        })
        .collect()
}

#[cfg(test)]
mod tests
{
    use super::*;

    fn pat() -> Patterns
    {
        Patterns::new().unwrap()
    }

    fn md(path: &str, text: &str) -> SourceFile
    {
        SourceFile {
            path: path.into(),
            text: text.into(),
        }
    }

    #[test]
    fn over_limit_prose_is_reported_but_table_rows_and_badges_are_exempt()
    {
        let long = "x".repeat(101);
        let text = format!(
            "{long}\n| {long} |\n[![b](https://a/{long})](https://b)\n- [t](x.md#{long}).\n"
        );
        let diags = check_columns(&pat(), &md("a.md", &text));
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].line, 1);
    }

    const MULTI_LINE_LICENSE: &str = "// SPDX-License-Identifier: GPL-2.0-only AND OFL-1.1\n// Copyright (C) 2026 X\n//\n// Code: GPL.\n\n// a/b.rs\n\n//! Doc.\n\n#![no_std]\n";

    #[test]
    fn header_accepts_multi_line_license_block()
    {
        assert_eq!(header_violation("a/b.rs", MULTI_LINE_LICENSE), None);
    }

    #[test]
    fn header_rejects_a_path_line_naming_another_file()
    {
        let wrong = MULTI_LINE_LICENSE.replace("// a/b.rs", "// b.rs");
        assert_eq!(
            header_violation("a/b.rs", &wrong),
            Some((6, "expected path line `// a/b.rs`".to_owned()))
        );
    }

    #[test]
    fn header_rejects_attribute_before_doc()
    {
        let attr_first = "// SPDX-License-Identifier: GPL-2.0-only\n// (C)\n\n// a.rs\n\n#![no_std]\n\n//! Doc.\n";
        assert_eq!(
            header_violation("a.rs", attr_first),
            Some((6, "crate attribute precedes the `//!` block".to_owned()))
        );
    }

    #[test]
    fn header_rejects_license_block_without_blank_line()
    {
        let no_blank = "// SPDX-License-Identifier: GPL-2.0-only\n// (C)\n//! Doc.\nfn main() {}\n";
        assert_eq!(
            header_violation("a.rs", no_blank),
            Some((
                4,
                "license block is not followed by a blank line".to_owned()
            ))
        );
    }

    #[test]
    fn header_requires_path_line_first_after_license()
    {
        let late =
            "// SPDX-License-Identifier: GPL-2.0-only\n// (C)\n\n// note\n\n// a.rs\n\n//! Doc.\n";
        assert_eq!(
            header_violation("a.rs", late),
            Some((4, "expected path line `// a.rs`".to_owned()))
        );
    }

    #[test]
    fn header_rejects_a_doubled_blank_line_before_the_path_line()
    {
        let doubled = "// SPDX-License-Identifier: GPL-2.0-only\n// (C)\n\n\n// a.rs\n\n//! Doc.\n";
        assert_eq!(
            header_violation("a.rs", doubled),
            Some((
                4,
                "exactly one blank line separates the license block from the path line".to_owned()
            ))
        );
    }

    #[test]
    fn header_rejects_description_adjacent_to_the_path_line()
    {
        let adjacent = "// SPDX-License-Identifier: GPL-2.0-only\n// (C)\n\n// a.rs\n//! Doc.\n";
        assert_eq!(
            header_violation("a.rs", adjacent),
            Some((5, "path line must be followed by a blank line".to_owned()))
        );
    }

    #[test]
    fn header_rejects_a_comment_between_the_path_line_and_the_description()
    {
        let note_first =
            "// SPDX-License-Identifier: GPL-2.0-only\n// (C)\n\n// a.rs\n\n// note\n//! Doc.\n";
        assert_eq!(
            header_violation("a.rs", note_first),
            Some((6, "missing `//!` description".to_owned()))
        );
    }

    #[test]
    fn header_rejects_a_doubled_blank_line_before_the_description()
    {
        let doubled = "// SPDX-License-Identifier: GPL-2.0-only\n// (C)\n\n// a.rs\n\n\n//! Doc.\n";
        assert_eq!(
            header_violation("a.rs", doubled),
            Some((
                6,
                "exactly one blank line separates the path line from the `//!` block".to_owned()
            ))
        );
    }

    #[test]
    fn header_rejects_missing_path_line()
    {
        let eof = "// SPDX-License-Identifier: GPL-2.0-only\n// (C)\n\n";
        assert_eq!(
            header_violation("a.rs", eof),
            Some((3, "missing path line `// a.rs`".to_owned()))
        );
    }

    #[test]
    fn front_matter_is_absent_without_a_leading_rule()
    {
        assert_eq!(front_matter_len("# T\n"), 0);
    }

    #[test]
    fn closed_front_matter_spans_its_lines()
    {
        assert_eq!(front_matter_len("---\nname: x\n---\n# T\n"), 3);
    }

    #[test]
    fn unclosed_front_matter_is_not_skipped()
    {
        assert_eq!(front_matter_len("---\nname: x\n# T\n"), 0);
    }

    #[test]
    fn image_only_and_plus_marked_link_lines_are_exempt()
    {
        let long = "x".repeat(101);
        let text = format!("![a](https://e/{long})\n+ [t](x.md#{long})\n");
        assert!(check_columns(&pat(), &md("a.md", &text)).is_empty());
    }

    #[test]
    fn link_lines_with_paren_list_markers_or_question_and_exclamation_marks_are_exempt()
    {
        let long = "x".repeat(101);
        let text = format!("1) [t](x.md#{long})?\n2. [t](x.md#{long})!\n");
        assert!(check_columns(&pat(), &md("a.md", &text)).is_empty());
    }

    #[test]
    fn badge_links_resolve_to_their_outer_target()
    {
        let targets = link_targets(&pat(), "d/x.md", "[![b](https://img)](../a.md)\n");
        assert_eq!(targets, BTreeSet::from(["a.md".to_owned()]));
    }

    #[test]
    fn front_matter_is_exempt_from_the_column_limit()
    {
        let long = "x".repeat(101);
        let text = format!("---\nname: {long}\n---\n\n{long}\n");
        let diags = check_columns(&pat(), &md("a.md", &text));
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].line, 5);
    }

    #[test]
    fn fences_close_only_on_a_matching_run()
    {
        let text = "````\n```\n(see x.md)\n```\n````\n(see y.md)\n~~~\n(see z.md)\n~~~\n";
        let diags = check_bare_cites(&pat(), &md("a.md", text));
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].line, 6);
    }

    #[test]
    fn header_handles_block_comments_and_shebangs()
    {
        let ld = "/*\n * SPDX-License-Identifier: GPL-2.0-only\n * (C)\n *\n * k/x.ld\n */\n";
        assert_eq!(header_violation("k/x.ld", ld), None);
        let sh = "#!/bin/sh\n# SPDX-License-Identifier: GPL-2.0-only\n# (C)\n\n# t/run.sh\n";
        assert_eq!(header_violation("t/run.sh", sh), None);
    }

    #[test]
    fn summarized_by_parses_links_none_and_rejects_malformed_sections()
    {
        let good = "# T\n\nBody.\n\n---\n\n## Summarized By\n\n[A](../a.md),\n[B](b.md)\n";
        let entries = summarized_by(&pat(), "d/x.md", good).unwrap();
        assert_eq!(
            entries,
            BTreeSet::from(["a.md".to_owned(), "d/b.md".to_owned()])
        );
        let none = "# T\n\n---\n\n## Summarized By\n\nNone\n";
        assert!(summarized_by(&pat(), "d/x.md", none).unwrap().is_empty());
        let no_rule = "# T\n\n## Summarized By\n\nNone\n";
        assert!(summarized_by(&pat(), "d/x.md", no_rule).is_err());
        let trailing = "# T\n\n---\n\n## Summarized By\n\nNone\n\n## More\n";
        assert!(summarized_by(&pat(), "d/x.md", trailing).is_err());
        let missing = "# T\n\nBody.\n";
        assert!(summarized_by(&pat(), "d/x.md", missing).is_err());
    }

    #[test]
    fn summarized_by_ignores_the_example_inside_a_fence()
    {
        let text = "# T\n\n```markdown\n## Summarized By\n\n[X](x.md)\n```\n\n---\n\n## Summarized By\n\nNone\n";
        assert!(summarized_by(&pat(), "d/x.md", text).unwrap().is_empty());
    }

    #[test]
    fn backlink_forward_requires_the_summarizer_to_link_back()
    {
        let doc = md("docs/a.md", "# A\n\n---\n\n## Summarized By\n\n[B](b.md)\n");
        let linking = md(
            "docs/b.md",
            "# B\n\nSee [A](a.md).\n\n---\n\n## Summarized By\n\nNone\n",
        );
        assert!(check_summarized_by(&pat(), &[&doc, &linking]).is_empty());
        let silent = md("docs/b.md", "# B\n\n---\n\n## Summarized By\n\nNone\n");
        let diags = check_summarized_by(&pat(), &[&doc, &silent]);
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].rule, "md-backlink-forward");
    }

    #[test]
    fn unreachable_documents_and_unlinked_component_docs_are_reported()
    {
        let root = md("README.md", "[D](docs/d.md) [C](c/README.md)\n");
        let d = md("docs/d.md", "# D\n\n---\n\n## Summarized By\n\nNone\n");
        let c = md("c/README.md", "# C\n\n---\n\n## Summarized By\n\nNone\n");
        let orphan = md("c/docs/o.md", "# O\n\n---\n\n## Summarized By\n\nNone\n");
        let diags = check_reachable(&pat(), &[&root, &d, &c, &orphan]);
        let messages: Vec<&str> = diags.iter().map(|d| d.message.as_str()).collect();
        assert!(messages.iter().any(|m| m.contains("not reachable")));
        assert!(
            messages
                .iter()
                .any(|m| m.contains("does not link `c/docs/o.md`"))
        );
    }

    #[test]
    fn bare_cites_are_flagged_outside_fences_only()
    {
        let text = "See (see x.md).\n```\n(see y.md)\n```\n";
        let diags = check_bare_cites(&pat(), &md("a.md", text));
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].line, 1);
    }

    #[test]
    fn a_fence_line_with_an_info_string_does_not_close_an_open_fence()
    {
        let text = "```\n```rust\n(see x.md)\n```\n(see y.md)\n";
        let diags = check_bare_cites(&pat(), &md("a.md", text));
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].line, 5);
    }

    #[test]
    fn links_that_climb_past_the_repository_root_resolve_to_nothing()
    {
        let targets = link_targets(&pat(), "docs/a.md", "[x](../../x.md) [y](../y.md)\n");
        assert_eq!(targets, BTreeSet::from(["y.md".to_owned()]));
    }

    #[test]
    fn summarized_by_rejects_entries_outside_the_repository()
    {
        for entry in ["[X](../../x.md)", "[X](#a)", "[X](https://e/x.md)"]
        {
            let text = format!("# T\n\n---\n\n## Summarized By\n\n{entry}\n");
            let err = summarized_by(&pat(), "docs/a.md", &text).unwrap_err();
            assert_eq!(err.0, 5);
            assert!(
                err.1.contains("does not resolve to a repository document"),
                "{entry}"
            );
        }
    }

    #[test]
    fn a_backtick_line_with_a_backtick_in_its_info_string_is_not_a_fence()
    {
        let text = "```x``` (see a.md)\n(see b.md)\n";
        let diags = check_bare_cites(&pat(), &md("a.md", text));
        assert_eq!(diags.iter().map(|d| d.line).collect::<Vec<_>>(), vec![1, 2]);
    }

    #[test]
    fn summarized_by_rejects_a_section_with_neither_links_nor_none()
    {
        for body in ["", ", ,"]
        {
            let text = format!("# T\n\n---\n\n## Summarized By\n\n{body}\n");
            assert_eq!(
                summarized_by(&pat(), "docs/a.md", &text),
                Err((
                    5,
                    "`## Summarized By` holds neither links nor `None`".to_owned()
                )),
                "{body:?}"
            );
        }
    }

    #[test]
    fn a_link_whose_text_wraps_across_lines_is_found()
    {
        let targets = link_targets(
            &pat(),
            "docs/a.md",
            "See [the\nother doc](b.md).\n\n```\n[c](c.md)\n```\n",
        );
        assert_eq!(targets, BTreeSet::from(["docs/b.md".to_owned()]));
    }

    /// A docs/testing.md stand-in whose surface list names, in prose and in
    /// the screen, the items `coverage_sources` defines, plus `extra` in the
    /// prose list and `screen_extra` in the screen.
    fn coverage_doc(extra: &str, screen_extra: &str) -> SourceFile
    {
        md(
            COVERAGE_DOC,
            &format!(
                "# Testing\n\n## Coverage tiers\n\n`gone_before_the_list` is outside it.\n\n\
                 **Boundary surface.** The surface is `core/a/*/tramp.rs` (`tramp.rs`) as a whole and\n\
                 `info.cpu_count`, `per_cpu_init_*`, the `git grep -n -E\n'x|y' <head>` \
                 command, `--runs 1`,{extra} and `frame::init`.\n\n\
                 ```sh\n\
                 git diff --stat \"$B\" <head> -- core/a/mm.rs \\\n    'core/a/*/tramp.rs'\n\
                 S='MAX_WIDTH|send_(wake|halt)_ipi'\n\
                 S=\"$S|VECTOR_[A-Z_]+|shoot(_range)?{screen_extra}\"\n\
                 ```\n\n**Repeat count.** `left_out` is past the list.\n"
            ),
        )
    }

    fn coverage_sources() -> Vec<SourceFile>
    {
        vec![
            md(
                "core/a/mm.rs",
                "const MAX_WIDTH: usize = 4;\nfn send_wake_ipi() {}\nfn send_halt_ipi() {}\n\
                 const VECTOR_WAKE: u8 = 1;\nfn shoot() {}\nfn shoot_range() {}\n\
                 fn per_cpu_init_slabs() {}\nfn f(info: &Info) { let _ = info.cpu_count; }\n\
                 mod frame { pub fn init() {} }\nfn g() { frame::init(); }\n\
                 // only_in_a_comment is named here and nowhere else.\n",
            ),
            md("xtask/src/x.rs", "fn only_in_xtask() {}\n"),
        ]
    }

    fn coverage_check(doc: &SourceFile) -> Vec<(usize, String)>
    {
        let sources = coverage_sources();
        let sources: Vec<&SourceFile> = sources.iter().collect();
        let tracked: Vec<String> = [
            "core/a/mm.rs",
            "core/a/x86/tramp.rs",
            "core/b/ap_.rs",
            "core/b/x86_tramp_entry.rs",
            "core/b/x86_trampoline.S",
            "xtask/src/x.rs",
        ]
        .map(str::to_owned)
        .to_vec();
        check_coverage_symbols(&[doc], &sources, &tracked)
            .into_iter()
            .map(|d| (d.line, d.message))
            .collect()
    }

    #[test]
    fn coverage_list_that_resolves_passes()
    {
        assert!(coverage_check(&coverage_doc("", "")).is_empty());
    }

    #[test]
    fn coverage_name_missing_from_the_tree_is_reported_at_its_line()
    {
        let diags = coverage_check(&coverage_doc(" `renamed_away`,", ""));
        assert_eq!(diags.len(), 1, "{diags:?}");
        assert_eq!(diags[0].0, 9);
        assert!(diags[0].1.contains("`renamed_away`"), "{}", diags[0].1);
    }

    #[test]
    fn coverage_screen_group_is_expanded_into_each_alternative()
    {
        let diags = coverage_check(&coverage_doc("", "|send_(wake|park)_ipi"));
        assert_eq!(diags.len(), 1, "{diags:?}");
        assert_eq!(diags[0].0, 15);
        assert!(diags[0].1.contains("`send_park_ipi`"), "{}", diags[0].1);
    }

    #[test]
    fn coverage_name_only_in_a_comment_or_in_xtask_does_not_resolve()
    {
        let diags = coverage_check(&coverage_doc(" `only_in_a_comment`, `only_in_xtask`,", ""));
        assert_eq!(diags.len(), 2, "{diags:?}");
    }

    #[test]
    fn coverage_path_that_names_no_tracked_file_is_reported()
    {
        let doc = coverage_doc("", "");
        let doc = md(
            COVERAGE_DOC,
            &doc.text.replace("core/a/mm.rs", "core/a/moved.rs"),
        );
        let diags = coverage_check(&doc);
        assert_eq!(diags.len(), 1, "{diags:?}");
        assert!(diags[0].1.contains("`core/a/moved.rs`"), "{}", diags[0].1);
    }

    #[test]
    fn coverage_bare_file_name_resolves_in_any_directory_but_an_unknown_one_is_reported()
    {
        let diags = coverage_check(&coverage_doc(" `tramp.rs`, `gone.rs`,", ""));
        assert_eq!(diags.len(), 1, "{diags:?}");
        assert!(diags[0].1.contains("`gone.rs`"), "{}", diags[0].1);
    }

    #[test]
    fn coverage_glob_path_matching_only_across_a_slash_or_naming_nothing_is_reported()
    {
        // `core/*/tramp.rs` matches `core/a/x86/tramp.rs` only if `*` crosses a `/`.
        let diags = coverage_check(&coverage_doc(" `core/*/tramp.rs`, `core/a/*/gone.rs`,", ""));
        let shown: Vec<&str> = diags.iter().map(|d| d.1.as_str()).collect();
        assert_eq!(shown.len(), 2, "{shown:?}");
        assert!(
            shown[0].contains("`core/*/tramp.rs`") && shown[0].contains("names no tracked file"),
            "{}",
            shown[0]
        );
        assert!(
            shown[1].contains("`core/a/*/gone.rs`") && shown[1].contains("names no tracked file"),
            "{}",
            shown[1]
        );
    }

    #[test]
    fn coverage_glob_path_star_matches_any_run_of_its_component_but_not_a_wrong_suffix()
    {
        // `ap_*.rs` resolves through an empty run (`ap_.rs`), `*_tramp*.rs` through two
        // runs; `*.S.rs` names nothing, since `x86_trampoline.S` lacks the `.rs` suffix.
        let diags = coverage_check(&coverage_doc(
            " `core/b/ap_*.rs`, `core/b/*_tramp*.rs`, `core/b/*.S.rs`,",
            "",
        ));
        assert_eq!(diags.len(), 1, "{diags:?}");
        assert!(diags[0].1.contains("`core/b/*.S.rs`"), "{}", diags[0].1);
    }

    #[test]
    fn coverage_malformed_screen_alternative_is_reported_as_an_invalid_pattern()
    {
        let diags = coverage_check(&coverage_doc("", "|send_(wake"));
        assert_eq!(diags.len(), 1, "{diags:?}");
        assert!(
            diags[0].1.contains("not a valid regular expression (")
                && diags[0].1.contains("unclosed group"),
            "{}",
            diags[0].1
        );
    }

    #[test]
    fn coverage_list_without_its_section_heading_is_reported()
    {
        let doc = coverage_doc("", "");
        let doc = md(
            COVERAGE_DOC,
            &doc.text.replace("## Coverage tiers", "## Coverage"),
        );
        let diags = coverage_check(&doc);
        assert_eq!(diags.len(), 1, "{diags:?}");
        assert!(diags[0].1.contains("## Coverage tiers"), "{}", diags[0].1);
    }

    #[test]
    fn coverage_list_without_its_boundary_surface_paragraph_is_reported()
    {
        let doc = coverage_doc("", "");
        let doc = md(
            COVERAGE_DOC,
            &doc.text
                .replace("**Boundary surface.**", "Boundary surface."),
        );
        let diags = coverage_check(&doc);
        assert_eq!(diags.len(), 1, "{diags:?}");
        assert!(
            diags[0].1.contains("**Boundary surface.**"),
            "{}",
            diags[0].1
        );
    }

    #[test]
    fn coverage_check_without_the_testing_document_is_reported()
    {
        let other = md("docs/other.md", "# Other\n");
        let diags = check_coverage_symbols(&[&other], &[], &[]);
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].path, COVERAGE_DOC);
        assert!(
            diags[0].message.contains("not a tracked document"),
            "{}",
            diags[0].message
        );
    }

    #[test]
    fn coverage_list_without_its_repeat_count_paragraph_is_reported()
    {
        let doc = coverage_doc("", "");
        let doc = md(
            COVERAGE_DOC,
            &doc.text.replace("**Repeat count.**", "Repeat count."),
        );
        let diags = coverage_check(&doc);
        assert_eq!(diags.len(), 1, "{diags:?}");
        assert!(diags[0].1.contains("**Repeat count.**"), "{}", diags[0].1);
    }
}
