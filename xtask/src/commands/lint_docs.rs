// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/commands/lint_docs.rs

//! Lint-docs command: mechanical checks of the documentation and source-header
//! rules in `docs/coding-standards.md` and `docs/documentation-standards.md`.
//!
//! Each rule prints `error <rule>: <path>:<line>: <message>` (or `warning`)
//! per violation; any error-level diagnostic fails the command. The rules
//! check only what a script can decide: column widths, header layout, the
//! `## Summarized By` section's shape and forward links, and document
//! reachability. Whether a passage is a summary, or a statement matches the
//! code, stays with the pre-merge review.

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

/// The rules, with the level each runs at. `md-reachable` and
/// `md-backlink-forward` are warnings until the grouping-directory scope and
/// the tree-wide Summarized By rewrite land (Issue #438); `md-bare-cite` stays
/// a warning because the pattern has legitimate uses.
const RULES: &[(&str, Level)] = &[
    ("md-columns", Level::Error),
    ("src-header", Level::Error),
    ("md-summarized-by", Level::Error),
    ("md-backlink-forward", Level::Error),
    ("md-reachable", Level::Error),
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
}
