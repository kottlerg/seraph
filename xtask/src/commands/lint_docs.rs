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
    ("md-backlink-forward", Level::Warning),
    ("md-reachable", Level::Warning),
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

/// A line that is one link, image, or badge construct (optionally a list item,
/// optionally followed by sentence punctuation): the URL cannot break, so the
/// column limit exempts it (docs/coding-standards.md § Markdown).
/// The regular expressions the rules share, compiled once per run.
struct Patterns
{
    /// A line that is one link, image, or badge construct (optionally a list
    /// item, optionally followed by sentence punctuation): the URL cannot
    /// break, so the column limit exempts it (docs/coding-standards.md § Markdown).
    link_only: Regex,
    /// A `(see <name>.md)` citation outside link syntax.
    bare_cite: Regex,
    /// A Markdown inline link; group 1 is the target.
    md_link: Regex,
}

impl Patterns
{
    fn new() -> Result<Self>
    {
        Ok(Self {
            link_only: Regex::new(
                r"^\s*(?:[-*]\s+|\d+\.\s+)?(?:\[!\[[^\]]*\]\([^)]*\)\]\([^)]*\)|\[[^\]]*\]\([^)]*\)|<?https?://\S+>?)[.,;:)]*\s*$",
            )?,
            bare_cite: Regex::new(r"\(see [A-Za-z0-9_./-]+\.md\)")?,
            md_link: Regex::new(r"\[[^\]]*\]\(([^)\s]+)\)")?,
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
/// opens with a run of three or more backticks or tildes and closes only on a
/// run of the same character at least as long.
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
            (None, Some((c, n))) if n >= 3 =>
            {
                open = Some((c, n));
                false
            }
            (Some((oc, on)), Some((c, n))) if c == oc && n >= on =>
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
    // The path line is the first non-blank line after the license block.
    let expected = format!("{prefix} {path}");
    let Some(path_idx) = lines[end..].iter().position(|l| !blank(l)).map(|i| end + i)
    else
    {
        return Some((end + 1, format!("missing path line `{expected}`")));
    };
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
        let rest = &lines[path_idx + 2..];
        let doc = rest.iter().position(|l| l.starts_with("//!"));
        let attr = rest.iter().position(|l| l.starts_with("#!["));
        match (doc, attr)
        {
            (None, _) => return Some((path_idx + 3, "missing `//!` description".into())),
            (Some(d), Some(a)) if a < d =>
            {
                return Some((
                    path_idx + 3 + a,
                    "crate attribute precedes the `//!` block".into(),
                ));
            }
            _ =>
            {}
        }
    }
    None
}

// ── md-summarized-by, md-backlink-forward ────────────────────────────────────

/// Link targets in `text` outside fenced code, resolved to repository-relative
/// paths; external and in-page links are skipped.
fn link_targets(pat: &Patterns, path: &str, text: &str) -> BTreeSet<String>
{
    let dir = Path::new(path).parent().unwrap_or_else(|| Path::new(""));
    let mut out = BTreeSet::new();
    for (_, line) in prose_lines(text)
    {
        for cap in pat.md_link.captures_iter(line)
        {
            let target = cap[1].split('#').next().unwrap_or("");
            if target.is_empty() || target.contains("://") || target.starts_with("mailto:")
            {
                continue;
            }
            out.insert(normalize(&dir.join(target)));
        }
    }
    out
}

/// Collapse `.` and `..` components without touching the filesystem.
fn normalize(path: &Path) -> String
{
    let mut parts: Vec<String> = Vec::new();
    for component in path.components()
    {
        match component
        {
            Component::ParentDir =>
            {
                parts.pop();
            }
            Component::Normal(s) => parts.push(s.to_string_lossy().into_owned()),
            _ =>
            {}
        }
    }
    parts.join("/")
}

/// The `## Summarized By` section of an authoritative document: `None` when
/// the section is missing or malformed (the violation is reported separately),
/// else the resolved entry paths.
fn summarized_by(
    pat: &Patterns,
    path: &str,
    text: &str,
) -> std::result::Result<BTreeSet<String>, (usize, String)>
{
    let lines: Vec<(usize, &str)> = prose_lines(text).collect();
    let heading = lines
        .iter()
        .rposition(|(_, l)| l.trim_end() == "## Summarized By")
        .ok_or((
            text.lines().count(),
            "missing `## Summarized By` section".to_owned(),
        ))?;
    let (heading_line, _) = lines[heading];
    let before: Vec<&str> = lines[..heading]
        .iter()
        .rev()
        .map(|(_, l)| *l)
        .filter(|l| !l.trim().is_empty())
        .collect();
    if before.first().copied() != Some("---")
    {
        return Err((
            heading_line + 1,
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
        return Err((
            heading_line + 1,
            "`## Summarized By` must be the last section".into(),
        ));
    }
    let joined = body.join(" ");
    if joined.trim() == "None"
    {
        return Ok(BTreeSet::new());
    }
    let stripped = pat.md_link.replace_all(&joined, "").replace(',', "");
    if !stripped.trim().is_empty()
    {
        return Err((
            heading_line + 1,
            "`## Summarized By` holds text other than links or `None`".into(),
        ));
    }
    Ok(link_targets(pat, path, &format!("\n{joined}\n")))
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

    #[test]
    fn header_accepts_multi_line_license_block_and_rejects_wrong_path()
    {
        let ok = "// SPDX-License-Identifier: GPL-2.0-only AND OFL-1.1\n// Copyright (C) 2026 X\n//\n// Code: GPL.\n\n// a/b.rs\n\n//! Doc.\n\n#![no_std]\n";
        assert_eq!(header_violation("a/b.rs", ok), None);
        let wrong = ok.replace("// a/b.rs", "// b.rs");
        assert!(header_violation("a/b.rs", &wrong).is_some());
    }

    #[test]
    fn header_rejects_attribute_before_doc()
    {
        let attr_first = "// SPDX-License-Identifier: GPL-2.0-only\n// (C)\n\n// a.rs\n\n#![no_std]\n\n//! Doc.\n";
        assert_eq!(
            header_violation("a.rs", attr_first).map(|(l, _)| l),
            Some(6)
        );
    }

    #[test]
    fn header_rejects_missing_doc()
    {
        let no_doc =
            "// SPDX-License-Identifier: GPL-2.0-only\n// (C)\n\n// a.rs\n\nfn main() {}\n";
        assert!(header_violation("a.rs", no_doc).is_some());
    }

    #[test]
    fn header_rejects_license_block_without_blank_line()
    {
        let no_blank = "// SPDX-License-Identifier: GPL-2.0-only\n// (C)\n//! Doc.\nfn main() {}\n";
        assert!(header_violation("a.rs", no_blank).is_some());
    }

    #[test]
    fn header_requires_path_line_first_after_license_and_blank_before_doc()
    {
        let late =
            "// SPDX-License-Identifier: GPL-2.0-only\n// (C)\n\n// note\n\n// a.rs\n\n//! Doc.\n";
        assert_eq!(header_violation("a.rs", late).map(|(l, _)| l), Some(4));
        let adjacent = "// SPDX-License-Identifier: GPL-2.0-only\n// (C)\n\n// a.rs\n//! Doc.\n";
        assert_eq!(header_violation("a.rs", adjacent).map(|(l, _)| l), Some(5));
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
}
