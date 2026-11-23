// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/commands/threat_scope.rs

//! `threat-scope`: the scope of a threat audit of one section of
//! `docs/threat-model.md`, read from the document and git at a head.
//!
//! The `threat-audit` workflow (`.claude/workflows/threat-audit.js`) has no
//! file or process access of its own: every fact reaches it through an agent's
//! structured output. This command parses the section, resolves the files its
//! mitigations and coverage name, reports the references that resolve to
//! nothing, cuts the files into reviewer shards, and prints the result with an
//! FNV-1a 64 digest the workflow recomputes, so the section's text reaches the
//! reviewers byte for byte as the document states it (xtask/README.md
//! § `cargo xtask threat-scope` states the format and the encoding).

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::error::{Context, Result, bail};
use json::{Value, json};

use super::orch::{now_secs, timestamp};
use super::release_scope::{Digest, Issue, issue_fields, issues_digest, read_issues};
use crate::cli::ThreatScopeArgs;
use crate::context::Context as BuildContext;
use crate::util::run_cmd_capture;

/// The document whose sections the command scopes.
const DOCUMENT: &str = "docs/threat-model.md";

/// The part of the document that holds the assumptions every boundary shares;
/// every reviewer is given it with the section's own.
const SYSTEM_ASSUMPTIONS: &str = "### System-wide assumptions";

/// The blocks a boundary section holds, in this order; the parser refuses a
/// section that lacks one.
const LABELS: [&str; 6] = [
    "Attacker",
    "Assets",
    "Assumptions",
    "Mitigations",
    "Fuzz targets and proof harnesses",
    "Gaps",
];

/// The blocks whose file references are the audit's scope.
const SCOPED_LABELS: [&str; 2] = ["Mitigations", "Fuzz targets and proof harnesses"];

/// The most files one shard holds. A reviewer reads each file whole, and its
/// callers and dependencies besides; past six files those reads crowd out the
/// adversarial reading of each, which is the bound the release review's
/// shards keep too.
const MAX_SHARD_FILES: usize = 6;

/// The most lines one shard holds: two or three of the larger parser files,
/// so a mitigation's code stays with one reviewer. A file is never split: one
/// longer than this takes a shard of its own.
const MAX_SHARD_LINES: u64 = 2500;

// ── The section ───────────────────────────────────────────────────────────────

/// One item of a block: a bullet with its continuation lines, or the whole
/// paragraph of a block that has no bullet; the raw Markdown either way.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Item
{
    text: String,
    /// The tracked text files its path references resolve to, in order of
    /// reference; a directory reference contributes the text files under it.
    files: Vec<String>,
    /// The backticked paths that resolve to nothing tracked, and the linked
    /// documents that do not exist.
    unresolved: Vec<String>,
    /// The backticked identifiers found as a word in none of `files`.
    unlocated: Vec<String>,
}

/// One labelled block of the section: `**<label>.**` and the lines to the next.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Block
{
    label: String,
    /// The block's raw Markdown, the label removed.
    text: String,
    items: Vec<Item>,
}

/// A section as parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Section
{
    name: String,
    system_assumptions: String,
    blocks: Vec<Block>,
}

/// The number of leading `#` of a Markdown heading line, 0 for any other line.
fn heading_level(line: &str) -> usize
{
    let hashes = line.chars().take_while(|c| *c == '#').count();
    if hashes > 0 && line.chars().nth(hashes) == Some(' ')
    {
        hashes
    }
    else
    {
        0
    }
}

/// The lines of the part of `doc` that the line `heading` opens, to the next
/// heading of its level or above, or a `---` rule.
fn part<'a>(doc: &'a str, heading: &str) -> Option<Vec<&'a str>>
{
    let level = heading_level(heading);
    let mut lines = doc.lines();
    lines.find(|l| l.trim_end() == heading)?;
    Some(
        lines
            .take_while(|l| {
                let h = heading_level(l);
                l.trim_end() != "---" && !(h > 0 && h <= level)
            })
            .collect(),
    )
}

/// The lines joined, with the blank lines at either end removed.
fn trimmed(lines: &[&str]) -> String
{
    let start = lines.iter().position(|l| !l.trim().is_empty());
    let end = lines.iter().rposition(|l| !l.trim().is_empty());
    match (start, end)
    {
        (Some(s), Some(e)) => lines.get(s..=e).unwrap_or_default().join("\n"),
        _ => String::new(),
    }
}

/// The items of a block's text: each bullet with its indented continuation
/// lines, a paragraph before the first bullet counting as one item; or the
/// whole text when it has no bullet.
fn items_of(text: &str) -> Vec<String>
{
    let mut bullets: Vec<Vec<&str>> = Vec::new();
    let mut lead: Vec<&str> = Vec::new();
    let mut in_bullet = false;
    for line in text.lines()
    {
        if line.starts_with("- ")
        {
            bullets.push(vec![line]);
            in_bullet = true;
        }
        else if in_bullet && line.starts_with("  ")
        {
            if let Some(last) = bullets.last_mut()
            {
                last.push(line);
            }
        }
        else if bullets.is_empty()
        {
            lead.push(line);
        }
        else
        {
            in_bullet = false;
        }
    }
    let lead = trimmed(&lead);
    let mut out = Vec::new();
    if !lead.is_empty()
    {
        out.push(lead);
    }
    out.extend(bullets.iter().map(|lines| lines.join("\n")));
    out
}

/// The section `## <name>` of the document, with the document's system-wide
/// assumptions.
fn parse_section(doc: &str, name: &str) -> Result<Section>
{
    let heading = format!("## {name}");
    let Some(lines) = part(doc, &heading)
    else
    {
        bail!(
            "{DOCUMENT} has no section {heading:?}; its boundary sections are: {}",
            boundary_sections(doc).join(", ")
        );
    };
    let system_assumptions = part(doc, SYSTEM_ASSUMPTIONS)
        .map(|l| trimmed(&l))
        .with_context(|| format!("{DOCUMENT} has no {SYSTEM_ASSUMPTIONS:?}"))?;
    let mut blocks: Vec<(String, Vec<&str>)> = Vec::new();
    for line in lines
    {
        let opened = line
            .strip_prefix("**")
            .and_then(|rest| rest.split_once(".**"))
            .filter(|(label, _)| LABELS.contains(label));
        match (opened, blocks.last_mut())
        {
            (Some((label, rest)), _) => blocks.push((label.to_owned(), vec![rest.trim_start()])),
            (None, Some((_, body))) => body.push(line),
            (None, None) =>
            {}
        }
    }
    let labels: Vec<&str> = blocks.iter().map(|(l, _)| l.as_str()).collect();
    if labels != LABELS
    {
        bail!(
            "section {name:?} of {DOCUMENT} holds the blocks {labels:?}, not {LABELS:?} in that \
             order: it is not a boundary section"
        );
    }
    Ok(Section {
        name: name.to_owned(),
        system_assumptions,
        blocks: blocks
            .into_iter()
            .map(|(label, body)| {
                let text = trimmed(&body);
                let items = items_of(&text)
                    .into_iter()
                    .map(|text| Item {
                        text,
                        files: Vec::new(),
                        unresolved: Vec::new(),
                        unlocated: Vec::new(),
                    })
                    .collect();
                Block { label, text, items }
            })
            .collect(),
    })
}

/// The `## ` sections of the document that are boundary sections.
fn boundary_sections(doc: &str) -> Vec<String>
{
    doc.lines()
        .filter_map(|l| l.strip_prefix("## "))
        .filter(|name| parse_section(doc, name).is_ok())
        .map(str::to_owned)
        .collect()
}

// ── References ────────────────────────────────────────────────────────────────

/// The backticked spans of a text, in order.
fn code_spans(text: &str) -> Vec<&str>
{
    text.split('`').skip(1).step_by(2).collect()
}

/// The targets of the inline links of a text, in order, without an anchor.
fn link_targets(text: &str) -> Vec<&str>
{
    text.split("](")
        .skip(1)
        .filter_map(|rest| rest.split_once(')'))
        .map(|(target, _)| target.split('#').next().unwrap_or(target))
        .filter(|t| !t.is_empty() && !t.contains("://"))
        .collect()
}

/// The repository path a span names: it holds a `/` and no whitespace, and
/// does not begin with `/`, which marks a path of the running system's
/// namespace (`/services/drivers/`), not of the repository.
fn path_span(span: &str) -> Option<&str>
{
    (span.contains('/') && !span.starts_with('/') && !span.contains(char::is_whitespace))
        .then(|| span.trim_end_matches('/'))
}

/// The word a span names when it is an identifier or a path of identifiers
/// (`a::b::c` names `c`).
fn identifier(span: &str) -> Option<&str>
{
    let ident = |s: &str| {
        let mut chars = s.chars();
        chars
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
    };
    if span.split("::").all(ident)
    {
        span.rsplit("::").next()
    }
    else
    {
        None
    }
}

/// Whether `word` occurs in `text` with no identifier character on either side.
fn has_word(text: &str, word: &str) -> bool
{
    let ident = |c: char| c.is_ascii_alphanumeric() || c == '_';
    text.match_indices(word).any(|(at, _)| {
        let before = text.get(..at).and_then(|s| s.chars().next_back());
        let after = at
            .checked_add(word.len())
            .and_then(|end| text.get(end..))
            .and_then(|s| s.chars().next());
        !before.is_some_and(ident) && !after.is_some_and(ident)
    })
}

/// The repository path a link in `docs/threat-model.md` resolves to.
fn link_path(target: &str) -> String
{
    let mut parts: Vec<&str> = vec!["docs"];
    for seg in target.split('/')
    {
        match seg
        {
            ".." =>
            {
                parts.pop();
            }
            "." | "" =>
            {}
            _ => parts.push(seg),
        }
    }
    parts.join("/")
}

/// The tree a scope resolves against: its tracked paths, and the text of a
/// tracked file, `None` for a binary one.
trait Tree
{
    fn paths(&self) -> &[String];
    fn text(&self, path: &str) -> Option<String>;
}

/// The tracked paths a path span names: the file itself, or every file under
/// the directory; `None` when it names nothing tracked.
fn expand(tree: &dyn Tree, span: &str) -> Option<Vec<String>>
{
    if tree.paths().iter().any(|p| p == span)
    {
        return Some(vec![span.to_owned()]);
    }
    let prefix = format!("{span}/");
    let under: Vec<String> = tree
        .paths()
        .iter()
        .filter(|p| p.starts_with(&prefix))
        .cloned()
        .collect();
    (!under.is_empty()).then_some(under)
}

/// Resolve every item's references against the tree.
fn resolve(section: &mut Section, tree: &dyn Tree)
{
    for item in section.blocks.iter_mut().flat_map(|b| b.items.iter_mut())
    {
        let spans: Vec<String> = code_spans(&item.text)
            .into_iter()
            .map(str::to_owned)
            .collect();
        for span in &spans
        {
            let Some(path) = path_span(span)
            else
            {
                continue;
            };
            match expand(tree, path)
            {
                Some(paths) =>
                {
                    for p in paths
                    {
                        if !item.files.contains(&p) && tree.text(&p).is_some()
                        {
                            item.files.push(p);
                        }
                    }
                }
                None => item.unresolved.push(span.clone()),
            }
        }
        let targets: Vec<String> = link_targets(&item.text)
            .into_iter()
            .map(str::to_owned)
            .collect();
        for target in targets
        {
            if expand(tree, &link_path(&target)).is_none()
            {
                item.unresolved.push(target);
            }
        }
        if item.files.is_empty()
        {
            continue;
        }
        let texts: Vec<String> = item.files.iter().filter_map(|f| tree.text(f)).collect();
        for span in spans.iter().filter(|s| path_span(s).is_none())
        {
            if let Some(word) = identifier(span)
                && !texts.iter().any(|t| has_word(t, word))
                && !item.unlocated.contains(span)
            {
                item.unlocated.push(span.clone());
            }
        }
    }
}

// ── Shards ────────────────────────────────────────────────────────────────────

/// A file of the scope and its line count.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ScopeFile
{
    path: String,
    lines: u64,
}

/// One reviewer's files, and the scoped items (`<label>#<n>`, 1-based) that
/// name one of them.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Shard
{
    files: Vec<ScopeFile>,
    items: Vec<String>,
}

impl Shard
{
    fn lines(&self) -> u64
    {
        self.files.iter().fold(0, |n, f| n.saturating_add(f.lines))
    }
}

/// The lines of a text: its newlines, and one more when it does not end in
/// one.
fn line_count(text: &str) -> u64
{
    let newlines = text.bytes().filter(|b| *b == b'\n').count();
    let partial = usize::from(!text.is_empty() && !text.ends_with('\n'));
    u64::try_from(newlines.saturating_add(partial)).unwrap_or(u64::MAX)
}

/// The id of item `index` (0-based) of a block.
fn item_id(label: &str, index: usize) -> String
{
    format!("{label}#{}", index.saturating_add(1))
}

/// The blocks whose file references are the audit's scope.
fn scoped(section: &Section) -> impl Iterator<Item = &Block>
{
    section
        .blocks
        .iter()
        .filter(|b| SCOPED_LABELS.contains(&b.label.as_str()))
}

/// The scope's files in order of first reference, each with its line count.
fn scope_files(section: &Section, tree: &dyn Tree) -> Vec<ScopeFile>
{
    let mut seen = HashSet::new();
    let mut files = Vec::new();
    for path in scoped(section)
        .flat_map(|b| &b.items)
        .flat_map(|i| &i.files)
    {
        if seen.insert(path.clone())
        {
            files.push(ScopeFile {
                path: path.clone(),
                lines: tree.text(path).map_or(0, |t| line_count(&t)),
            });
        }
    }
    files
}

/// Pack the files, in order and never split, into shards of at most
/// `MAX_SHARD_FILES` files and `MAX_SHARD_LINES` lines (next fit: a file that
/// does not fit opens the next shard), and give each shard the scoped items
/// that name one of its files.
fn shards_of(section: &Section, files: Vec<ScopeFile>) -> Vec<Shard>
{
    let mut shards: Vec<Shard> = Vec::new();
    for file in files
    {
        let fits = shards.last().is_some_and(|s| {
            s.files.len() < MAX_SHARD_FILES
                && s.lines().saturating_add(file.lines) <= MAX_SHARD_LINES
        });
        match shards.last_mut()
        {
            Some(shard) if fits => shard.files.push(file),
            _ => shards.push(Shard {
                files: vec![file],
                items: Vec::new(),
            }),
        }
    }
    for shard in &mut shards
    {
        for block in scoped(section)
        {
            for (i, item) in block.items.iter().enumerate()
            {
                if item
                    .files
                    .iter()
                    .any(|p| shard.files.iter().any(|f| f.path == *p))
                {
                    shard.items.push(item_id(&block.label, i));
                }
            }
        }
    }
    shards
}

/// The ids of the items of the blocks `keep` accepts that `select` selects.
fn item_ids(section: &Section, keep: fn(&Block) -> bool, select: fn(&Item) -> bool) -> Vec<String>
{
    section
        .blocks
        .iter()
        .filter(|b| keep(b))
        .flat_map(|b| {
            b.items
                .iter()
                .enumerate()
                .filter(|(_, i)| select(i))
                .map(|(n, _)| item_id(&b.label, n))
        })
        .collect()
}

/// The Mitigations items that name no file.
fn unanchored(section: &Section) -> Vec<String>
{
    item_ids(
        section,
        |b| b.label == "Mitigations",
        |i| i.files.is_empty(),
    )
}

/// The items, of every block, with a reference that resolves to nothing.
fn unresolved(section: &Section) -> Vec<String>
{
    item_ids(section, |_| true, |i| !i.unresolved.is_empty())
}

/// The slug of a section name: its ASCII letters and digits in lower case,
/// every other run of characters one hyphen.
fn slug(name: &str) -> String
{
    let mut out = String::new();
    for c in name.chars()
    {
        if c.is_ascii_alphanumeric()
        {
            out.push(c.to_ascii_lowercase());
        }
        else if !out.is_empty() && !out.ends_with('-')
        {
            out.push('-');
        }
    }
    out.trim_end_matches('-').to_owned()
}

/// The documents the section's links name, in order, once each.
fn documents(section: &Section, tree: &dyn Tree) -> Vec<String>
{
    let mut out: Vec<String> = Vec::new();
    for block in &section.blocks
    {
        for target in link_targets(&block.text)
        {
            let path = link_path(target);
            if expand(tree, &path).is_some() && !out.contains(&path)
            {
                out.push(path);
            }
        }
    }
    out
}

// ── Encoding ──────────────────────────────────────────────────────────────────

/// The scope as read.
struct Scope
{
    head: String,
    repo_root: String,
    tree_at_head: bool,
    section: Section,
    documents: Vec<String>,
    unanchored: Vec<String>,
    unresolved: Vec<String>,
    shards: Vec<Shard>,
    issues: Vec<Issue>,
    /// When the open Issues were read from the tracker, UTC.
    issues_as_of: String,
}

/// A list as digest fields: its length, then each entry.
fn strings(d: &mut Digest, list: &[String])
{
    d.field(&list.len().to_string());
    for s in list
    {
        d.field(s);
    }
}

impl Scope
{
    /// Whether every Mitigations item names a file and every reference
    /// resolves.
    fn complete(&self) -> bool
    {
        self.unanchored.is_empty() && self.unresolved.is_empty()
    }

    /// The summary: everything but the open Issues, which it counts and
    /// digests, and the digest of its fields in the order xtask/README.md
    /// states.
    fn summary(&self, per_page: usize) -> Value
    {
        let pages = self.issues.len().div_ceil(per_page.max(1));
        let issues = issues_digest(&self.issues);
        let name_slug = slug(&self.section.name);
        let mut d = Digest::new();
        d.field("threat-summary")
            .field(&self.head)
            .field(&self.repo_root)
            .field(&self.tree_at_head.to_string())
            .field(DOCUMENT)
            .field(&self.section.name)
            .field(&name_slug)
            .field(&self.section.system_assumptions)
            .field(&self.section.blocks.len().to_string());
        for b in &self.section.blocks
        {
            d.field(&b.label)
                .field(&b.text)
                .field(&b.items.len().to_string());
            for i in &b.items
            {
                d.field(&i.text);
                strings(&mut d, &i.files);
                strings(&mut d, &i.unresolved);
                strings(&mut d, &i.unlocated);
            }
        }
        strings(&mut d, &self.documents);
        strings(&mut d, &self.unanchored);
        strings(&mut d, &self.unresolved);
        d.field(&self.complete().to_string())
            .field(&self.shards.len().to_string());
        for s in &self.shards
        {
            d.field(&s.lines().to_string())
                .field(&s.files.len().to_string());
            for f in &s.files
            {
                d.field(&f.path).field(&f.lines.to_string());
            }
            strings(&mut d, &s.items);
        }
        d.field(&per_page.to_string())
            .field(&self.issues.len().to_string())
            .field(&pages.to_string())
            .field(&issues)
            .field(&self.issues_as_of);
        let blocks: Vec<Value> = self
            .section
            .blocks
            .iter()
            .map(|b| {
                let items: Vec<Value> = b
                    .items
                    .iter()
                    .map(|i| {
                        json!({
                            "text": i.text,
                            "files": i.files,
                            "unresolved": i.unresolved,
                            "unlocated": i.unlocated,
                        })
                    })
                    .collect();
                json!({ "label": b.label, "text": b.text, "items": items })
            })
            .collect();
        let shards: Vec<Value> = self
            .shards
            .iter()
            .map(|s| {
                let files: Vec<Value> = s
                    .files
                    .iter()
                    .map(|f| json!({ "path": f.path, "lines": f.lines }))
                    .collect();
                json!({ "lines": s.lines(), "files": files, "items": s.items })
            })
            .collect();
        json!({
            "head": self.head,
            "repo_root": self.repo_root,
            "tree_at_head": self.tree_at_head,
            "document": DOCUMENT,
            "section": self.section.name,
            "slug": name_slug,
            "system_assumptions": self.section.system_assumptions,
            "blocks": blocks,
            "documents": self.documents,
            "unanchored": self.unanchored,
            "unresolved": self.unresolved,
            "complete": self.complete(),
            "shards": shards,
            "page_entries": per_page,
            "open_issue_count": self.issues.len(),
            "open_issue_pages": pages,
            "open_issues_digest": issues,
            "issues_as_of": self.issues_as_of,
            "digest": d.hex(),
        })
    }

    /// Page `page` (1-based) of the open Issues, with its digest.
    fn issue_page(&self, page: usize, per_page: usize) -> Result<Value>
    {
        let chunks: Vec<&[Issue]> = self.issues.chunks(per_page.max(1)).collect();
        let slice = page
            .checked_sub(1)
            .and_then(|i| chunks.get(i))
            .with_context(|| {
                format!(
                    "the open Issues fill {} page(s); page {page} does not exist",
                    chunks.len()
                )
            })?;
        let mut d = Digest::new();
        d.field("threat-issues")
            .field(&self.head)
            .field(&page.to_string())
            .field(&chunks.len().to_string())
            .field(&per_page.to_string());
        for i in *slice
        {
            issue_fields(&mut d, i);
        }
        let items: Vec<Value> = slice
            .iter()
            .map(|i| json!({ "number": i.number, "title": i.title }))
            .collect();
        Ok(json!({
            "list": "issues",
            "head": self.head,
            "page": page,
            "pages": chunks.len(),
            "page_entries": per_page,
            "items": items,
            "digest": d.hex(),
        }))
    }
}

// ── The open Issues ───────────────────────────────────────────────────────────

/// Where a summary saves the open Issues it read, by their digest, for the
/// pages cut from them: a tracker that moves while the workflow fetches the
/// pages then changes nothing it receives.
const SNAPSHOT_DIR: &str = "target/xtask/threat-scope";

/// The open Issues one summary read, and when.
#[derive(Debug)]
struct Snapshot
{
    as_of: String,
    issues: Vec<Issue>,
}

fn snapshot_path(root: &Path, digest: &str) -> PathBuf
{
    root.join(SNAPSHOT_DIR)
        .join(format!("issues-{digest}.json"))
}

fn snapshot_json(as_of: &str, issues: &[Issue]) -> Value
{
    let items: Vec<Value> = issues
        .iter()
        .map(|i| json!({ "number": i.number, "title": i.title }))
        .collect();
    json!({ "as_of": as_of, "issues": items })
}

/// The snapshot saved as `text`, refused unless its Issues digest to
/// `digest`, the name it was asked for by.
fn parse_snapshot(text: &str, digest: &str) -> Result<Snapshot>
{
    let v = json::parse(text).context("parsing the saved open-Issue list")?;
    let as_of = v["as_of"]
        .as_str()
        .context("the saved open-Issue list has no as_of")?
        .to_owned();
    let issues = v["issues"]
        .as_array()
        .context("the saved open-Issue list has no issues")?
        .iter()
        .map(|i| {
            Ok(Issue {
                number: i["number"]
                    .as_u64()
                    .context("a saved Issue without a number")?,
                title: i["title"]
                    .as_str()
                    .context("a saved Issue without a title")?
                    .to_owned(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    if issues_digest(&issues) != digest
    {
        bail!("the open-Issue list saved under {digest} does not digest to it");
    }
    Ok(Snapshot { as_of, issues })
}

/// The open Issues: the list saved under `digest`, or the tracker's now.
fn open_issues(root: &Path, digest: Option<&str>) -> Result<Snapshot>
{
    match digest
    {
        Some(d) =>
        {
            let path = snapshot_path(root, d);
            let text = std::fs::read_to_string(&path).with_context(|| {
                format!(
                    "no open-Issue list is saved under {d} ({}); a summary saves it",
                    path.display()
                )
            })?;
            parse_snapshot(&text, d)
        }
        None => Ok(Snapshot {
            issues: read_issues(root)?,
            as_of: timestamp(now_secs()?),
        }),
    }
}

/// Save the summary's open Issues under their digest.
fn save_snapshot(root: &Path, scope: &Scope) -> Result<()>
{
    let path = snapshot_path(root, &issues_digest(&scope.issues));
    if let Some(dir) = path.parent()
    {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    std::fs::write(
        &path,
        snapshot_json(&scope.issues_as_of, &scope.issues).to_string_pretty(),
    )
    .with_context(|| format!("writing {}", path.display()))
}

// ── Reading ───────────────────────────────────────────────────────────────────

/// The tree at a commit, read through git.
struct GitTree<'a>
{
    root: &'a Path,
    head: String,
    paths: Vec<String>,
}

impl Tree for GitTree<'_>
{
    fn paths(&self) -> &[String]
    {
        &self.paths
    }

    /// The blob's text; `None` for a binary blob (a NUL byte in its first
    /// 8000 bytes, git's own test) or one that is not UTF-8.
    fn text(&self, path: &str) -> Option<String>
    {
        let out = Command::new("git")
            .args(["cat-file", "blob", &format!("{}:{path}", self.head)])
            .current_dir(self.root)
            .output()
            .ok()?;
        let start = out.stdout.get(..8000).unwrap_or(&out.stdout);
        if !out.status.success() || start.contains(&0)
        {
            return None;
        }
        String::from_utf8(out.stdout).ok()
    }
}

fn git(root: &Path, args: &[&str]) -> Result<String>
{
    run_cmd_capture(Command::new("git").args(args).current_dir(root))
        .with_context(|| format!("git {}", args.join(" ")))
}

fn read_scope(root: &Path, args: &ThreatScopeArgs) -> Result<Scope>
{
    let head = git(
        root,
        &[
            "rev-parse",
            "--verify",
            &format!("{}^{{commit}}", args.head),
        ],
    )?
    .trim()
    .to_owned();
    let checked_out = git(root, &["rev-parse", "HEAD"])?.trim().to_owned();
    let clean = git(root, &["status", "--porcelain"])?.trim().is_empty();
    let doc = git(root, &["show", &format!("{head}:{DOCUMENT}")])?;
    let paths = git(root, &["ls-tree", "-r", "-z", "--name-only", &head])?
        .split('\0')
        .filter(|p| !p.is_empty())
        .map(str::to_owned)
        .collect();
    let tree = GitTree {
        root,
        head: head.clone(),
        paths,
    };
    let mut section = parse_section(&doc, &args.section)?;
    resolve(&mut section, &tree);
    let issues = open_issues(root, args.issues.as_deref())?;
    let files = scope_files(&section, &tree);
    Ok(Scope {
        repo_root: git(root, &["rev-parse", "--show-toplevel"])?
            .trim()
            .to_owned(),
        tree_at_head: clean && checked_out == head,
        documents: documents(&section, &tree),
        unanchored: unanchored(&section),
        unresolved: unresolved(&section),
        shards: shards_of(&section, files),
        issues: issues.issues,
        issues_as_of: issues.as_of,
        section,
        head,
    })
}

/// Entry point for `cargo xtask threat-scope`.
pub fn run(ctx: &BuildContext, args: &ThreatScopeArgs) -> Result<()>
{
    let per_page = usize::try_from(args.page_entries).context("--page-entries is too large")?;
    let page = args
        .page
        .as_deref()
        .map(|spec| {
            spec.strip_prefix("issues:")
                .and_then(|n| n.parse::<usize>().ok())
                .with_context(|| format!("--page takes issues:<n>, not {spec}"))
        })
        .transpose()?;
    let scope = read_scope(&ctx.root, args)?;
    if page.is_none() && !scope.complete() && !args.allow_incomplete
    {
        bail!(
            "the scope of section {:?} is incomplete: Mitigations items naming no file {:?}, \
             items with an unresolved reference {:?} (pass --allow-incomplete to print it as it \
             stands)",
            args.section,
            scope.unanchored,
            scope.unresolved
        );
    }
    let out = if let Some(n) = page
    {
        scope.issue_page(n, per_page)?
    }
    else
    {
        if args.issues.is_none()
        {
            save_snapshot(&ctx.root, &scope)?;
        }
        scope.summary(per_page)
    };
    println!("{}", out.to_string_pretty());
    Ok(())
}

#[cfg(test)]
mod tests
{
    use super::*;

    const DOC: &str = "# Threat Model\n\
        \n\
        ## Scope\n\
        \n\
        Intro.\n\
        \n\
        ### System-wide assumptions\n\
        \n\
        - Firmware runs as built.\n\
        \n\
        ---\n\
        \n\
        ## Disk Images\n\
        \n\
        Implementation status: provisional.\n\
        \n\
        **Attacker.** Anyone who writes a disk\n\
        ([signing.md](signing.md) § Threat Model).\n\
        \n\
        **Assets.** vfsd.\n\
        \n\
        **Assumptions.** None.\n\
        \n\
        **Mitigations.**\n\
        \n\
        - The GPT crate, `a/gpt`: `parse_header` checks it;\n  `gpt::missing_fn` too.\n\
        - The block driver bounds it (`resolve_lba` in `b/main.rs`).\n\
        - A promise with no file ([gone](gone.md)).\n\
        - A dangling `c/gone.rs`.\n\
        \n\
        **Fuzz targets and proof harnesses.** `a/gpt/fuzz/seeds/` drive `t/gpt.rs`.\n\
        \n\
        **Gaps.**\n\
        \n\
        - Overlap is unchecked.\n\
        \n\
        ---\n\
        \n\
        ## Summarized By\n\
        \n\
        None\n";

    struct Fake(Vec<String>);

    impl Tree for Fake
    {
        fn paths(&self) -> &[String]
        {
            &self.0
        }

        fn text(&self, path: &str) -> Option<String>
        {
            match path
            {
                "a/gpt/src/lib.rs" => Some("pub fn parse_header() {}\n".repeat(1500)),
                "a/gpt/Cargo.toml" => Some("[package]\n".to_owned()),
                "b/main.rs" => Some("fn resolve_lba() {}\n".repeat(1200)),
                "t/gpt.rs" => Some("fn main() {}".to_owned()),
                "docs/signing.md" => Some("# Signing\n".to_owned()),
                _ => None,
            }
        }
    }

    fn tree() -> Fake
    {
        Fake(
            [
                "a/gpt/Cargo.toml",
                "a/gpt/fuzz/seeds/disk",
                "a/gpt/src/lib.rs",
                "b/main.rs",
                "docs/signing.md",
                "t/gpt.rs",
            ]
            .map(str::to_owned)
            .to_vec(),
        )
    }

    fn resolved() -> Section
    {
        let mut s = parse_section(DOC, "Disk Images").unwrap();
        resolve(&mut s, &tree());
        s
    }

    fn scope(doc: &str) -> Scope
    {
        let mut section = parse_section(doc, "Disk Images").unwrap();
        resolve(&mut section, &tree());
        Scope {
            head: "h".to_owned(),
            repo_root: "/r".to_owned(),
            tree_at_head: true,
            documents: documents(&section, &tree()),
            unanchored: unanchored(&section),
            unresolved: unresolved(&section),
            shards: shards_of(&section, scope_files(&section, &tree())),
            issues: (1..=5)
                .map(|number| Issue {
                    number,
                    title: format!("issue {number}"),
                })
                .collect(),
            issues_as_of: "2026-11-23T10:00Z".to_owned(),
            section,
        }
    }

    // Defect caught: a lens that is not the document's text, or blocks read
    // out of order or cut at the wrong line.
    #[test]
    fn the_blocks_are_read_verbatim_in_order()
    {
        let s = resolved();
        let labels: Vec<&str> = s.blocks.iter().map(|b| b.label.as_str()).collect();
        assert_eq!(labels, LABELS);
        assert_eq!(
            s.blocks[0].text,
            "Anyone who writes a disk\n([signing.md](signing.md) § Threat Model)."
        );
        assert_eq!(s.system_assumptions, "- Firmware runs as built.");
        assert_eq!(s.blocks[3].items.len(), 4);
        assert_eq!(
            s.blocks[3].items[0].text,
            "- The GPT crate, `a/gpt`: `parse_header` checks it;\n  `gpt::missing_fn` too."
        );
        assert_eq!(s.blocks[4].items.len(), 1);
        assert_eq!(
            s.blocks[5].items,
            [Item {
                text: "- Overlap is unchecked.".to_owned(),
                files: Vec::new(),
                unresolved: Vec::new(),
                unlocated: Vec::new(),
            }]
        );
    }

    // Defect caught: an audit started on a section that is not a boundary.
    #[test]
    fn a_section_without_every_block_is_refused()
    {
        let refused = |doc: &str, name: &str| parse_section(doc, name).unwrap_err().to_string();
        assert!(refused(DOC, "Scope").contains("not a boundary section"));
        assert!(refused(DOC, "Nowhere").contains("its boundary sections are: Disk Images"));
        assert!(
            refused(&DOC.replace("**Gaps.**", "**Holes.**"), "Disk Images")
                .contains("not a boundary section")
        );
        assert_eq!(boundary_sections(DOC), ["Disk Images"]);
    }

    // Defect caught: a scope missing a file a mitigation names, or holding a
    // binary seed no reviewer can read.
    #[test]
    fn references_resolve_to_tracked_text_files()
    {
        let s = resolved();
        let m = &s.blocks[3].items;
        assert_eq!(m[0].files, ["a/gpt/Cargo.toml", "a/gpt/src/lib.rs"]);
        assert_eq!(m[1].files, ["b/main.rs"]);
        assert_eq!(m[2].unresolved, ["gone.md"]);
        assert_eq!(m[3].unresolved, ["c/gone.rs"]);
        let coverage = &s.blocks[4].items[0];
        assert_eq!(coverage.unresolved, Vec::<String>::new());
        assert_eq!(coverage.files, ["t/gpt.rs"]);
        assert_eq!(s.blocks[0].items[0].unresolved, Vec::<String>::new());
    }

    // Defect caught: a mitigation naming a function its files do not hold
    // passes unnoticed.
    #[test]
    fn an_identifier_absent_from_its_items_files_is_unlocated()
    {
        let s = resolved();
        assert_eq!(s.blocks[3].items[0].unlocated, ["gpt::missing_fn"]);
        assert_eq!(s.blocks[3].items[1].unlocated, Vec::<String>::new());
    }

    // Defect caught: a path of the running system's namespace, which a section
    // names beside repository paths, taken for a repository file and reported
    // as a reference to nothing, refusing a correct section.
    #[test]
    fn a_namespace_path_is_not_a_repository_reference()
    {
        assert_eq!(path_span("/services/drivers/"), None);
        assert_eq!(path_span("/config/boot.conf"), None);
        assert_eq!(path_span("a/gpt/"), Some("a/gpt"));
        assert_eq!(path_span("read or write"), None);
        let doc = DOC.replace(
            "- Overlap is unchecked.",
            "- Overlap in `/services/drivers/` is unchecked.",
        );
        let mut s = parse_section(&doc, "Disk Images").unwrap();
        resolve(&mut s, &tree());
        assert_eq!(s.blocks[5].items[0].unresolved, Vec::<String>::new());
        assert_eq!(unresolved(&s), ["Mitigations#3", "Mitigations#4"]);
    }

    // Defect caught: a mitigation with no file, or a dangling reference,
    // leaves the scope incomplete without the command saying so.
    #[test]
    fn an_incomplete_scope_is_named()
    {
        let s = resolved();
        assert_eq!(unanchored(&s), ["Mitigations#3", "Mitigations#4"]);
        assert_eq!(unresolved(&s), ["Mitigations#3", "Mitigations#4"]);
        assert!(!scope(DOC).complete());
    }

    // Defect caught: a shard over its bounds, a split file, or a shard whose
    // reviewer is not given the claims its files implement.
    #[test]
    fn shards_pack_in_order_and_never_split_a_file()
    {
        let s = resolved();
        let shards = shards_of(&s, scope_files(&s, &tree()));
        let paths: Vec<Vec<&str>> = shards
            .iter()
            .map(|sh| sh.files.iter().map(|f| f.path.as_str()).collect())
            .collect();
        assert_eq!(
            paths,
            [
                vec!["a/gpt/Cargo.toml", "a/gpt/src/lib.rs"],
                vec!["b/main.rs", "t/gpt.rs"]
            ]
        );
        assert_eq!(shards[0].items, ["Mitigations#1"]);
        assert_eq!(
            shards[1].items,
            ["Mitigations#2", "Fuzz targets and proof harnesses#1"]
        );
        let file = |lines| ScopeFile {
            path: "x".to_owned(),
            lines,
        };
        let big = shards_of(&s, vec![file(MAX_SHARD_LINES + 1), file(1)]);
        assert_eq!(big.len(), 2);
        assert_eq!(big[0].lines(), MAX_SHARD_LINES + 1);
        assert_eq!(shards_of(&s, vec![file(1); MAX_SHARD_FILES + 1]).len(), 2);
    }

    #[test]
    fn words_links_and_slugs()
    {
        assert!(has_word("fn resolve_lba(", "resolve_lba"));
        assert!(!has_word("fn resolve_lba_x(", "resolve_lba"));
        assert_eq!(identifier("ipc::recv_guard::RecvGuard"), Some("RecvGuard"));
        assert_eq!(identifier("dma-confinement = required"), None);
        assert_eq!(identifier("cfg(fuzzing)"), None);
        assert_eq!(
            link_path("../core/kernel/docs/entropy.md"),
            "core/kernel/docs/entropy.md"
        );
        assert_eq!(slug("Boot-Chain Signatures"), "boot-chain-signatures");
        assert_eq!(line_count("a\nb"), 2);
        assert_eq!(line_count("a\n"), 1);
        assert_eq!(line_count(""), 0);
    }

    // Defect caught: a summary an agent altered still matches its digest.
    #[test]
    fn the_summary_digest_covers_the_lens_text()
    {
        let a = scope(DOC).summary(200);
        let b = scope(&DOC.replace("Anyone who writes", "Anyone who edits")).summary(200);
        assert_ne!(a["digest"], b["digest"]);
        assert_eq!(a["documents"], json!(["docs/signing.md"]));
        assert_eq!(a["complete"], json!(false));
        assert_eq!(a["open_issue_pages"], json!(1));
    }

    // Defect caught: a page cut from the tracker as it stands when the page is
    // asked for, not from the list its summary counted, so an Issue filed
    // between the two fails the run; or a saved list read back altered.
    #[test]
    fn a_saved_open_issue_list_reads_back_only_under_its_digest()
    {
        let s = scope(DOC);
        let digest = issues_digest(&s.issues);
        let text = snapshot_json(&s.issues_as_of, &s.issues).to_string_pretty();
        let back = parse_snapshot(&text, &digest).unwrap();
        assert_eq!(back.issues, s.issues);
        assert_eq!(back.as_of, s.issues_as_of);
        let altered = text.replace("issue 3", "issue three");
        let err = parse_snapshot(&altered, &digest).unwrap_err().to_string();
        assert!(err.contains("does not digest"), "{err}");
        assert_eq!(s.summary(200)["issues_as_of"], json!("2026-11-23T10:00Z"));
    }

    // Defect caught: an Issue page past the list, or pages that drop an Issue.
    #[test]
    fn the_issue_pages_hold_every_issue_once()
    {
        let s = scope(DOC);
        let numbers: Vec<Value> = (1..=3)
            .flat_map(|p| {
                s.issue_page(p, 2).unwrap()["items"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|i| i["number"].clone())
                    .collect::<Vec<_>>()
            })
            .collect();
        assert_eq!(numbers, (1..=5).map(|n| json!(n)).collect::<Vec<_>>());
        for page in [0, 4]
        {
            let err = s.issue_page(page, 2).unwrap_err().to_string();
            assert!(err.contains("does not exist"), "{err}");
        }
    }
}
