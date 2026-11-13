// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/commands/release_scope.rs

//! `release-scope`: the scope of a release review, read from git and `gh`.
//!
//! The `release-review` workflow (`.claude/workflows/release-review.js`) has
//! no file or process access of its own: every fact reaches it through an
//! agent's structured output. This command produces those facts, so no agent
//! derives them, and cuts every list into pages of at most `--page-entries`
//! entries, so no agent's output grows with the range. Each printed object
//! carries an FNV-1a 64 digest of its own content, and the summary carries
//! the digest of each whole list: the workflow recomputes them and refuses a
//! scope that an agent truncated or altered (xtask/README.md
//! § `cargo xtask release-scope` states the encoding).

use std::collections::HashSet;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};
use serde_json::{Value, json};

use crate::cli::ReleaseScopeArgs;
use crate::context::Context as BuildContext;
use crate::gh;
use crate::util::run_cmd_capture;

/// The most open Issues the command reads; a list that reaches it may be
/// truncated, and the command refuses it.
const ISSUE_LIMIT: usize = 1000;

/// The file names, outside the documents and instruction files, that no build
/// reads: repository metadata. Every other file is code for the review.
const OTHER_FILE_NAMES: &[&str] = &[
    "LICENSE",
    ".gitignore",
    ".gitattributes",
    ".gitkeep",
    ".editorconfig",
    ".clang-format",
];

// ── Digest ────────────────────────────────────────────────────────────────────

/// FNV-1a 64 over a sequence of fields, each the field's UTF-8 bytes followed
/// by a NUL byte. The workflow script computes the same function; the test
/// `the_digest_of_the_shared_vector_is_pinned` pins the value the script's
/// self-test also pins.
struct Digest(u64);

impl Digest
{
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;

    fn new() -> Self
    {
        Digest(Self::OFFSET)
    }

    fn byte(&mut self, b: u8)
    {
        self.0 = (self.0 ^ u64::from(b)).wrapping_mul(Self::PRIME);
    }

    fn field(&mut self, value: &str) -> &mut Self
    {
        for b in value.bytes()
        {
            self.byte(b);
        }
        self.byte(0);
        self
    }

    fn hex(&self) -> String
    {
        format!("{:016x}", self.0)
    }
}

// ── The scope's lists ─────────────────────────────────────────────────────────

/// One path of the range diff `<from>..<head>`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RangeFile
{
    path: String,
    /// Added plus deleted lines; 0 for a binary file.
    changed: u64,
    at_head: bool,
    kind: &'static str,
}

/// One first-parent commit of the range, with the files its own diff
/// (`<sha>^1..<sha>`) names.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Unit
{
    sha: String,
    /// N when the subject is `Merge pull request #N ...`, else 0.
    pr: u64,
    title: String,
    files: Vec<String>,
}

/// One open Issue.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Issue
{
    number: u64,
    title: String,
}

/// The three paged lists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum List
{
    Files,
    Units,
    Issues,
}

impl List
{
    fn name(self) -> &'static str
    {
        match self
        {
            List::Files => "files",
            List::Units => "units",
            List::Issues => "issues",
        }
    }
}

/// A unit's slice on one page: the files from `offset` on, `files.len()` of
/// them. A unit whose file list does not fit the room a page has left
/// continues on the next page.
#[derive(Debug, PartialEq, Eq)]
struct UnitChunk<'a>
{
    unit: &'a Unit,
    offset: usize,
    files: &'a [String],
}

/// The review kind of a range path: `rules` under `.claude/` or `.github/`,
/// `markdown` for any other `.md` file, `other` for repository metadata, and
/// `code` for everything else (Rust, assembly, linker scripts, build inputs,
/// anything a build embeds).
fn kind_of(path: &str) -> &'static str
{
    let name = path.rsplit('/').next().unwrap_or(path);
    if path.starts_with(".claude/") || path.starts_with(".github/")
    {
        "rules"
    }
    else if name.to_ascii_lowercase().ends_with(".md")
    {
        "markdown"
    }
    else if OTHER_FILE_NAMES.contains(&name)
    {
        "other"
    }
    else
    {
        "code"
    }
}

/// The pull request a first-parent subject `Merge pull request #N ...` names.
fn pr_of(subject: &str) -> Option<u64>
{
    let rest = subject.strip_prefix("Merge pull request #")?;
    let after = rest.trim_start_matches(|c: char| c.is_ascii_digit());
    let digits = rest.strip_suffix(after)?;
    if digits.is_empty() || !(after.is_empty() || after.starts_with(' '))
    {
        return None;
    }
    digits.parse().ok()
}

/// A unit's PR number and title from its subject and body: a pull request's
/// merge takes its title from the body's first non-empty line (the subject
/// when the body has none); any other commit is titled by its subject.
fn title_of(subject: &str, body: &str) -> (u64, String)
{
    match pr_of(subject)
    {
        Some(pr) =>
        {
            let title = body
                .lines()
                .map(str::trim)
                .find(|l| !l.is_empty())
                .unwrap_or(subject);
            (pr, title.to_owned())
        }
        None => (0, subject.to_owned()),
    }
}

/// `[workspace.package] version` of a root `Cargo.toml`.
fn workspace_version(manifest: &str) -> Option<String>
{
    let mut in_section = false;
    for line in manifest.lines().map(str::trim)
    {
        if line.starts_with('[')
        {
            in_section = line == "[workspace.package]";
            continue;
        }
        if !in_section
        {
            continue;
        }
        let Some((key, value)) = line.split_once('=')
        else
        {
            continue;
        };
        if key.trim() == "version"
        {
            return Some(value.trim().trim_matches('"').to_owned());
        }
    }
    None
}

/// The paths of `git diff --name-only -z` (or `ls-tree --name-only -z`).
fn nul_paths(out: &str) -> Vec<String>
{
    out.split('\0')
        .filter(|p| !p.is_empty())
        .map(str::to_owned)
        .collect()
}

/// The `(path, changed)` pairs of `git diff --numstat --no-renames -z`: each
/// record `<added>\t<deleted>\t<path>\0`, where a binary file prints `-` for
/// both counts and counts 0.
fn numstat(out: &str) -> Result<Vec<(String, u64)>>
{
    let mut entries = Vec::new();
    for record in out.split('\0').filter(|r| !r.is_empty())
    {
        let mut parts = record.splitn(3, '\t');
        let (Some(added), Some(deleted), Some(path)) = (parts.next(), parts.next(), parts.next())
        else
        {
            bail!("unexpected numstat record {record:?}");
        };
        let count = |n: &str| -> Result<u64> {
            if n == "-"
            {
                Ok(0)
            }
            else
            {
                n.parse()
                    .with_context(|| format!("unexpected numstat count in {record:?}"))
            }
        };
        let changed = count(added)?
            .checked_add(count(deleted)?)
            .context("numstat count overflows")?;
        entries.push((path.to_owned(), changed));
    }
    Ok(entries)
}

// ── Paging ────────────────────────────────────────────────────────────────────

/// Cut the units into pages of at most `per_page` entries, a file of a unit
/// being one entry and a unit with no file one. A unit's file list is split
/// where a page fills, so no page exceeds the bound however many files one
/// unit has.
fn unit_pages(units: &[Unit], per_page: usize) -> Vec<Vec<UnitChunk<'_>>>
{
    let per_page = per_page.max(1);
    let mut pages = Vec::new();
    let mut current: Vec<UnitChunk<'_>> = Vec::new();
    let mut room = per_page;
    for unit in units
    {
        if unit.files.is_empty()
        {
            if room == 0
            {
                pages.push(std::mem::take(&mut current));
                room = per_page;
            }
            current.push(UnitChunk {
                unit,
                offset: 0,
                files: &unit.files,
            });
            room = room.saturating_sub(1);
            continue;
        }
        let mut rest: &[String] = &unit.files;
        let mut offset: usize = 0;
        while !rest.is_empty()
        {
            if room == 0
            {
                pages.push(std::mem::take(&mut current));
                room = per_page;
            }
            let (files, tail) = rest
                .split_at_checked(room.min(rest.len()))
                .unwrap_or((rest, &[]));
            current.push(UnitChunk {
                unit,
                offset,
                files,
            });
            offset = offset.saturating_add(files.len());
            room = room.saturating_sub(files.len());
            rest = tail;
        }
    }
    if !current.is_empty()
    {
        pages.push(current);
    }
    pages
}

/// The number of pages of `count` entries at `per_page` a page.
fn page_count(count: usize, per_page: usize) -> usize
{
    count.div_ceil(per_page.max(1))
}

/// The entries the units occupy: one per file, one per unit with no file.
fn unit_entries(units: &[Unit]) -> usize
{
    units.iter().map(|u| u.files.len().max(1)).sum()
}

// ── Encoding ──────────────────────────────────────────────────────────────────

fn file_fields(d: &mut Digest, f: &RangeFile)
{
    d.field(&f.path)
        .field(&f.changed.to_string())
        .field(if f.at_head { "true" } else { "false" })
        .field(f.kind);
}

fn unit_fields(d: &mut Digest, u: &Unit)
{
    d.field(&u.sha)
        .field(&u.pr.to_string())
        .field(&u.title)
        .field(&u.files.len().to_string());
    for f in &u.files
    {
        d.field(f);
    }
}

fn chunk_fields(d: &mut Digest, c: &UnitChunk<'_>)
{
    d.field(&c.unit.sha)
        .field(&c.unit.pr.to_string())
        .field(&c.unit.title)
        .field(&c.unit.files.len().to_string())
        .field(&c.offset.to_string())
        .field(&c.files.len().to_string());
    for f in c.files
    {
        d.field(f);
    }
}

fn issue_fields(d: &mut Digest, i: &Issue)
{
    d.field(&i.number.to_string()).field(&i.title);
}

/// The digest of a whole list: its name, then each entry's fields.
fn list_digest<T>(list: List, items: &[T], fields: fn(&mut Digest, &T)) -> String
{
    let mut d = Digest::new();
    d.field(list.name());
    for item in items
    {
        fields(&mut d, item);
    }
    d.hex()
}

fn file_json(f: &RangeFile) -> Value
{
    json!({ "path": f.path, "changed": f.changed, "at_head": f.at_head, "kind": f.kind })
}

fn chunk_json(c: &UnitChunk<'_>) -> Value
{
    json!({
        "sha": c.unit.sha,
        "pr": c.unit.pr,
        "title": c.unit.title,
        "file_count": c.unit.files.len(),
        "offset": c.offset,
        "files": c.files,
    })
}

fn issue_json(i: &Issue) -> Value
{
    json!({ "number": i.number, "title": i.title })
}

/// The scope as read: the range's ends and state, the three lists, the
/// versions, and the open milestones.
struct Scope
{
    head: String,
    from_sha: String,
    repo_root: String,
    tree_at_head: bool,
    from_ancestor: bool,
    version_at_head: String,
    version_at_from: String,
    milestones: Vec<String>,
    files: Vec<RangeFile>,
    units: Vec<Unit>,
    issues: Vec<Issue>,
}

impl Scope
{
    /// The page header's fields, digested before its entries.
    fn page_digest(&self, list: List, page: usize, pages: usize, per_page: usize) -> Digest
    {
        let mut d = Digest::new();
        d.field(list.name())
            .field(&self.head)
            .field(&self.from_sha)
            .field(&page.to_string())
            .field(&pages.to_string())
            .field(&per_page.to_string());
        d
    }

    /// One page of one list, 1-based, with its digest.
    fn page(&self, list: List, page: usize, per_page: usize) -> Result<Value>
    {
        let (items, pages, digest) = match list
        {
            List::Files =>
            {
                let chunks: Vec<&[RangeFile]> = self.files.chunks(per_page).collect();
                let slice = page_slice(&chunks, list, page)?;
                let mut d = self.page_digest(list, page, chunks.len(), per_page);
                for f in *slice
                {
                    file_fields(&mut d, f);
                }
                (
                    slice.iter().map(file_json).collect::<Vec<_>>(),
                    chunks.len(),
                    d.hex(),
                )
            }
            List::Units =>
            {
                let chunks = unit_pages(&self.units, per_page);
                let slice = page_slice(&chunks, list, page)?;
                let mut d = self.page_digest(list, page, chunks.len(), per_page);
                for c in slice
                {
                    chunk_fields(&mut d, c);
                }
                (
                    slice.iter().map(chunk_json).collect(),
                    chunks.len(),
                    d.hex(),
                )
            }
            List::Issues =>
            {
                let chunks: Vec<&[Issue]> = self.issues.chunks(per_page).collect();
                let slice = page_slice(&chunks, list, page)?;
                let mut d = self.page_digest(list, page, chunks.len(), per_page);
                for i in *slice
                {
                    issue_fields(&mut d, i);
                }
                (
                    slice.iter().map(issue_json).collect(),
                    chunks.len(),
                    d.hex(),
                )
            }
        };
        Ok(json!({
            "list": list.name(),
            "head": self.head,
            "from_sha": self.from_sha,
            "page": page,
            "pages": pages,
            "page_entries": per_page,
            "items": items,
            "digest": digest,
        }))
    }

    /// The summary: everything but the lists, each list's count, page count
    /// and digest, and the digest of these fields.
    fn summary(&self, per_page: usize) -> Value
    {
        let files = (
            self.files.len(),
            page_count(self.files.len(), per_page),
            list_digest(List::Files, &self.files, file_fields),
        );
        let entries = unit_entries(&self.units);
        let units = (
            self.units.len(),
            page_count(entries, per_page),
            list_digest(List::Units, &self.units, unit_fields),
        );
        let issues = (
            self.issues.len(),
            page_count(self.issues.len(), per_page),
            list_digest(List::Issues, &self.issues, issue_fields),
        );
        let unit_file_entries: usize = self.units.iter().map(|u| u.files.len()).sum();
        let mut d = Digest::new();
        d.field("summary")
            .field(&self.head)
            .field(&self.from_sha)
            .field(&self.repo_root)
            .field(&self.tree_at_head.to_string())
            .field(&self.from_ancestor.to_string())
            .field(&self.version_at_head)
            .field(&self.version_at_from)
            .field(&per_page.to_string());
        for (count, pages, digest) in [&files, &units, &issues]
        {
            d.field(&count.to_string())
                .field(&pages.to_string())
                .field(digest);
        }
        d.field(&unit_file_entries.to_string())
            .field(&self.milestones.len().to_string());
        for m in &self.milestones
        {
            d.field(m);
        }
        json!({
            "head": self.head,
            "from_sha": self.from_sha,
            "repo_root": self.repo_root,
            "tree_at_head": self.tree_at_head,
            "from_ancestor": self.from_ancestor,
            "version_at_head": self.version_at_head,
            "version_at_from": self.version_at_from,
            "page_entries": per_page,
            "range_file_count": files.0,
            "range_file_pages": files.1,
            "range_files_digest": files.2,
            "unit_count": units.0,
            "unit_pages": units.1,
            "units_digest": units.2,
            "open_issue_count": issues.0,
            "open_issue_pages": issues.1,
            "open_issues_digest": issues.2,
            "unit_file_entries": unit_file_entries,
            "milestones": self.milestones,
            "digest": d.hex(),
        })
    }
}

/// Page `page` (1-based) of `pages`, or an error naming the valid range.
fn page_slice<T>(pages: &[T], list: List, page: usize) -> Result<&T>
{
    page.checked_sub(1)
        .and_then(|i| pages.get(i))
        .with_context(|| {
            format!(
                "{} has {} page(s); page {page} does not exist",
                list.name(),
                pages.len()
            )
        })
}

/// `--page <list>:<n>`.
fn parse_page(spec: &str) -> Result<(List, usize)>
{
    let (name, number) = spec
        .split_once(':')
        .with_context(|| format!("--page takes <list>:<n>, not {spec}"))?;
    let list = match name
    {
        "files" => List::Files,
        "units" => List::Units,
        "issues" => List::Issues,
        _ => bail!("--page names files, units, or issues, not {name}"),
    };
    let page = number
        .parse()
        .with_context(|| format!("--page takes a page number, not {number}"))?;
    Ok((list, page))
}

// ── Reading the scope ─────────────────────────────────────────────────────────

fn git(root: &Path, args: &[&str]) -> Result<String>
{
    run_cmd_capture(Command::new("git").args(args).current_dir(root))
        .with_context(|| format!("git {}", args.join(" ")))
}

fn commit(root: &Path, rev: &str) -> Result<String>
{
    Ok(git(
        root,
        &["rev-parse", "--verify", &format!("{rev}^{{commit}}")],
    )?
    .trim()
    .to_owned())
}

fn version_at(root: &Path, sha: &str) -> Result<String>
{
    let manifest = git(root, &["show", &format!("{sha}:Cargo.toml")])?;
    workspace_version(&manifest)
        .with_context(|| format!("no [workspace.package] version in Cargo.toml at {sha}"))
}

fn read_units(root: &Path, from_sha: &str, head: &str) -> Result<Vec<Unit>>
{
    let shas = git(
        root,
        &[
            "log",
            "--first-parent",
            "--format=%H",
            &format!("{from_sha}..{head}"),
        ],
    )?;
    let mut units = Vec::new();
    for sha in shas.lines().filter(|l| !l.is_empty())
    {
        let message = git(root, &["log", "-1", "--format=%s%x00%b", sha])?;
        let (subject, body) = message.split_once('\0').unwrap_or((message.trim(), ""));
        let (pr, title) = title_of(subject, body);
        let files = nul_paths(&git(
            root,
            &[
                "diff",
                "--name-only",
                "--no-renames",
                "-z",
                &format!("{sha}^1"),
                sha,
            ],
        )?);
        units.push(Unit {
            sha: sha.to_owned(),
            pr,
            title,
            files,
        });
    }
    Ok(units)
}

fn read_files(root: &Path, from_sha: &str, head: &str) -> Result<Vec<RangeFile>>
{
    let at_head: HashSet<String> =
        nul_paths(&git(root, &["ls-tree", "-r", "-z", "--name-only", head])?)
            .into_iter()
            .collect();
    let stats = numstat(&git(
        root,
        &["diff", "--numstat", "--no-renames", "-z", from_sha, head],
    )?)?;
    Ok(stats
        .into_iter()
        .map(|(path, changed)| RangeFile {
            at_head: at_head.contains(&path),
            kind: kind_of(&path),
            path,
            changed,
        })
        .collect())
}

fn read_issues(root: &Path) -> Result<Vec<Issue>>
{
    let limit = ISSUE_LIMIT.to_string();
    let list = gh::json(
        root,
        &[
            "issue",
            "list",
            "--state",
            "open",
            "--limit",
            &limit,
            "--json",
            "number,title",
        ],
    )?;
    let mut issues: Vec<Issue> = list
        .as_array()
        .context("gh issue list returned no list")?
        .iter()
        .map(|i| {
            Ok(Issue {
                number: i["number"].as_u64().context("an Issue without a number")?,
                title: i["title"].as_str().unwrap_or_default().to_owned(),
            })
        })
        .collect::<Result<_>>()?;
    if issues.len() >= ISSUE_LIMIT
    {
        bail!("{ISSUE_LIMIT} or more open Issues: the list may be truncated");
    }
    issues.sort_by_key(|i| i.number);
    Ok(issues)
}

fn read_scope(root: &Path, from: &str, head: &str, list: Option<List>) -> Result<Scope>
{
    let head = commit(root, head)?;
    let from_sha = commit(root, from)?;
    let checked_out = commit(root, "HEAD")?;
    let clean = git(root, &["status", "--porcelain"])?.trim().is_empty();
    let from_ancestor = Command::new("git")
        .args(["merge-base", "--is-ancestor", &from_sha, &head])
        .current_dir(root)
        .status()
        .context("failed to launch git merge-base")?
        .success();
    let summary = list.is_none();
    let wants = |l: List| summary || list == Some(l);
    Ok(Scope {
        repo_root: git(root, &["rev-parse", "--show-toplevel"])?
            .trim()
            .to_owned(),
        tree_at_head: clean && checked_out == head,
        from_ancestor,
        version_at_head: version_at(root, &head)?,
        version_at_from: version_at(root, &from_sha)?,
        milestones: if summary
        {
            gh::open_milestones(root)?
        }
        else
        {
            Vec::new()
        },
        files: if wants(List::Files)
        {
            read_files(root, &from_sha, &head)?
        }
        else
        {
            Vec::new()
        },
        units: if wants(List::Units)
        {
            read_units(root, &from_sha, &head)?
        }
        else
        {
            Vec::new()
        },
        issues: if wants(List::Issues)
        {
            read_issues(root)?
        }
        else
        {
            Vec::new()
        },
        head,
        from_sha,
    })
}

/// Entry point for `cargo xtask release-scope`.
pub fn run(ctx: &BuildContext, args: &ReleaseScopeArgs) -> Result<()>
{
    let per_page = usize::try_from(args.page_entries).context("--page-entries is too large")?;
    let page = args.page.as_deref().map(parse_page).transpose()?;
    let scope = read_scope(&ctx.root, &args.from, &args.head, page.map(|(l, _)| l))?;
    let out = match page
    {
        Some((list, n)) => scope.page(list, n, per_page)?,
        None => scope.summary(per_page),
    };
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}

#[cfg(test)]
mod tests
{
    use super::*;

    fn unit(sha: &str, files: usize) -> Unit
    {
        Unit {
            sha: sha.to_owned(),
            pr: 1,
            title: format!("unit {sha}"),
            files: (0..files).map(|i| format!("{sha}/f{i}.rs")).collect(),
        }
    }

    #[test]
    fn the_digest_of_the_shared_vector_is_pinned()
    {
        // The workflow script's self-test digests the same fields and pins
        // the same value; a change to either encoding breaks one of them.
        let mut d = Digest::new();
        d.field("seraph").field("").field("é→1");
        assert_eq!(d.hex(), "cd2f6e72302ab053");
    }

    #[test]
    fn the_digest_separates_fields()
    {
        let mut a = Digest::new();
        a.field("ab").field("c");
        let mut b = Digest::new();
        b.field("a").field("bc");
        assert_ne!(a.hex(), b.hex());
    }

    #[test]
    fn a_large_unit_is_split_across_pages_without_exceeding_the_bound()
    {
        let units = vec![unit("a", 3), unit("b", 7), unit("c", 0), unit("d", 2)];
        let pages = unit_pages(&units, 4);
        for page in &pages
        {
            let entries: usize = page.iter().map(|c| c.files.len().max(1)).sum();
            assert!(entries <= 4, "a page holds {entries} entries");
        }
        assert_eq!(pages.len(), page_count(unit_entries(&units), 4));
        // Joining the chunks in order restores every unit, its files in
        // order, and each chunk's offset is the files already seen.
        let mut joined: Vec<(String, Vec<String>)> = Vec::new();
        for c in pages.iter().flatten()
        {
            match joined.last_mut()
            {
                Some((sha, files)) if *sha == c.unit.sha && c.offset > 0 =>
                {
                    assert_eq!(c.offset, files.len());
                    files.extend_from_slice(c.files);
                }
                _ =>
                {
                    assert_eq!(c.offset, 0);
                    joined.push((c.unit.sha.clone(), c.files.to_vec()));
                }
            }
        }
        let expected: Vec<(String, Vec<String>)> = units
            .iter()
            .map(|u| (u.sha.clone(), u.files.clone()))
            .collect();
        assert_eq!(joined, expected);
    }

    #[test]
    fn units_that_fill_a_page_exactly_open_no_empty_page()
    {
        let units = vec![unit("a", 2), unit("b", 2)];
        let pages = unit_pages(&units, 2);
        assert_eq!(pages.len(), 2);
        assert!(pages.iter().all(|p| p.len() == 1));
        assert_eq!(unit_pages(&[], 2).len(), 0);
    }

    #[test]
    fn a_unit_with_no_file_takes_one_entry()
    {
        let units = vec![unit("a", 1), unit("b", 0), unit("c", 1)];
        let pages = unit_pages(&units, 2);
        assert_eq!(pages.len(), 2);
        assert_eq!(pages[0][1].unit.sha, "b");
        assert_eq!(pages[0][1].files.len(), 0);
        assert_eq!(unit_entries(&units), 3);
    }

    #[test]
    fn paths_are_classified_by_their_place_and_extension()
    {
        assert_eq!(kind_of(".claude/workflows/release-review.js"), "rules");
        assert_eq!(kind_of(".github/pull_request_template.md"), "rules");
        assert_eq!(kind_of("docs/conventions.md"), "markdown");
        assert_eq!(kind_of("core/kernel/README.MD"), "markdown");
        assert_eq!(kind_of("LICENSE"), "other");
        assert_eq!(kind_of("rootfs/.gitkeep"), "other");
        assert_eq!(kind_of("core/kernel/src/main.rs"), "code");
        assert_eq!(
            kind_of("xtask/baselines/ktest-timing/x86_64-16cpu.txt"),
            "code"
        );
        assert_eq!(kind_of("Cargo.lock"), "code");
    }

    #[test]
    fn a_merge_is_titled_by_its_body_and_another_commit_by_its_subject()
    {
        assert_eq!(
            title_of(
                "Merge pull request #1034 from kottlerg/chore/x",
                "\nclaude: allow issue-edit\n\nmore\n"
            ),
            (1034, "claude: allow issue-edit".to_owned())
        );
        assert_eq!(
            title_of("Merge pull request #7 from a/b", ""),
            (7, "Merge pull request #7 from a/b".to_owned())
        );
        assert_eq!(
            title_of("docs: fix a typo", "body"),
            (0, "docs: fix a typo".to_owned())
        );
        assert_eq!(pr_of("Merge pull request #12x from a"), None);
        assert_eq!(pr_of("Merge pull request # from a"), None);
        assert_eq!(pr_of("Merge pull request #12"), Some(12));
    }

    #[test]
    fn the_workspace_version_is_read_from_its_section_only()
    {
        let manifest = "[package]\nversion = \"9.9.9\"\n\n[workspace.package]\nedition = \
                        \"2024\"\nversion = \"0.1.4\"\n\n[workspace]\nversion = \"1.0.0\"\n";
        assert_eq!(workspace_version(manifest), Some("0.1.4".to_owned()));
        assert_eq!(workspace_version("[package]\nversion = \"1.0.0\"\n"), None);
    }

    #[test]
    fn numstat_records_count_binary_files_as_zero_and_keep_tabs_in_paths()
    {
        let out = concat!(
            "3\t4\tsrc/a.rs\0",
            "-\t-\timg.bin\0",
            "0\t1\tdir/with\ttab\0"
        );
        assert_eq!(
            numstat(out).unwrap(),
            vec![
                ("src/a.rs".to_owned(), 7),
                ("img.bin".to_owned(), 0),
                ("dir/with\ttab".to_owned(), 1),
            ]
        );
        numstat("3\tsrc/a.rs\0").unwrap_err();
        numstat("x\t1\tsrc/a.rs\0").unwrap_err();
    }

    #[test]
    fn a_page_is_named_by_list_and_number()
    {
        assert_eq!(parse_page("units:3").unwrap(), (List::Units, 3));
        assert_eq!(parse_page("issues:1").unwrap(), (List::Issues, 1));
        parse_page("units").unwrap_err();
        parse_page("commits:1").unwrap_err();
        parse_page("files:x").unwrap_err();
    }

    fn scope() -> Scope
    {
        Scope {
            head: "h".repeat(40),
            from_sha: "f".repeat(40),
            repo_root: "/repo".to_owned(),
            tree_at_head: true,
            from_ancestor: true,
            version_at_head: "0.1.3".to_owned(),
            version_at_from: "0.1.3".to_owned(),
            milestones: vec!["v0.1.4".to_owned()],
            files: (0..5)
                .map(|i| RangeFile {
                    path: format!("f{i}.rs"),
                    changed: i,
                    at_head: true,
                    kind: "code",
                })
                .collect(),
            units: vec![unit("a", 3), unit("b", 0)],
            issues: vec![Issue {
                number: 1,
                title: "t".to_owned(),
            }],
        }
    }

    #[test]
    fn a_page_outside_the_list_is_refused()
    {
        let s = scope();
        s.page(List::Files, 0, 2).unwrap_err();
        s.page(List::Files, 4, 2).unwrap_err();
        let last = s.page(List::Files, 3, 2).unwrap();
        assert_eq!(last["items"].as_array().unwrap().len(), 1);
        assert_eq!(last["pages"], 3);
    }

    #[test]
    fn the_summary_counts_each_list_in_the_pages_it_prints()
    {
        let s = scope();
        let summary = s.summary(2);
        assert_eq!(summary["range_file_count"], 5);
        assert_eq!(summary["range_file_pages"], 3);
        assert_eq!(summary["unit_count"], 2);
        assert_eq!(summary["unit_file_entries"], 3);
        assert_eq!(summary["unit_pages"], 2);
        assert_eq!(summary["open_issue_pages"], 1);
        let pages = summary["unit_pages"].as_u64().unwrap();
        for n in 1..=pages
        {
            s.page(List::Units, usize::try_from(n).unwrap(), 2).unwrap();
        }
        s.page(List::Units, 3, 2).unwrap_err();
    }
}
