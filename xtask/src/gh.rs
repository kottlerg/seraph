// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/gh.rs

//! Thin wrappers over the GitHub CLI (`gh`) for the pull-request and Issue
//! commands: each runs one `gh` invocation in the repository and returns its
//! output. `gh` resolves the repository from the clone's remote and carries
//! its own authentication.

use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};
use serde_json::Value;

use crate::util::require_tool;

/// Run `gh <args>` in `root` and return its stdout. On failure the error
/// carries gh's own message.
pub fn run(root: &Path, args: &[&str]) -> Result<String>
{
    let gh = require_tool("gh")?;
    let output = Command::new(gh)
        .args(args)
        .current_dir(root)
        .output()
        .context("failed to launch gh")?;
    if !output.status.success()
    {
        bail!(
            "gh {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Run `gh <args>` and parse its stdout as JSON.
pub fn json(root: &Path, args: &[&str]) -> Result<Value>
{
    let out = run(root, args)?;
    serde_json::from_str(&out).with_context(|| format!("gh {} returned no JSON", args.join(" ")))
}

/// An Issue's number, title, body, milestone, labels, and state.
pub fn issue(root: &Path, number: u64) -> Result<Value>
{
    json(
        root,
        &[
            "issue",
            "view",
            &number.to_string(),
            "--json",
            "number,title,body,milestone,labels,state",
        ],
    )
}

/// The largest list `open_issues_in` reads; `gh` may truncate a longer one.
const ISSUE_LIST_LIMIT: usize = 1000;

/// The number and title of every open Issue that carries `milestone`. Refuses
/// a list of `ISSUE_LIST_LIMIT` entries, which `gh` may have truncated.
pub fn open_issues_in(root: &Path, milestone: &str) -> Result<Vec<(u64, String)>>
{
    let limit = ISSUE_LIST_LIMIT.to_string();
    let list = json(
        root,
        &[
            "issue",
            "list",
            "--state",
            "open",
            "--milestone",
            milestone,
            "--limit",
            &limit,
            "--json",
            "number,title",
        ],
    )?;
    let issues: Vec<(u64, String)> = list
        .as_array()
        .map_or(&[][..], Vec::as_slice)
        .iter()
        .filter_map(|i| {
            Some((
                i.get("number")?.as_u64()?,
                i.get("title")?.as_str()?.to_owned(),
            ))
        })
        .collect();
    if issues.len() >= ISSUE_LIST_LIMIT
    {
        bail!(
            "milestone {milestone} lists {ISSUE_LIST_LIMIT} open Issues or more; gh may have \
             truncated the list"
        );
    }
    Ok(issues)
}

/// The titles of the repository's open milestones.
pub fn open_milestones(root: &Path) -> Result<Vec<String>>
{
    let out = run(
        root,
        &[
            "api",
            "repos/{owner}/{repo}/milestones?state=open&per_page=100",
            "--jq",
            ".[].title",
        ],
    )?;
    Ok(out
        .lines()
        .filter(|l| !l.is_empty())
        .map(str::to_owned)
        .collect())
}
