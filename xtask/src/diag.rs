// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/diag.rs

//! Diagnostics shared by the pull-request, review-record, and Issue checks.
//!
//! Each check returns `Diag` values; a command prints them as
//! `<level> <rule>: <where>: <message>` and fails when any is an error, or,
//! under `--strict`, when any is a warning.

use std::fmt;

use anyhow::{Result, bail};

/// Rule severity. A warning is printed and counted; it fails the command only
/// under `Strictness::Strict`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level
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

/// Whether warnings fail a run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Strictness
{
    /// Only errors fail the run.
    ErrorsOnly,
    /// Warnings fail the run too.
    Strict,
}

impl Strictness
{
    /// The strictness a command's `--strict` flag selects.
    pub fn from_flag(strict: bool) -> Self
    {
        if strict
        {
            Strictness::Strict
        }
        else
        {
            Strictness::ErrorsOnly
        }
    }
}

/// One finding of a check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Diag
{
    pub level: Level,
    pub rule: &'static str,
    /// What the finding is about: a commit, a file and line, or a field.
    pub at: String,
    pub message: String,
}

impl Diag
{
    pub fn error(rule: &'static str, at: impl Into<String>, message: impl Into<String>) -> Self
    {
        Diag {
            level: Level::Error,
            rule,
            at: at.into(),
            message: message.into(),
        }
    }

    pub fn warning(rule: &'static str, at: impl Into<String>, message: impl Into<String>) -> Self
    {
        Diag {
            level: Level::Warning,
            rule,
            at: at.into(),
            message: message.into(),
        }
    }
}

impl fmt::Display for Diag
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        write!(
            f,
            "{} {}: {}: {}",
            self.level, self.rule, self.at, self.message
        )
    }
}

/// Whether `diags` fails a run under `strictness`.
pub fn fails(diags: &[Diag], strictness: Strictness) -> bool
{
    diags.iter().any(|d| match d.level
    {
        Level::Error => true,
        Level::Warning => strictness == Strictness::Strict,
    })
}

/// Print every diagnostic and a summary line, and return an error when the
/// run fails.
pub fn report(name: &str, diags: &[Diag], strictness: Strictness) -> Result<()>
{
    for diag in diags
    {
        println!("{diag}");
    }
    let errors = diags.iter().filter(|d| d.level == Level::Error).count();
    let warnings = diags.iter().filter(|d| d.level == Level::Warning).count();
    println!("==> {name}: {errors} error(s), {warnings} warning(s)");
    if fails(diags, strictness)
    {
        bail!("{name} failed");
    }
    Ok(())
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn a_warning_fails_a_run_only_when_strict()
    {
        let warning = [Diag::warning("r", "x", "m")];
        assert!(!fails(&warning, Strictness::ErrorsOnly));
        assert!(fails(&warning, Strictness::Strict));
        assert!(fails(&[Diag::error("r", "x", "m")], Strictness::ErrorsOnly));
        assert!(!fails(&[], Strictness::Strict));
    }
}
