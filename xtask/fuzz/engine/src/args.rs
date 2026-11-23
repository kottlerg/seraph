// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/fuzz/engine/src/args.rs

//! The command line of a fuzz target binary, which `cargo xtask fuzz` writes:
//!
//! ```text
//! <target> --root DIR --work DIR [--seed S] (--runs N | --time SECS | --replay FILE | --minimize)
//! ```

use std::ffi::OsString;
use std::path::PathBuf;
use std::time::Duration;

/// What a run does.
#[derive(Debug, PartialEq, Eq)]
pub enum Mode
{
    /// Fuzz until the budget is spent or an input fails.
    Fuzz(Budget),
    /// Run the target once on the file's contents, outside the engine's panic
    /// catch, so a failure shows as it would anywhere.
    Replay(PathBuf),
    /// Minimize the working corpus by coverage.
    Minimize,
}

/// How long a fuzzing run lasts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Budget
{
    /// This many executions, the initial inputs' included: a run of a fixed
    /// count from a fixed seed is reproducible.
    Runs(u64),
    /// This long, by the wall clock.
    Time(Duration),
}

/// A parsed command line.
#[derive(Debug, PartialEq, Eq)]
pub struct Options
{
    /// The project root, which a target's checked-in input directory is
    /// relative to.
    pub root: PathBuf,
    /// The target's working directory: `corpus/`, `crashes/` and the
    /// supervisor's files.
    pub work: PathBuf,
    /// The seed of the run's random choices.
    pub seed: u64,
    /// What the run does.
    pub mode: Mode,
}

/// Parse the arguments after the program's name.
///
/// # Errors
///
/// Returns a message naming the argument at fault for an unknown option, an
/// option without its value, a value that is not a number, a missing
/// `--root` or `--work`, or a mode given twice or not at all.
pub fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Options, String>
{
    let mut args = args.into_iter();
    let (mut root, mut work, mut seed, mut mode) = (None, None, 0u64, None);
    while let Some(arg) = args.next()
    {
        let arg = arg.to_string_lossy().into_owned();
        let mut value = || args.next().ok_or_else(|| format!("{arg} needs a value"));
        let new_mode = match arg.as_str()
        {
            "--root" =>
            {
                root = Some(PathBuf::from(value()?));
                None
            }
            "--work" =>
            {
                work = Some(PathBuf::from(value()?));
                None
            }
            "--seed" =>
            {
                seed = number(&arg, &value()?)?;
                None
            }
            "--runs" => Some(Mode::Fuzz(Budget::Runs(number(&arg, &value()?)?))),
            "--time" => Some(Mode::Fuzz(Budget::Time(Duration::from_secs(number(
                &arg,
                &value()?,
            )?)))),
            "--replay" => Some(Mode::Replay(PathBuf::from(value()?))),
            "--minimize" => Some(Mode::Minimize),
            _ => return Err(format!("unknown argument {arg}")),
        };
        if let Some(new_mode) = new_mode
            && mode.replace(new_mode).is_some()
        {
            return Err(format!(
                "{arg}: only one of --runs, --time, --replay and --minimize"
            ));
        }
    }
    Ok(Options {
        root: root.ok_or("--root is required")?,
        work: work.ok_or("--work is required")?,
        seed,
        mode: mode.ok_or("one of --runs, --time, --replay and --minimize is required")?,
    })
}

/// `value` as a number, for the option `arg`.
fn number(arg: &str, value: &OsString) -> Result<u64, String>
{
    value
        .to_str()
        .and_then(|text| text.parse().ok())
        .ok_or_else(|| format!("{arg}: not a number: {}", value.to_string_lossy()))
}

#[cfg(test)]
mod tests
{
    use super::*;

    fn parse_words(words: &[&str]) -> Result<Options, String>
    {
        parse(words.iter().map(OsString::from))
    }

    #[test]
    fn a_full_command_line_parses_into_its_options()
    {
        let options = parse_words(&[
            "--root", "/r", "--work", "/w", "--seed", "9", "--runs", "500",
        ])
        .unwrap();
        assert_eq!(
            options,
            Options {
                root: PathBuf::from("/r"),
                work: PathBuf::from("/w"),
                seed: 9,
                mode: Mode::Fuzz(Budget::Runs(500)),
            }
        );
        let replay = parse_words(&["--replay", "f", "--root", "/r", "--work", "/w"]).unwrap();
        assert_eq!(replay.mode, Mode::Replay(PathBuf::from("f")));
        assert_eq!(replay.seed, 0);
    }

    #[test]
    fn a_command_line_without_one_mode_its_directories_or_a_valid_value_is_refused()
    {
        let base = ["--root", "/r", "--work", "/w"];
        for (extra, message) in [
            (&[][..], "is required"),
            (&["--runs", "1", "--minimize"][..], "only one of"),
            (&["--runs", "many"][..], "not a number"),
            (&["--time"][..], "needs a value"),
            (&["--bogus"][..], "unknown argument"),
        ]
        {
            let words: Vec<&str> = base.iter().chain(extra).copied().collect();
            let error = parse_words(&words).unwrap_err();
            assert!(error.contains(message), "{words:?}: {error}");
        }
        assert!(
            parse_words(&["--work", "/w", "--minimize"])
                .unwrap_err()
                .contains("--root")
        );
    }
}
