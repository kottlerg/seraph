// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/fuzz/engine/src/report.rs

//! A crash's files: the minimized input, `crashes/<hash>`, and its report,
//! `crashes/<hash>.txt`, `<hash>` being the FNV-1a hash of the crash's
//! deduplication key (a panic's location, or the way the process ended), so
//! a crash found again overwrites its own files.

use std::fmt::Write as _;
use std::io;
use std::path::{Path, PathBuf};

/// The FNV-1a 64-bit hash of `bytes`.
#[must_use]
pub fn fnv1a(bytes: &[u8]) -> u64
{
    bytes.iter().fold(0xCBF2_9CE4_8422_2325u64, |hash, &byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01B3)
    })
}

/// A crash ready to report.
pub struct Crash
{
    /// What failed: a panic's message, or how the process ended.
    pub what: String,
    /// The panic's location, `file:line:column`; `None` for a process that
    /// ended without one.
    pub location: Option<String>,
    /// The execution, counted from 1, at which the run found it.
    pub execution: u64,
    /// The run's seed.
    pub seed: u64,
    /// The length of the input before minimization.
    pub found_len: usize,
    /// The minimized input.
    pub input: Vec<u8>,
    /// The backtrace of the panic, or the output the process ended with.
    pub details: String,
}

impl Crash
{
    /// The deduplication key: the location, or the way the process ended.
    #[must_use]
    pub fn key(&self) -> &str
    {
        self.location.as_deref().unwrap_or(&self.what)
    }
}

/// Write `crash` of `target` under `work`/crashes and return the input's
/// path.
///
/// # Errors
///
/// Returns the error of a directory or a file that could not be written.
pub fn write(work: &Path, target: &str, crash: &Crash) -> io::Result<PathBuf>
{
    let dir = work.join("crashes");
    std::fs::create_dir_all(&dir)?;
    let name = format!("{:016x}", fnv1a(crash.key().as_bytes()));
    let input = dir.join(&name);
    std::fs::write(&input, &crash.input)?;
    std::fs::write(
        dir.join(format!("{name}.txt")),
        render(target, crash, &input),
    )?;
    Ok(input)
}

/// The report of `crash` of `target`, its minimized input saved at `input`.
/// `cargo xtask fuzz --self-test` reads its `location:` and `execution:`
/// lines.
#[must_use]
pub fn render(target: &str, crash: &Crash, input: &Path) -> String
{
    let mut text = String::new();
    let _ = writeln!(text, "target: {target}");
    let _ = writeln!(text, "failure: {}", crash.what);
    let _ = writeln!(
        text,
        "location: {}",
        crash
            .location
            .as_deref()
            .unwrap_or("none (the process ended)")
    );
    let _ = writeln!(text, "execution: {}", crash.execution);
    let _ = writeln!(text, "seed: {}", crash.seed);
    let _ = writeln!(
        text,
        "input: {} ({} bytes, minimized from {})",
        input.display(),
        crash.input.len(),
        crash.found_len
    );
    let _ = writeln!(
        text,
        "replay: cargo xtask fuzz {target} --replay {}",
        input.display()
    );
    let _ = writeln!(text, "\n{}", crash.details.trim_end());
    text
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn fnv1a_matches_its_reference_values()
    {
        assert_eq!(fnv1a(b""), 0xCBF2_9CE4_8422_2325);
        assert_eq!(fnv1a(b"a"), 0xAF63_DC4C_8601_EC8C);
    }

    // Defect caught: a report without the lines the self-test and a reader
    // rely on, or one that names a different input than the one written.
    #[test]
    fn a_written_crash_holds_its_input_and_a_report_naming_it()
    {
        let work = std::env::temp_dir().join(format!("fuzz-engine-report-{}", std::process::id()));
        let crash = Crash {
            what: "attempt to add with overflow".into(),
            location: Some("src/bin/planted.rs:10:5".into()),
            execution: 42,
            seed: 0,
            found_len: 9,
            input: vec![1, 2, 3],
            details: "backtrace".into(),
        };
        let input = write(&work, "planted", &crash).unwrap();
        assert_eq!(std::fs::read(&input).unwrap(), [1, 2, 3]);
        let report = std::fs::read_to_string(input.with_extension("txt")).unwrap();
        for line in [
            "location: src/bin/planted.rs:10:5\n",
            "execution: 42\n",
            &format!(
                "replay: cargo xtask fuzz planted --replay {}\n",
                input.display()
            ),
        ]
        {
            assert!(report.contains(line), "{line:?} not in {report}");
        }
        std::fs::remove_dir_all(&work).unwrap();
    }
}
