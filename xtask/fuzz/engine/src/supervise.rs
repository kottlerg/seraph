// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/fuzz/engine/src/supervise.rs

//! The supervising parent: it runs the fuzzing run in a child process and,
//! when the child ends without reporting (a signal, an `AddressSanitizer` error,
//! the allocation cap, the per-input time limit), reports the input the child
//! saved before its last execution, minimized by replaying candidates in
//! fresh processes while the process ends the same way.

use std::collections::VecDeque;
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};
use std::thread;

use crate::args::Options;
use crate::cap::EXIT_ALLOCATION_CAP;
use crate::exec::{self, EXIT_TIMEOUT, TIME_LIMIT};
use crate::fuzz::{self, CURRENT_INPUT};
use crate::minimize::minimize;
use crate::report::Crash;
use crate::{EXIT_ERROR, EXIT_FAILED, EXIT_REPORTED, Target};

/// The variable that marks the child process.
pub const ROLE: &str = "SERAPH_FUZZ_CHILD";

/// The exit status of an `AddressSanitizer` error, set through
/// `ASAN_OPTIONS`.
pub const EXIT_ASAN: i32 = 73;

/// The `AddressSanitizer` options of every process the supervisor starts: its
/// error status, and no leak check, since a leak is not a parser's failure
/// and the check runs at exit.
const ASAN_OPTIONS: &str = "exitcode=73:detect_leaks=0";

/// The file a candidate of the minimization is written to.
const CANDIDATE: &str = ".candidate";

/// The most bytes of the child's output the report keeps.
const OUTPUT_TAIL: usize = 64 << 10;

/// The most candidates the minimization of an abort tries; each is a process.
const MINIMIZE_BUDGET: usize = 2000;

/// How a process ended, by its exit status and, on Unix, its signal; `None`
/// for a clean exit.
#[must_use]
pub fn ending(code: Option<i32>, signal: Option<i32>) -> Option<String>
{
    match (code, signal)
    {
        (Some(0), _) => None,
        (Some(EXIT_TIMEOUT), _) => Some(format!(
            "the per-input time limit of {} s",
            TIME_LIMIT.as_secs()
        )),
        (Some(EXIT_ALLOCATION_CAP), _) => Some("the allocation cap".to_owned()),
        (Some(EXIT_ASAN), _) => Some("an AddressSanitizer error".to_owned()),
        (Some(code), _) => Some(format!("exit status {code}")),
        (None, Some(signal)) => Some(format!("signal {signal} ({})", signal_name(signal))),
        (None, None) => Some("an unknown ending".to_owned()),
    }
}

/// The name of a common fatal signal.
fn signal_name(signal: i32) -> &'static str
{
    match signal
    {
        4 => "SIGILL",
        6 => "SIGABRT",
        7 => "SIGBUS",
        8 => "SIGFPE",
        9 => "SIGKILL",
        11 => "SIGSEGV",
        _ => "another signal",
    }
}

/// How `status` ended, as [`ending`] describes it.
fn status_ending(status: ExitStatus) -> Option<String>
{
    #[cfg(unix)]
    let signal = std::os::unix::process::ExitStatusExt::signal(&status);
    #[cfg(not(unix))]
    let signal = None;
    ending(status.code(), signal)
}

/// Copy the child's output `from` to `to`, and return its last
/// [`OUTPUT_TAIL`] bytes.
fn copy_tail(mut from: impl Read, mut to: impl Write) -> Vec<u8>
{
    let mut tail = VecDeque::new();
    let mut buffer = [0u8; 4096];
    while let Ok(read) = from.read(&mut buffer)
    {
        let Some(chunk) = buffer.get(..read).filter(|chunk| !chunk.is_empty())
        else
        {
            break;
        };
        let _ = to.write_all(chunk);
        tail.extend(chunk);
        let excess = tail.len().saturating_sub(OUTPUT_TAIL);
        tail.drain(..excess);
    }
    tail.into()
}

/// Run the fuzzing run of `target` in a child process and report an ending it
/// did not report itself. Returns 0 for a run without a crash,
/// [`EXIT_FAILED`] for a reported crash, and [`EXIT_ERROR`] when the run
/// could not be made.
#[must_use]
pub fn supervise(target: &Target, options: &Options) -> i32
{
    let exe = match env::current_exe()
    {
        Ok(exe) => exe,
        Err(err) =>
        {
            eprintln!("fuzz: {}: locating the target binary: {err}", target.name);
            return EXIT_ERROR;
        }
    };
    let child = fixed_layout(&mut Command::new(&exe))
        .args(env::args_os().skip(1))
        .env(ROLE, "1")
        .env("ASAN_OPTIONS", ASAN_OPTIONS)
        .stderr(Stdio::piped())
        .spawn();
    let mut child = match child
    {
        Ok(child) => child,
        Err(err) =>
        {
            eprintln!("fuzz: {}: starting the run: {err}", target.name);
            return EXIT_ERROR;
        }
    };
    let copier = child
        .stderr
        .take()
        .map(|stderr| thread::spawn(move || copy_tail(stderr, std::io::stderr())));
    let status = child.wait();
    let output = copier
        .and_then(|copier| copier.join().ok())
        .unwrap_or_default();
    match status.map(|status| (status.code(), status_ending(status)))
    {
        Ok((_, None)) => 0,
        Ok((Some(EXIT_REPORTED), _)) => EXIT_FAILED,
        Ok((Some(EXIT_ERROR), _)) => EXIT_ERROR,
        Ok((_, Some(what))) => report_abort(target, options, &exe, what, &output),
        Err(err) =>
        {
            eprintln!("fuzz: {}: waiting for the run: {err}", target.name);
            EXIT_ERROR
        }
    }
}

/// Start `command`'s process with address-space randomization off, so its
/// address space is laid out the same at every start of the same binary.
/// Instrumented code compares addresses (the fuzz profile's UB checks align
/// and order pointers), those operands reach the compare table and the
/// dictionary, and so the mutations a seed draws: only a fixed layout makes a
/// run from a fixed seed reproducible.
#[cfg(target_os = "linux")]
fn fixed_layout(command: &mut Command) -> &mut Command
{
    use std::ffi::{c_int, c_ulong};
    use std::os::unix::process::CommandExt as _;

    /// `ADDR_NO_RANDOMIZE` of `<sys/personality.h>`.
    const ADDR_NO_RANDOMIZE: c_ulong = 0x0004_0000;
    /// The persona that reads the process's personality without changing it.
    const QUERY: c_ulong = 0xFFFF_FFFF;

    unsafe extern "C" {
        /// personality(2), from the C library std links.
        fn personality(persona: c_ulong) -> c_int;
    }

    let set = || {
        // SAFETY: personality(2) takes a plain integer and touches no memory
        // of the caller's; it is async-signal-safe, so it may run in the
        // forked child before exec.
        let current = unsafe { personality(QUERY) };
        let current = c_ulong::try_from(current).map_err(|_| std::io::Error::last_os_error())?;
        // SAFETY: as above.
        if unsafe { personality(current | ADDR_NO_RANDOMIZE) } < 0
        {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    };
    // SAFETY: the hook runs in the forked child before exec and only calls
    // personality(2) and reads errno, all async-signal-safe and free of
    // allocation and locks.
    unsafe { command.pre_exec(set) }
}

/// Start `command`'s process as the host lays it out: without a way to turn
/// randomization off, a run from a fixed seed is reproducible only as far as
/// the layout repeats.
#[cfg(not(target_os = "linux"))]
fn fixed_layout(command: &mut Command) -> &mut Command
{
    command
}

/// How a replay of `input` in a fresh process ends, and its output.
fn replay_ending(exe: &Path, options: &Options, input: &[u8]) -> (Option<String>, Vec<u8>)
{
    let candidate = options.work.join(CANDIDATE);
    if fs::write(&candidate, input).is_err()
    {
        return (None, Vec::new());
    }
    let output = Command::new(exe)
        .arg("--root")
        .arg(&options.root)
        .arg("--work")
        .arg(&options.work)
        .arg("--replay")
        .arg(&candidate)
        .env_remove(ROLE)
        .env("ASAN_OPTIONS", ASAN_OPTIONS)
        .stdin(Stdio::null())
        .output();
    match output
    {
        Ok(output) => (status_ending(output.status), output.stderr),
        Err(_) => (None, Vec::new()),
    }
}

/// Report the input the child saved before it ended as `what` says, minimized
/// while a replay ends the same way (an input over the time limit is reported
/// as saved, since each of its replays takes the limit).
fn report_abort(target: &Target, options: &Options, exe: &Path, what: String, output: &[u8])
-> i32
{
    let saved = fs::read(options.work.join(CURRENT_INPUT)).unwrap_or_default();
    let Some((execution, found)) = exec::read_current(&saved)
    else
    {
        eprintln!(
            "fuzz: {}: the run ended with {what} before its first execution",
            target.name
        );
        return EXIT_ERROR;
    };
    let (input, details) = if what.starts_with("the per-input time limit")
    {
        (found.to_vec(), output.to_vec())
    }
    else
    {
        let input = minimize(found, MINIMIZE_BUDGET, |candidate| {
            replay_ending(exe, options, candidate).0.as_deref() == Some(&what)
        });
        let (_, replayed) = replay_ending(exe, options, &input);
        (input, replayed)
    };
    let crash = Crash {
        what,
        location: None,
        execution,
        seed: options.seed,
        found_len: found.len(),
        input,
        details: format!("output:\n{}", String::from_utf8_lossy(&details)),
    };
    let _ = fs::remove_file(options.work.join(CANDIDATE));
    match fuzz::write_crash(target, options, &crash)
    {
        EXIT_REPORTED => EXIT_FAILED,
        status => status,
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    // Defect caught: an abort read as a clean run, or two different endings
    // given one description, which would merge their deduplication keys.
    #[test]
    fn each_ending_has_its_own_description_and_a_clean_exit_has_none()
    {
        assert_eq!(ending(Some(0), None), None);
        let endings = [
            ending(Some(EXIT_TIMEOUT), None),
            ending(Some(EXIT_ALLOCATION_CAP), None),
            ending(Some(EXIT_ASAN), None),
            ending(Some(101), None),
            ending(None, Some(11)),
            ending(None, Some(6)),
        ];
        for (index, one) in endings.iter().enumerate()
        {
            assert!(one.is_some(), "{index}");
            assert!(!endings[index + 1..].contains(one), "{one:?}");
        }
        assert_eq!(ending(None, Some(11)).unwrap(), "signal 11 (SIGSEGV)");
    }

    #[test]
    fn the_copied_output_keeps_its_tail()
    {
        let output: Vec<u8> = (0..OUTPUT_TAIL + 10)
            .map(|i| u8::try_from(i % 251).unwrap())
            .collect();
        let tail = copy_tail(&output[..], std::io::sink());
        assert_eq!(tail.len(), OUTPUT_TAIL);
        assert_eq!(tail[..], output[10..]);
    }
}
