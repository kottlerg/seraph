// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/commands/test_logd_reclaim.rs

//! logd death-forward test: a child's death reaches logd and evicts its slot.
//!
//! logd has no read surface, so no harness can observe a slot. svctest's
//! `logd_death_forward` phase spawns a child that registers the log name
//! [`CHILD_NAME`] and exits with code [`CHILD_EXIT_REASON`]. procmgr's
//! teardown forwards the death to logd's death queue, and logd evicts the slot
//! and logs `reclaim: badge=<b> exit_reason=0x17 name=svctest-logd-reclaim`
//! (`services/logd/docs/ipc-interface.md` § Death-notification cascade). This
//! command reads a svctest boot's serial log and passes when the log holds
//! svctest's pass marker and exactly one such line. A log whose
//! `run-parallel` trailer records a `QEMU-CRASH` is skipped, not failed: that
//! outcome is a host-emulator crash, which `run-parallel` itself tolerates.
//!
//! `--log <file>` reads a saved log and boots nothing; CI passes the log its
//! svctest cell's `run-parallel --save-logs` boot saved. With no log, the
//! command boots the current sysroot once through `run-parallel` (svctest must
//! be staged, as for any svctest boot) and reads the log that boot saves.

use std::path::PathBuf;

use anyhow::{Context as _, Result, bail};

use crate::cli::{
    DEFAULT_FAIL_GRACE_SECS, DEFAULT_FAIL_REGEX, DEFAULT_PASS_REGEX, RunParallelArgs,
    TestLogdReclaimArgs,
};
use crate::commands::run_parallel::{QEMU_CRASH_LABEL, saved_log_file, saved_log_outcome};
use crate::context::Context;
use crate::util::step;

/// The log name svctest's `logd_death_forward` child registers
/// (`LOGD_RECLAIM_NAME` in `services/svctest/src/phases/procmgr.rs`).
const CHILD_NAME: &str = "svctest-logd-reclaim";

/// The code that child exits with (`LOGD_RECLAIM_EXIT_CODE`), which procmgr
/// posts to logd as the death's exit reason.
const CHILD_EXIT_REASON: u64 = 0x17;

/// svctest's terminal pass marker (docs/testing.md § Reporting marker).
const PASS_MARKER: &str = "[svctest] ALL TESTS PASSED";

/// The start of logd's death-drain reclaim line after its timestamp: logd's
/// self-log tag, then the line `logd_codec::reclaim` formats.
const RECLAIM_PREFIX: &str = "[logd] reclaim: badge=";

/// One death-drain reclaim line.
#[derive(Debug, PartialEq, Eq)]
struct Reclaim<'a>
{
    badge: u64,
    exit_reason: u64,
    name: &'a str,
}

/// What a log's check found.
#[derive(Debug, PartialEq, Eq)]
enum Verdict
{
    /// logd reclaimed the child's slot; the child's badge.
    Pass(u64),
    /// The boot's `run-parallel` outcome, a host-emulator crash: the log
    /// holds the guest's output only up to the crash, so it cannot show
    /// whether the guest completed, and nothing is checked.
    Skipped(String),
}

/// `line` without its leading `[<seconds>.<fraction>] ` timestamp, or
/// unchanged when it has none.
fn strip_timestamp(line: &str) -> &str
{
    let Some(rest) = line.strip_prefix('[')
    else
    {
        return line;
    };
    match rest.split_once("] ")
    {
        Some((stamp, after))
            if !stamp.is_empty() && stamp.bytes().all(|b| b.is_ascii_digit() || b == b'.') =>
        {
            after
        }
        _ => line,
    }
}

/// Parse `[<ts>] [logd] reclaim: badge=<dec> exit_reason=0x<hex> name=<name>`,
/// the tag at the line's start after the timestamp, so another sender's text
/// that quotes the line does not count. The name runs to the end of the line;
/// a trailing `\r` is not part of it.
fn parse_reclaim(line: &str) -> Option<Reclaim<'_>>
{
    let rest = strip_timestamp(line).strip_prefix(RECLAIM_PREFIX)?;
    let (badge, rest) = rest.split_once(" exit_reason=0x")?;
    let (exit_reason, name) = rest.split_once(" name=")?;
    Some(Reclaim {
        badge: badge.parse().ok()?,
        exit_reason: u64::from_str_radix(exit_reason, 16).ok()?,
        name: name.trim_end_matches('\r'),
    })
}

/// Check one svctest boot's serial log.
fn check_log(log: &str) -> Result<Verdict>
{
    if let Some(outcome) = saved_log_outcome(log)
        && outcome.starts_with(QEMU_CRASH_LABEL)
    {
        return Ok(Verdict::Skipped(outcome.to_string()));
    }
    if !log.lines().any(|l| l.contains(PASS_MARKER))
    {
        bail!("the log has no svctest pass marker ({PASS_MARKER:?}): not a passing svctest boot");
    }
    let lines: Vec<Reclaim<'_>> = log
        .lines()
        .filter_map(parse_reclaim)
        .filter(|r| r.name == CHILD_NAME)
        .collect();
    match lines.as_slice()
    {
        [] => bail!(
            "no logd `reclaim:` line names {CHILD_NAME:?}: the child's death did not reach \
             logd's death queue, or logd did not evict its slot"
        ),
        [one] if one.exit_reason != CHILD_EXIT_REASON => bail!(
            "logd reclaimed {CHILD_NAME:?} (badge {}) with exit reason {:#x}, not the child's \
             exit code {CHILD_EXIT_REASON:#x}",
            one.badge,
            one.exit_reason
        ),
        [one] => Ok(Verdict::Pass(one.badge)),
        many => bail!(
            "{} logd `reclaim:` lines name {CHILD_NAME:?}; one child registers it",
            many.len()
        ),
    }
}

pub fn run(ctx: &Context, args: &TestLogdReclaimArgs) -> Result<()>
{
    let log_path = match &args.log
    {
        Some(path) => path.clone(),
        None => boot(ctx, args)?,
    };
    step(&format!(
        "logd reclaim test: reading {}",
        log_path.display()
    ));
    let bytes =
        std::fs::read(&log_path).with_context(|| format!("reading {}", log_path.display()))?;
    match check_log(&String::from_utf8_lossy(&bytes))
        .with_context(|| format!("checking {}", log_path.display()))?
    {
        Verdict::Pass(badge) => step(&format!(
            "logd reclaim test: PASS (logd evicted {CHILD_NAME:?}, badge {badge}, on its exit \
             with code {CHILD_EXIT_REASON:#x})"
        )),
        Verdict::Skipped(outcome) => step(&format!(
            "logd reclaim test: SKIPPED (the boot's run-parallel outcome is {outcome}, a \
             host-emulator crash; nothing to check)"
        )),
    }
    Ok(())
}

/// Boot the current sysroot once through `run-parallel`, saving the run's
/// log, and return the saved log's path. A log an earlier boot saved there is
/// removed first, so the check never reads it.
fn boot(ctx: &Context, args: &TestLogdReclaimArgs) -> Result<PathBuf>
{
    let dir = ctx.target_dir.join("xtask").join("test-logd-reclaim");
    let log = dir.join(saved_log_file(args.arch, args.cpus, 1));
    match std::fs::remove_file(&log)
    {
        Ok(()) =>
        {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound =>
        {}
        Err(e) => return Err(e).with_context(|| format!("removing {}", log.display())),
    }
    let run = RunParallelArgs {
        arch: args.arch,
        parallel: 1,
        runs: 1,
        timeout: args.timeout,
        cpus: args.cpus,
        mem: args.mem,
        riscv_mmu: args.riscv_mmu,
        x86_paging: args.x86_paging,
        iommu: crate::qemu::Iommu::Attached,
        debug_port: None,
        debug_target: None,
        display: crate::qemu::BatchDisplay::Headless,
        pass: DEFAULT_PASS_REGEX.to_string(),
        fail: DEFAULT_FAIL_REGEX.to_string(),
        fail_also: None,
        debug_listen: false,
        hold_on_hang: false,
        fail_grace_secs: DEFAULT_FAIL_GRACE_SECS,
        save_logs: Some(dir),
        second_disk: None,
        second_disk_block_size: None,
        second_disk_shared_line: false,
    };
    step("logd reclaim test: booting the current sysroot (svctest staged)");
    crate::commands::run_parallel::run(ctx, &run)?;
    Ok(log)
}

#[cfg(test)]
mod tests
{
    use logd_codec::reclaim::{Cause, ReclaimLine};

    use super::*;

    const PASS: &str = "[78.819745] [svctest] ALL TESTS PASSED";

    /// One serial line as logd's `self_log` emits it: timestamp, tag, the
    /// line `logd_codec::reclaim` formats, and the CRLF ending.
    fn logd_line(line: &ReclaimLine<'_>) -> String
    {
        format!("[3.122334] [logd] {line}\r")
    }

    #[test]
    fn parses_the_line_logd_formats()
    {
        let line = logd_line(&ReclaimLine {
            badge: 234_050_274_665_587_601,
            cause: Cause::Death {
                exit_reason: CHILD_EXIT_REASON,
            },
            name: CHILD_NAME.as_bytes(),
        });
        assert_eq!(
            parse_reclaim(&line),
            Some(Reclaim {
                badge: 234_050_274_665_587_601,
                exit_reason: CHILD_EXIT_REASON,
                name: CHILD_NAME,
            })
        );
    }

    #[test]
    fn a_formatted_name_with_spaces_runs_to_the_end_of_the_line()
    {
        let line = logd_line(&ReclaimLine {
            badge: 9,
            cause: Cause::Death { exit_reason: 0x2a },
            name: b"fatfs /data",
        });
        assert_eq!(parse_reclaim(&line).map(|r| r.name), Some("fatfs /data"));
    }

    #[test]
    fn a_formatted_resync_line_is_not_a_death_drain_line()
    {
        let line = logd_line(&ReclaimLine {
            badge: 70,
            cause: Cause::Resync,
            name: CHILD_NAME.as_bytes(),
        });
        assert_eq!(parse_reclaim(&line), None);
    }

    #[test]
    fn another_senders_quote_of_the_line_is_not_logds()
    {
        let line =
            format!("[3.1] [svctest] [logd] reclaim: badge=70 exit_reason=0x17 name={CHILD_NAME}");
        assert_eq!(parse_reclaim(&line), None);
    }

    #[test]
    fn a_passing_log_with_the_named_line_passes()
    {
        let log = format!(
            "[1.0] [logd] reclaim: badge=65 exit_reason=0x0 name=svctest\n\
             [1.1] [logd] reclaim: badge=70 exit_reason=0x17 name={CHILD_NAME}\n{PASS}\n\
             [run-parallel] arch=x86_64 cpus=4 accel=kvm run=1 outcome=PASS wall_s=42.380\n"
        );
        assert_eq!(check_log(&log).expect("passes"), Verdict::Pass(70));
    }

    #[test]
    fn a_log_without_the_named_line_fails()
    {
        let log = format!("[1.0] [logd] reclaim: badge=65 exit_reason=0x17 name=svctest\n{PASS}\n");
        assert!(check_log(&log).is_err());
    }

    #[test]
    fn another_exit_reason_fails()
    {
        let log = format!("[logd] reclaim: badge=70 exit_reason=0x0 name={CHILD_NAME}\n{PASS}\n");
        assert!(check_log(&log).is_err());
    }

    #[test]
    fn two_named_lines_fail()
    {
        let line = format!("[logd] reclaim: badge=70 exit_reason=0x17 name={CHILD_NAME}\n");
        let log = format!("{line}{line}{PASS}\n");
        assert!(check_log(&log).is_err());
    }

    #[test]
    fn a_log_without_the_pass_marker_fails()
    {
        let log = format!("[logd] reclaim: badge=70 exit_reason=0x17 name={CHILD_NAME}\n");
        assert!(check_log(&log).is_err());
    }

    #[test]
    fn another_name_with_the_child_name_as_prefix_does_not_match()
    {
        let log =
            format!("[logd] reclaim: badge=70 exit_reason=0x17 name={CHILD_NAME}.2\n{PASS}\n");
        assert!(check_log(&log).is_err());
    }

    #[test]
    fn a_host_emulator_crash_is_skipped()
    {
        let log = "[0.5] [svctest] starting\n\
                   [run-parallel] arch=riscv64 cpus=4 accel=tcg run=1 outcome=QEMU-CRASH_rc=139 \
                   wall_s=12.000\n";
        assert_eq!(
            check_log(log).expect("skipped"),
            Verdict::Skipped("QEMU-CRASH_rc=139".to_string())
        );
    }

    #[test]
    fn a_guest_line_with_the_trailer_prefix_is_not_the_trailer()
    {
        let log = "[run-parallel] outcome=QEMU-CRASH_rc=139\n\
                   [0.5] [svctest] SOME TESTS FAILED\n\
                   [run-parallel] arch=riscv64 cpus=4 accel=tcg run=1 outcome=FAIL wall_s=12.000\n";
        assert!(check_log(log).is_err());
    }

    #[test]
    fn a_failed_boot_is_not_skipped()
    {
        let log = "[0.5] [svctest] SOME TESTS FAILED\n\
                   [run-parallel] arch=riscv64 cpus=4 accel=tcg run=1 outcome=FAIL wall_s=12.000\n";
        assert!(check_log(log).is_err());
    }
}
