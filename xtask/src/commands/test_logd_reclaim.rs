// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/commands/test_logd_reclaim.rs

//! logd death-forward test: a child's death reaches logd and evicts its slot.
//!
//! logd has no read surface, so no harness can observe a slot. svctest's
//! `logd_death_forward` phase spawns a child that registers the log name
//! [`CHILD_NAME`] and exits with code [`CHILD_EXIT_REASON`]. procmgr's
//! teardown forwards the death to logd's death queue, and logd evicts the slot
//! and logs `reclaim: badge=<b> exit_reason=0x17 name="<name>"`
//! (`services/logd/docs/ipc-interface.md` § Death-notification cascade). The
//! name holds a forged ` exit_reason=0x0`, which the line, a log record,
//! carries inside the quoted name. This command reads a svctest boot's serial
//! log and passes when the log holds svctest's pass marker and exactly one
//! such line, whose fields read back to the child's badge, exit reason, and
//! name. It also checks the child's own lines: its record [`CHILD_RECORD`],
//! and after it the text line [`CHILD_TEXT`] whole, which the child splits
//! around the record (`logd_reclaim_child_main` in
//! `services/svctest/src/phases/procmgr.rs`). A log whose `run-parallel`
//! trailer records a `QEMU-CRASH` is skipped, not failed: that outcome is a
//! host-emulator crash, which `run-parallel` itself tolerates.
//!
//! `--log <file>` reads a saved log and boots nothing; CI passes the log its
//! svctest cell's `run-parallel --save-logs` boot saved. With no log, the
//! command boots the current sysroot once through `run-parallel` (svctest must
//! be staged, as for any svctest boot) and reads the log that boot saves.

use std::path::PathBuf;

use anyhow::{Context as _, Result, bail};
use logd_codec::reclaim::{Cause, ReclaimLine};

use crate::cli::{
    DEFAULT_FAIL_GRACE_SECS, DEFAULT_FAIL_REGEX, DEFAULT_PASS_REGEX, RunParallelArgs,
    TestLogdReclaimArgs,
};
use crate::commands::run_parallel::{QEMU_CRASH_LABEL, saved_log_file, saved_log_outcome};
use crate::context::Context;
use crate::util::step;

/// The log name svctest's `logd_death_forward` child registers
/// (`LOGD_RECLAIM_NAME` in `services/svctest/src/phases/procmgr.rs`), with a
/// forged field in it.
const CHILD_NAME: &str = "svctest-logd-reclaim exit_reason=0x0";

/// The child's record as logd renders it: its message and its `code` field,
/// [`CHILD_EXIT_REASON`] in decimal.
const CHILD_RECORD: &str = "logd-reclaim child exiting code=23";

/// The text line the child sends in two halves, one before its records and
/// one after them (`LOGD_PARTIAL_TEXT` and `LOGD_RESUMED_TEXT`).
const CHILD_TEXT: &str = "partial text line resumed";

/// The code that child exits with (`LOGD_RECLAIM_EXIT_CODE`), which procmgr
/// posts to logd as the death's exit reason.
const CHILD_EXIT_REASON: u64 = 0x17;

/// svctest's terminal pass marker (docs/testing.md § Reporting marker).
const PASS_MARKER: &str = "[svctest] ALL TESTS PASSED";

/// logd's self-log tag, which starts its reclaim line after the timestamp.
const LOGD_TAG: &str = "[logd] ";

/// The message of a death drain's reclaim record
/// (`logd_codec::reclaim::ReclaimLine::message`).
const DEATH_MESSAGE: &str = "reclaim:";

/// One death-drain reclaim line.
#[derive(Debug, PartialEq, Eq)]
struct Reclaim
{
    badge: u64,
    exit_reason: u64,
    name: Vec<u8>,
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
/// that quotes the line does not count. The fields are read with the codec's
/// parser (`logd_codec::record::fields`), so a quoted name is read whole and
/// unescaped, and the line must be exactly the rendering of the record those
/// fields give: a further field, or any other text, fails it. A trailing
/// `\r` is not part of the line.
fn parse_reclaim(line: &str) -> Option<Reclaim>
{
    let body = strip_timestamp(line)
        .trim_end_matches('\r')
        .strip_prefix(LOGD_TAG)?;
    let fields: Vec<_> = logd_codec::record::fields(body.strip_prefix(DEATH_MESSAGE)?).collect();
    let [badge, exit_reason, name] = fields.as_slice()
    else
    {
        return None;
    };
    if (badge.key, exit_reason.key, name.key) != ("badge", "exit_reason", "name")
    {
        return None;
    }
    let text = |f: &logd_codec::record::RenderedField<'_>| {
        String::from_utf8(f.value.bytes().collect()).ok()
    };
    let parsed = Reclaim {
        badge: text(badge)?.parse().ok()?,
        exit_reason: u64::from_str_radix(text(exit_reason)?.strip_prefix("0x")?, 16).ok()?,
        name: name.value.bytes().collect(),
    };
    let rendered = ReclaimLine {
        badge: parsed.badge,
        cause: Cause::Death {
            exit_reason: parsed.exit_reason,
        },
        name: &parsed.name,
    }
    .to_string();
    (rendered == body).then_some(parsed)
}

/// The index of each of `lines` that is `[<CHILD_NAME>] <body>` after its
/// timestamp, a trailing `\r` aside.
fn child_lines(lines: &[&str], body: &str) -> Vec<usize>
{
    let want = format!("[{CHILD_NAME}] {body}");
    lines
        .iter()
        .enumerate()
        .filter(|(_, l)| strip_timestamp(l).trim_end_matches('\r') == want)
        .map(|(i, _)| i)
        .collect()
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
    let all: Vec<&str> = log.lines().collect();
    let records = child_lines(&all, CHILD_RECORD);
    let texts = child_lines(&all, CHILD_TEXT);
    match (records.as_slice(), texts.as_slice())
    {
        ([record], [text]) if record < text =>
        {}
        ([], _) => bail!(
            "no line of {CHILD_NAME:?} is its record {CHILD_RECORD:?}: the record did not \
             reach logd, or logd rendered it otherwise"
        ),
        (_, []) => bail!(
            "no line of {CHILD_NAME:?} is the text line {CHILD_TEXT:?} whole: a record \
             disturbed the child's pending text line"
        ),
        _ => bail!(
            "{CHILD_NAME:?} has {} record lines and {} text lines; it sends one record, then \
             ends the text line once",
            records.len(),
            texts.len()
        ),
    }
    let lines: Vec<Reclaim> = all
        .iter()
        .copied()
        .filter_map(parse_reclaim)
        .filter(|r| r.name == CHILD_NAME.as_bytes())
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
        host: args.host.clone(),
    };
    step("logd reclaim test: booting the current sysroot (svctest staged)");
    crate::commands::run_parallel::run(ctx, &run)?;
    Ok(log)
}

#[cfg(test)]
mod tests
{
    use super::*;

    const PASS: &str = "[78.819745] [svctest] ALL TESTS PASSED";

    /// One serial line as logd emits a reclaim line: timestamp, tag, the
    /// record `logd_codec::reclaim` builds as rendered, and the CRLF ending.
    fn logd_line(line: &ReclaimLine<'_>) -> String
    {
        format!("[3.122334] [logd] {line}\r")
    }

    /// The child's death-drain reclaim line with `badge` and `exit_reason`.
    fn child_reclaim(badge: u64, exit_reason: u64) -> String
    {
        logd_line(&ReclaimLine {
            badge,
            cause: Cause::Death { exit_reason },
            name: CHILD_NAME.as_bytes(),
        })
    }

    /// The child's own record line, then its text line.
    fn child_output() -> String
    {
        format!("[1.05] [{CHILD_NAME}] {CHILD_RECORD}\r\n[1.06] [{CHILD_NAME}] {CHILD_TEXT}\r\n")
    }

    #[test]
    fn parses_the_line_logd_formats()
    {
        let line = child_reclaim(234_050_274_665_587_601, CHILD_EXIT_REASON);
        assert!(line.contains(r#"name="svctest-logd-reclaim exit_reason=0x0""#));
        assert_eq!(
            parse_reclaim(&line),
            Some(Reclaim {
                badge: 234_050_274_665_587_601,
                exit_reason: CHILD_EXIT_REASON,
                name: CHILD_NAME.as_bytes().to_vec(),
            })
        );
    }

    #[test]
    fn a_plain_name_parses()
    {
        let line = logd_line(&ReclaimLine {
            badge: 9,
            cause: Cause::Death { exit_reason: 0x2a },
            name: b"fatfs",
        });
        assert_eq!(
            parse_reclaim(&line).map(|r| r.name),
            Some(b"fatfs".to_vec())
        );
    }

    #[test]
    fn an_unquoted_forged_field_is_not_logds_line()
    {
        // The line a name could forge if logd wrote it unquoted: a fourth
        // field, so not the record's rendering.
        let line = "[3.1] [logd] reclaim: badge=70 exit_reason=0x17 name=svctest-logd-reclaim \
                    exit_reason=0x0";
        assert_eq!(parse_reclaim(line), None);
    }

    #[test]
    fn trailing_text_after_the_fields_is_not_logds_line()
    {
        let line = format!("{} junk", child_reclaim(70, 0x17).trim_end_matches('\r'));
        assert_eq!(parse_reclaim(&line), None);
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
        let line = format!("[3.1] [svctest] {}", &child_reclaim(70, 0x17)[11..]);
        assert!(line.starts_with("[3.1] [svctest] [logd] reclaim:"));
        assert_eq!(parse_reclaim(&line), None);
    }

    #[test]
    fn a_passing_log_with_the_named_line_passes()
    {
        let log = format!(
            "[1.0] [logd] reclaim: badge=65 exit_reason=0x0 name=svctest\n{}{}\n{PASS}\n\
             [run-parallel] arch=x86_64 cpus=4 accel=kvm run=1 outcome=PASS wall_s=42.380\n",
            child_output(),
            child_reclaim(70, 0x17),
        );
        assert_eq!(check_log(&log).expect("passes"), Verdict::Pass(70));
    }

    #[test]
    fn a_log_without_the_named_line_fails()
    {
        let log = format!(
            "{}[1.0] [logd] reclaim: badge=65 exit_reason=0x17 name=svctest\n{PASS}\n",
            child_output()
        );
        assert!(check_log(&log).is_err());
    }

    #[test]
    fn another_exit_reason_fails()
    {
        let log = format!("{}{}\n{PASS}\n", child_output(), child_reclaim(70, 0));
        assert!(check_log(&log).is_err());
    }

    #[test]
    fn two_named_lines_fail()
    {
        let line = child_reclaim(70, 0x17);
        let log = format!("{}{line}\n{line}\n{PASS}\n", child_output());
        assert!(check_log(&log).is_err());
    }

    #[test]
    fn a_log_without_the_pass_marker_fails()
    {
        let log = format!("{}{}\n", child_output(), child_reclaim(70, 0x17));
        assert!(check_log(&log).is_err());
    }

    #[test]
    fn another_name_with_the_child_name_as_prefix_does_not_match()
    {
        let line = logd_line(&ReclaimLine {
            badge: 70,
            cause: Cause::Death { exit_reason: 0x17 },
            name: format!("{CHILD_NAME}.2").as_bytes(),
        });
        let log = format!("{}{line}\n{PASS}\n", child_output());
        assert!(check_log(&log).is_err());
    }

    #[test]
    fn a_log_without_the_childs_record_fails()
    {
        let log = format!(
            "[1.06] [{CHILD_NAME}] {CHILD_TEXT}\r\n{}\n{PASS}\n",
            child_reclaim(70, 0x17)
        );
        assert!(check_log(&log).is_err());
    }

    #[test]
    fn a_text_line_the_record_split_fails()
    {
        // A receiver that flushed the pending text at the record.
        let log = format!(
            "[1.04] [{CHILD_NAME}] partial text \r\n[1.05] [{CHILD_NAME}] {CHILD_RECORD}\r\n\
             [1.06] [{CHILD_NAME}] line resumed\r\n{}\n{PASS}\n",
            child_reclaim(70, 0x17)
        );
        assert!(check_log(&log).is_err());
    }

    #[test]
    fn a_text_line_before_the_record_fails()
    {
        let log = format!(
            "[1.04] [{CHILD_NAME}] {CHILD_TEXT}\r\n[1.05] [{CHILD_NAME}] {CHILD_RECORD}\r\n\
             {}\n{PASS}\n",
            child_reclaim(70, 0x17)
        );
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
