// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/commands/test_crash_report.rs

//! Crash-report test: the crash service's report blocks in a boot's log.
//!
//! No harness can read the system log from inside the guest, so the reports
//! crashd logs are checked here, in a boot's saved serial log
//! (docs/testing.md § Crash reports). Every block in the log must be complete
//! and hold the fields its kind, thread, and status require
//! (`crash_report::Block::check`, the parser of the format crashd emits,
//! services/crashd/docs/block-format.md).
//!
//! With `--expect reports` (the default), the log must also hold, for the
//! `crashme` fixture the usertest boot runs, one `vm` and one `exception`
//! block, each complete, of its main thread, its walk starting at its
//! instruction pointer, and each matched by the kernel's decline line naming
//! the block's id. A block is tied to `crashme` through its `badge`, which
//! logd's `reclaim:` line at the process's death names. With
//! `--expect none`, the log must hold no block: the boot of an image that
//! does not stage crashd. A log whose `run-parallel` trailer records a
//! `QEMU-CRASH` is skipped, as `test-logd-reclaim` skips it.

use anyhow::{Context as _, Result, bail};
use crash_report::Block;

use crate::cli::{CrashReportExpect, TestCrashReportArgs};
use crate::commands::run_parallel::{QEMU_CRASH_LABEL, saved_log_outcome};
use crate::crash_log::reclaimed_names;
use crate::util::step;

/// The log name of the fixture whose two reports the usertest boot leaves.
const FIXTURE: &str = "crashme";

/// The kernel's decline line, up to its reason
/// (`report_user_kill` in `core/kernel/src/ipc/fault.rs`).
const DECLINE_TAG: &str = "handler declined, reason=0x";

/// What a log's check found.
#[derive(Debug, PartialEq, Eq)]
enum Verdict
{
    /// Every block checked, and the expectation held; the block count.
    Pass(usize),
    /// A host-emulator crash ended the boot; nothing is checked.
    Skipped(String),
}

/// The decline reasons the kernel's `fault unhandled` lines print.
fn declined_reasons(log: &str) -> Vec<u64>
{
    log.lines()
        .filter_map(|line| {
            let at = line.find(DECLINE_TAG)?;
            let hex: String = line[at + DECLINE_TAG.len()..]
                .chars()
                .take_while(char::is_ascii_hexdigit)
                .collect();
            u64::from_str_radix(&hex, 16).ok()
        })
        .collect()
}

/// Check one fixture block beyond its format: complete, of the main thread,
/// its walk starting at its instruction pointer, and declined with its id.
fn check_fixture_block(block: &Block, declined: &[u64]) -> Result<()>
{
    if block.get("status") != Some("complete") || block.get("thread") != Some("main")
    {
        bail!(
            "{FIXTURE}'s block {:016x} is not a complete report of its main thread",
            block.id
        );
    }
    if block.frames().first().copied() != block.hex("ip")
    {
        bail!(
            "{FIXTURE}'s block {:016x}: the walk does not start at the instruction pointer",
            block.id
        );
    }
    if !declined.contains(&block.id)
    {
        bail!(
            "no kernel decline line carries {FIXTURE}'s block id {:016x}",
            block.id
        );
    }
    Ok(())
}

/// Check one boot's serial log against `expect`.
fn check_log(log: &str, expect: CrashReportExpect) -> Result<Verdict>
{
    if let Some(outcome) = saved_log_outcome(log)
        && outcome.starts_with(QEMU_CRASH_LABEL)
    {
        return Ok(Verdict::Skipped(outcome.to_string()));
    }
    let blocks = crash_report::parse(log);
    for block in &blocks
    {
        block
            .check()
            .map_err(|defect| anyhow::anyhow!("block {:016x}: {defect:?}", block.id))?;
    }
    match expect
    {
        CrashReportExpect::None =>
        {
            if let Some(block) = blocks.first()
            {
                bail!(
                    "the log holds {} report block(s) (the first {:016x}), but the image stages \
                     no crash service",
                    blocks.len(),
                    block.id
                );
            }
        }
        CrashReportExpect::Reports =>
        {
            let names = reclaimed_names(log);
            let declined = declined_reasons(log);
            for kind in ["vm", "exception"]
            {
                let block = blocks
                    .iter()
                    .find(|b| {
                        b.get("kind") == Some(kind)
                            && b.get("badge")
                                .and_then(|badge| badge.parse::<u64>().ok())
                                .and_then(|badge| names.get(&badge))
                                .is_some_and(|name| name == FIXTURE)
                    })
                    .with_context(|| format!("no `{kind}` report block of {FIXTURE}"))?;
                check_fixture_block(block, &declined)?;
            }
        }
    }
    Ok(Verdict::Pass(blocks.len()))
}

pub fn run(args: &TestCrashReportArgs) -> Result<()>
{
    step(&format!(
        "crash report test: reading {}",
        args.log.display()
    ));
    let bytes =
        std::fs::read(&args.log).with_context(|| format!("reading {}", args.log.display()))?;
    match check_log(&String::from_utf8_lossy(&bytes), args.expect)
        .with_context(|| format!("checking {}", args.log.display()))?
    {
        Verdict::Pass(count) => step(&format!(
            "crash report test: PASS ({count} report block(s), every one well-formed)"
        )),
        Verdict::Skipped(outcome) => step(&format!(
            "crash report test: SKIPPED (the boot's run-parallel outcome is {outcome}, a \
             host-emulator crash; nothing to check)"
        )),
    }
    Ok(())
}

#[cfg(test)]
mod tests
{
    use crash_report::{Access, Arch, Fault, Image, Report, Status, Thread};

    use super::*;

    const IMAGE: Image = Image {
        load_bias: 0x1000_0000,
        text_start: 0x1000_1000,
        text_end: 0x1000_9000,
    };

    /// The serial lines `report` and its death leave: the block as logd
    /// prints crashd's lines, the kernel's decline line, and logd's reclaim
    /// line naming `name`.
    fn death(report: &Report<'_>, name: &str) -> String
    {
        let mut log = String::new();
        report.emit(|line| log.push_str(&format!("[2.5] [crashd] {line}\r\n")));
        log.push_str(&format!(
            "[2.4] fault unhandled: tid=7 handler declined, reason={:#x}\n",
            report.id
        ));
        log.push_str(&format!(
            "[2.6] [logd] reclaim: badge={} exit_reason=0x100e name={name}\r\n",
            report.badge
        ));
        log
    }

    fn fixture_report(id: u64, fault: Fault, regs: &[u64]) -> Report<'_>
    {
        Report {
            id,
            badge: 42,
            arch: Arch::X86_64,
            thread: Thread::Main,
            status: Status::Complete,
            fault,
            ip: IMAGE.text_start + 0x10,
            image: Some(IMAGE),
            regs,
            code: &[0x0f, 0x0b],
            frames: &[IMAGE.text_start + 0x10, IMAGE.text_start + 0x40],
        }
    }

    fn both_reports(regs: &[u64]) -> String
    {
        let vm = fixture_report(
            0xaa,
            Fault::Vm {
                access: Access::Write,
                addr: 0,
                pager_reason: Some(3),
            },
            regs,
        );
        let mut exception = fixture_report(
            0xbb,
            Fault::Exception {
                code: syscall_abi::FAULT_EXC_ILLEGAL_INSTRUCTION,
                aux: 0,
            },
            regs,
        );
        exception.badge = 43;
        let mut log = death(&vm, FIXTURE);
        log.push_str(&death(&exception, FIXTURE));
        log
    }

    #[test]
    fn the_fixtures_two_reports_pass()
    {
        let regs = [0u64; 21];
        assert_eq!(
            check_log(&both_reports(&regs), CrashReportExpect::Reports).unwrap(),
            Verdict::Pass(2)
        );
    }

    #[test]
    fn a_missing_fixture_report_fails()
    {
        let regs = [0u64; 21];
        let log: String = both_reports(&regs)
            .lines()
            .filter(|l| !l.contains("name=crashme") || l.contains("badge=42"))
            .map(|l| format!("{l}\n"))
            .collect();
        assert!(check_log(&log, CrashReportExpect::Reports).is_err());
    }

    #[test]
    fn a_fixture_report_without_its_decline_line_fails()
    {
        let regs = [0u64; 21];
        let log = both_reports(&regs).replace("reason=0xaa", "reason=0xcc");
        assert!(check_log(&log, CrashReportExpect::Reports).is_err());
    }

    #[test]
    fn a_malformed_block_fails_whatever_the_expectation()
    {
        let regs = [0u64; 21];
        let log = both_reports(&regs).replace("arch=x86_64", "arch=pdp11");
        assert!(check_log(&log, CrashReportExpect::Reports).is_err());
        let one = death(
            &fixture_report(0xdd, Fault::Exception { code: 1, aux: 0 }, &regs),
            "other",
        )
        .replace("arch=x86_64", "arch=pdp11");
        assert!(check_log(&one, CrashReportExpect::None).is_err());
    }

    #[test]
    fn a_fixture_report_of_another_thread_fails()
    {
        // A well-formed block of an unidentified thread, so the block checks
        // as a block but not as the fixture's main-thread report.
        let mut vm = fixture_report(
            0xaa,
            Fault::Vm {
                access: Access::Write,
                addr: 0,
                pager_reason: Some(3),
            },
            &[],
        );
        vm.thread = Thread::Unidentified;
        vm.frames = &[];
        let regs = [0u64; 21];
        let mut exception = fixture_report(
            0xbb,
            Fault::Exception {
                code: syscall_abi::FAULT_EXC_ILLEGAL_INSTRUCTION,
                aux: 0,
            },
            &regs,
        );
        exception.badge = 43;
        let mut log = death(&vm, FIXTURE);
        log.push_str(&death(&exception, FIXTURE));
        let error = check_log(&log, CrashReportExpect::Reports).unwrap_err();
        assert!(format!("{error:#}").contains("main thread"));
    }

    #[test]
    fn a_fixture_walk_not_starting_at_the_instruction_pointer_fails()
    {
        let regs = [0u64; 21];
        let log = both_reports(&regs).replacen(
            "frame.0=0x0000000010001010",
            "frame.0=0x0000000010001020",
            1,
        );
        let error = check_log(&log, CrashReportExpect::Reports).unwrap_err();
        assert!(format!("{error:#}").contains("walk does not start"));
    }

    #[test]
    fn a_log_a_host_emulator_crash_ended_is_skipped()
    {
        let log = "[1.0] [crashd] CRASH-BEGIN id=00000000000000aa version=1\n\
                   [run-parallel] arch=x86_64 cpus=4 accel=kvm run=1 outcome=QEMU-CRASH_rc=139\n";
        assert_eq!(
            check_log(log, CrashReportExpect::Reports).unwrap(),
            Verdict::Skipped("QEMU-CRASH_rc=139".to_string())
        );
    }

    #[test]
    fn expecting_none_passes_a_log_without_blocks_and_fails_one_with_a_block()
    {
        let quiet = "[1.0] kernel: USERSPACE FAULT: tid=27 cpu=1 cause=#PF\n";
        assert_eq!(
            check_log(quiet, CrashReportExpect::None).unwrap(),
            Verdict::Pass(0)
        );
        let regs = [0u64; 21];
        assert!(check_log(&both_reports(&regs), CrashReportExpect::None).is_err());
    }
}
