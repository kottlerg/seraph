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
//! block of its main thread and one `exception` block of a spawned thread,
//! each complete, its walk starting at its instruction pointer, matched by
//! the kernel's decline line naming the block's id, and carrying the stack
//! pointer the kernel's register dump of that declined thread prints (and, in
//! the `vm` block, the faulting address that dump prints). A block
//! is tied to `crashme` through its `badge`, which logd's `reclaim:` line at
//! the process's death names. With
//! `--expect none`, the log must hold no block: the boot of an image that
//! does not stage crashd. A log whose `run-parallel` trailer records a
//! `QEMU-CRASH` is skipped, not failed: that outcome is a host-emulator
//! crash, which `run-parallel` itself tolerates.

use std::collections::HashMap;

use anyhow::{Context as _, Result, bail};
use crash_report::Block;

use crate::cli::{CrashReportExpect, TestCrashReportArgs};
use crate::commands::run_parallel::{QEMU_CRASH_LABEL, saved_log_outcome};
use crate::crash_log::reclaimed_names;
use crate::util::step;

/// The log name of the fixture whose three reports the usertest boot leaves.
const FIXTURE: &str = "crashme";

/// The kernel's decline line, up to its reason
/// (`report_user_kill` in `core/kernel/src/ipc/fault.rs`).
const DECLINE_TAG: &str = "handler declined, reason=0x";

/// The kernel's register dump header of a thread it kills on a fault, up to
/// the thread's id.
const DUMP_TAG: &str = "USERSPACE FAULT: tid=";

/// The fixture's blocks the usertest boot must leave, by kind and thread:
/// `crashme vm`, `crashme exception`, and `crashme worker`'s spawned thread.
const FIXTURE_BLOCKS: [(&str, &str); 3] = [
    ("vm", "main"),
    ("exception", "main"),
    ("exception", "spawned"),
];

/// What a log's check found.
#[derive(Debug, PartialEq, Eq)]
enum Verdict
{
    /// Every block checked, and the expectation held; the block count.
    Pass(usize),
    /// A host-emulator crash ended the boot; nothing is checked.
    Skipped(String),
}

/// The tid of each of the kernel's `fault unhandled` decline lines, by the
/// decline reason it prints.
fn declined_tids(log: &str) -> HashMap<u64, u64>
{
    log.lines()
        .filter_map(|line| {
            let at = line.find(DECLINE_TAG)?;
            let hex: String = line[at + DECLINE_TAG.len()..]
                .chars()
                .take_while(char::is_ascii_hexdigit)
                .collect();
            let reason = u64::from_str_radix(&hex, 16).ok()?;
            Some((reason, number_after(line, "tid=")?))
        })
        .collect()
}

/// The decimal number directly after `tag` in `line`.
fn number_after(line: &str, tag: &str) -> Option<u64>
{
    let at = line.find(tag)?;
    let digits: String = line[at + tag.len()..]
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    digits.parse().ok()
}

/// The register `name` of the kernel's `USERSPACE FAULT` dump of thread
/// `tid`: the first `<name>=0x…` word in the lines after the dump's header,
/// up to the next header (`report_user_kill`'s register dump, printed for a
/// thread the kernel kills on a declined fault).
fn dumped_register(log: &str, tid: u64, name: &str) -> Option<u64>
{
    let token = format!(" {name}=0x");
    let mut lines = log.lines();
    lines.find(|line| number_after(line, DUMP_TAG) == Some(tid))?;
    for line in lines.take_while(|line| !line.contains(DUMP_TAG))
    {
        if let Some(at) = line.find(&token)
        {
            let hex: String = line[at + token.len()..]
                .chars()
                .take_while(char::is_ascii_hexdigit)
                .collect();
            return u64::from_str_radix(&hex, 16).ok();
        }
    }
    None
}

/// Check one fixture block beyond its format: complete, of the thread
/// `thread`, its walk starting at its instruction pointer, declined with its
/// id, and its stack pointer the one the kernel's dump of the declined thread
/// prints, so the block read the thread that faulted. A `vm` block's `addr`,
/// the fault message's address, must also be the faulting address that dump
/// prints (`cr2` on x86-64, `stval` on RISC-V), so the dump names the access
/// that faulted.
fn check_fixture_block(block: &Block, thread: &str, log: &str) -> Result<()>
{
    let id = block.id;
    if block.get("status") != Some("complete") || block.get("thread") != Some(thread)
    {
        bail!("{FIXTURE}'s block {id:016x} is not a complete report of a `{thread}` thread");
    }
    if block.frames().first().copied() != block.hex("ip")
    {
        bail!("{FIXTURE}'s block {id:016x}: the walk does not start at the instruction pointer");
    }
    let Some(&tid) = declined_tids(log).get(&id)
    else
    {
        bail!("no kernel decline line carries {FIXTURE}'s block id {id:016x}");
    };
    let (sp, fault_addr) = if block.get("arch") == Some("riscv64")
    {
        ("sp", "stval")
    }
    else
    {
        ("rsp", "cr2")
    };
    let reported = block.hex(&format!("reg.{sp}"));
    let dumped = dumped_register(log, tid, sp);
    if reported.is_none() || reported != dumped
    {
        bail!(
            "{FIXTURE}'s block {id:016x}: its {sp} {reported:x?} is not the {dumped:x?} the \
             kernel dumped for the declined thread {tid}"
        );
    }
    if block.get("kind") == Some("vm")
    {
        let reported = block.hex("addr");
        let dumped = dumped_register(log, tid, fault_addr);
        if reported.is_none() || reported != dumped
        {
            bail!(
                "{FIXTURE}'s block {id:016x}: its addr {reported:x?} is not the \
                 {fault_addr} {dumped:x?} the kernel dumped for the declined thread {tid}"
            );
        }
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
            for (kind, thread) in FIXTURE_BLOCKS
            {
                let block = blocks
                    .iter()
                    .find(|b| {
                        b.get("kind") == Some(kind)
                            && b.get("thread") == Some(thread)
                            && b.get("badge")
                                .and_then(|badge| badge.parse::<u64>().ok())
                                .and_then(|badge| names.get(&badge))
                                .is_some_and(|name| name == FIXTURE)
                    })
                    .with_context(|| {
                        format!("no `{kind}` report block of a `{thread}` thread of {FIXTURE}")
                    })?;
                check_fixture_block(block, thread, log)?;
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

    /// Index of `rsp` in the x86-64 register file the reports carry.
    const RSP: usize = 17;

    /// The faulting address of the fixture's `vm` report.
    const VM_ADDR: u64 = 0x7fff_eff8;

    /// The serial lines `report` and its death leave: the block as logd
    /// prints crashd's lines, the kernel's decline line and register dump of
    /// the declined thread (tid the report's id), its stack pointer the
    /// report's and its `cr2` a `vm` report's address, and logd's reclaim line
    /// naming `name`.
    fn death(report: &Report<'_>, name: &str) -> String
    {
        let mut log = String::new();
        report.emit(|line| log.push_str(&format!("[2.5] [crashd] {line}\r\n")));
        let tid = report.id;
        log.push_str(&format!(
            "[2.4] fault unhandled: tid={tid} handler declined, reason={:#x}\n",
            report.id
        ));
        let cr2 = match report.fault
        {
            Fault::Vm { addr, .. } => addr,
            Fault::Exception { .. } => 0,
        };
        log.push_str(&format!(
            "[2.4] USERSPACE FAULT: tid={tid} cpu=0 cause=#UD (vec=6 err=0x0)\n  rip=0x1  \
             cr2={cr2:#018x}  fs_base=0x0\n  rsi=0x0000000000000000  rbp=0x0  rsp={:#018x}\n",
            report.regs.get(RSP).copied().unwrap_or(0)
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

    fn fixture_reports(regs: &[u64]) -> String
    {
        let vm = fixture_report(
            0xaa,
            Fault::Vm {
                access: Access::Write,
                addr: VM_ADDR,
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
        let mut worker = fixture_report(
            0xee,
            Fault::Exception {
                code: syscall_abi::FAULT_EXC_ILLEGAL_INSTRUCTION,
                aux: 0,
            },
            regs,
        );
        worker.badge = 44;
        worker.thread = Thread::Spawned;
        let mut log = death(&vm, FIXTURE);
        log.push_str(&death(&exception, FIXTURE));
        log.push_str(&death(&worker, FIXTURE));
        log
    }

    #[test]
    fn the_fixtures_three_reports_pass()
    {
        let mut regs = [0u64; 21];
        regs[RSP] = 0x7fff_f000;
        assert_eq!(
            check_log(&fixture_reports(&regs), CrashReportExpect::Reports).unwrap(),
            Verdict::Pass(3)
        );
    }

    #[test]
    fn a_fixture_report_whose_stack_pointer_is_not_the_declined_threads_fails()
    {
        // The worker block read another thread than the one the kernel
        // killed: its stack pointer differs from the dump's.
        let mut regs = [0u64; 21];
        regs[RSP] = 0x7fff_f000;
        let log = fixture_reports(&regs);
        let mut lines: Vec<String> = log.lines().map(String::from).collect();
        let last_dump = lines
            .iter()
            .rposition(|l| l.contains("  rsp=0x000000007ffff000"))
            .unwrap();
        lines[last_dump] = lines[last_dump].replace("7ffff000", "7fffe000");
        let error = check_log(&lines.join("\n"), CrashReportExpect::Reports).unwrap_err();
        assert!(format!("{error:#}").contains("kernel dumped"));
    }

    #[test]
    fn a_vm_report_whose_address_is_not_the_dumped_cr2_fails()
    {
        // The kernel's dump of the declined vm fault prints a stale CR2 (another
        // fault's address) rather than the fault message's address.
        let regs = [0u64; 21];
        let log = fixture_reports(&regs).replacen(
            &format!("cr2={VM_ADDR:#018x}"),
            "cr2=0x0000402505e83ff0",
            1,
        );
        let error = check_log(&log, CrashReportExpect::Reports).unwrap_err();
        assert!(format!("{error:#}").contains("its addr"));
    }

    #[test]
    fn a_missing_fixture_report_fails()
    {
        let regs = [0u64; 21];
        let log: String = fixture_reports(&regs)
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
        let log = fixture_reports(&regs).replace("reason=0xaa", "reason=0xcc");
        assert!(check_log(&log, CrashReportExpect::Reports).is_err());
    }

    #[test]
    fn a_malformed_block_fails_whatever_the_expectation()
    {
        let regs = [0u64; 21];
        // A `text` that is not two hexadecimal words is malformed; a value of
        // a set-valued field the reader does not know would not be.
        let log = fixture_reports(&regs).replace(" text=0x", " text=0y");
        assert!(check_log(&log, CrashReportExpect::Reports).is_err());
        let one = death(
            &fixture_report(0xdd, Fault::Exception { code: 1, aux: 0 }, &regs),
            "other",
        )
        .replace(" text=0x", " text=0y");
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
        assert!(format!("{error:#}").contains("`main` thread"));
    }

    #[test]
    fn a_fixture_walk_not_starting_at_the_instruction_pointer_fails()
    {
        let regs = [0u64; 21];
        let log = fixture_reports(&regs).replacen(
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
        assert!(check_log(&fixture_reports(&regs), CrashReportExpect::None).is_err());
    }
}
