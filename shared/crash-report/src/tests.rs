// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/crash-report/src/tests.rs

//! Host tests of the emitter, the parser, and the walk.

extern crate std;

use alloc::string::String;
use alloc::vec::Vec;
use std::format;

use super::*;

const IMAGE: Image = Image {
    load_bias: 0x7f00_0000_0000,
    text_start: 0x7f00_0000_1000,
    text_end: 0x7f00_0000_9000,
};

/// The block `report` emits, each line prefixed as logd prints it.
fn logged(report: &Report<'_>) -> String
{
    let mut log = String::new();
    report.emit(|line| log.push_str(&format!("[crashd] {line}\n")));
    log
}

fn main_vm_report<'a>(regs: &'a [u64], code: &'a [u8], frames: &'a [u64]) -> Report<'a>
{
    Report {
        id: 0x0123_4567_89ab_cdef,
        badge: 4_242_424_242,
        arch: Arch::X86_64,
        thread: Thread::Main,
        status: Status::Complete,
        fault: Fault::Vm {
            access: Access::Write,
            addr: 0,
            pager_reason: Some(3),
        },
        ip: 0x7f00_0000_1234,
        image: Some(IMAGE),
        regs,
        code,
        frames,
    }
}

#[test]
fn a_complete_main_thread_report_round_trips_and_passes_the_check()
{
    let regs: Vec<u64> = (0..21).collect();
    let code = [0xc7, 0x04, 0x25, 0, 0, 0, 0];
    let frames = [0x7f00_0000_1234, 0x7f00_0000_2000];
    let report = main_vm_report(&regs, &code, &frames);
    let mut emitted = 0;
    let mut log = String::new();
    emitted += report.emit(|line| log.push_str(&format!("[crashd] {line}\n")));

    let blocks = parse(&log);
    assert_eq!(blocks.len(), 1);
    let block = &blocks[0];
    assert_eq!(block.check(), Ok(()));
    assert_eq!(emitted, block.fields().len() + 2);
    assert_eq!(block.id, 0x0123_4567_89ab_cdef);
    assert_eq!(block.version, VERSION);
    assert_eq!(block.get("badge"), Some("4242424242"));
    assert_eq!(block.get("access"), Some("write"));
    assert_eq!(block.hex("addr"), Some(0));
    assert_eq!(block.hex("pager_reason"), Some(3));
    assert_eq!(block.hex("load_bias"), Some(IMAGE.load_bias));
    assert_eq!(
        block.get("text"),
        Some("0x00007f0000001000-0x00007f0000009000")
    );
    assert_eq!(block.hex("reg.rax"), Some(0));
    assert_eq!(block.hex("reg.fs_base"), Some(20));
    assert_eq!(block.get("code"), Some("c7042500000000"));
    assert_eq!(block.frames(), frames);
}

#[test]
fn an_exception_report_names_its_class_and_aux_word()
{
    let regs: Vec<u64> = (0..35).collect();
    let report = Report {
        id: 7,
        badge: 9,
        arch: Arch::Riscv64,
        thread: Thread::Main,
        status: Status::Complete,
        fault: Fault::Exception {
            code: syscall_abi::FAULT_EXC_ILLEGAL_INSTRUCTION,
            aux: 0xdead,
        },
        ip: IMAGE.text_start,
        image: Some(IMAGE),
        regs: &regs,
        code: &[0, 0, 0, 0],
        frames: &[IMAGE.text_start],
    };
    let blocks = parse(&logged(&report));
    assert_eq!(blocks[0].check(), Ok(()));
    assert_eq!(blocks[0].get("kind"), Some("exception"));
    assert_eq!(blocks[0].get("exception"), Some("illegal-instruction"));
    assert_eq!(blocks[0].hex("aux"), Some(0xdead));
    assert_eq!(blocks[0].hex("reg.sstatus"), Some(34));
    assert_eq!(blocks[0].get("pager_reason"), None);
}

#[test]
fn an_unidentified_thread_report_passes_without_registers_or_frames()
{
    let mut report = main_vm_report(&[], &[0x90], &[]);
    report.thread = Thread::Unidentified;
    let blocks = parse(&logged(&report));
    assert_eq!(blocks[0].check(), Ok(()));
    assert_eq!(blocks[0].get("reg.rax"), None);
    assert_eq!(blocks[0].get("walk"), None);
}

#[test]
fn a_spawned_thread_report_carries_registers_and_fails_without_them()
{
    let regs = [5u64; 21];
    let mut report = main_vm_report(&regs, &[0x90], &[0x1000]);
    report.thread = Thread::Spawned;
    let blocks = parse(&logged(&report));
    assert_eq!(blocks[0].check(), Ok(()));
    assert_eq!(blocks[0].get("thread"), Some("spawned"));
    assert_eq!(blocks[0].hex("reg.rax"), Some(5));

    let mut bare = main_vm_report(&[], &[0x90], &[]);
    bare.thread = Thread::Spawned;
    assert_eq!(
        parse(&logged(&bare))[0].check(),
        Err(Defect::Missing("reg.rax".into()))
    );
}

#[test]
fn a_thread_value_the_reader_does_not_know_requires_no_registers()
{
    let mut report = main_vm_report(&[], &[0x90], &[]);
    report.thread = Thread::Unidentified;
    let log = logged(&report).replace("thread=unidentified", "thread=later-kind");
    let blocks = parse(&log);
    assert_eq!(blocks[0].get("thread"), Some("later-kind"));
    assert_eq!(blocks[0].check(), Ok(()));
}

#[test]
fn an_unattached_report_needs_only_the_fault_message_fields()
{
    let mut report = main_vm_report(&[], &[], &[]);
    report.status = Status::Unattached;
    report.image = None;
    let blocks = parse(&logged(&report));
    assert_eq!(blocks[0].check(), Ok(()));
    assert_eq!(blocks[0].get("load_bias"), None);
}

#[test]
fn a_register_file_of_the_wrong_length_is_not_emitted_and_fails_the_check()
{
    let regs = [1u64; 20];
    let report = main_vm_report(&regs, &[0x90], &[1]);
    let blocks = parse(&logged(&report));
    assert_eq!(blocks[0].get("reg.rax"), None);
    assert_eq!(blocks[0].check(), Err(Defect::Missing("reg.rax".into())));
}

#[test]
fn code_bytes_and_frames_are_capped()
{
    let regs = [0u64; 21];
    let code = [0xaa; 40];
    let frames: Vec<u64> = (0..100).collect();
    let report = main_vm_report(&regs, &code, &frames);
    let blocks = parse(&logged(&report));
    assert_eq!(
        blocks[0].get("code").map(str::len),
        Some(MAX_CODE_BYTES * 2)
    );
    assert_eq!(blocks[0].frames().len(), MAX_FRAMES);
}

#[test]
fn a_block_without_its_end_marker_or_with_a_wrong_count_is_incomplete()
{
    let report = main_vm_report(&[], &[], &[]);
    let log = logged(&report);
    let truncated: String = log
        .lines()
        .filter(|l| !l.contains(END_TAG))
        .map(|l| format!("{l}\n"))
        .collect();
    assert_eq!(parse(&truncated)[0].check(), Err(Defect::Incomplete));

    let dropped_field: String = log
        .lines()
        .filter(|l| !l.contains(" ip="))
        .map(|l| format!("{l}\n"))
        .collect();
    assert_eq!(parse(&dropped_field)[0].check(), Err(Defect::Incomplete));
}

#[test]
fn interleaved_blocks_and_other_lines_are_separated_by_id()
{
    let mut first = main_vm_report(&[], &[], &[]);
    first.thread = Thread::Unidentified;
    let mut second = main_vm_report(&[], &[], &[]);
    second.thread = Thread::Unidentified;
    second.id = 0xfeed;
    second.badge = 1;
    let a: Vec<String> = logged(&first).lines().map(String::from).collect();
    let b: Vec<String> = logged(&second).lines().map(String::from).collect();
    let mut log = String::from("[logd] reclaim: badge=1 exit_reason=0x100e name=x\n");
    for (x, y) in a.iter().zip(b.iter())
    {
        log.push_str(&format!("{x}\nUSERSPACE FAULT: noise CRASH\n{y}\n"));
    }
    for rest in a.iter().skip(b.len()).chain(b.iter().skip(a.len()))
    {
        log.push_str(&format!("{rest}\n"));
    }
    let blocks = parse(&log);
    assert_eq!(blocks.len(), 2);
    assert_eq!(blocks[0].check(), Ok(()));
    assert_eq!(blocks[1].check(), Ok(()));
    assert_eq!(blocks[1].get("badge"), Some("1"));
}

#[test]
fn a_field_line_written_twice_counts_once()
{
    let report = main_vm_report(&[], &[], &[]);
    let mut log = String::new();
    for line in logged(&report).lines()
    {
        log.push_str(line);
        log.push('\n');
        if line.contains(" status=")
        {
            log.push_str(line);
            log.push('\n');
        }
    }
    let mut block = parse(&log).remove(0);
    assert!(block.is_complete());
    assert_eq!(
        block.fields().iter().filter(|(k, _)| k == "status").count(),
        1
    );
    // A repeated key with another value is a second line, and breaks the
    // count.
    log = log.replacen("status=complete", "status=timeout", 1);
    block = parse(&log).remove(0);
    assert!(!block.is_complete());
}

#[test]
fn a_malformed_value_is_refused_by_name()
{
    let report = main_vm_report(&[], &[], &[]);
    let log = logged(&report).replace("addr=0x", "addr=zz");
    assert_eq!(
        parse(&log)[0].check(),
        Err(Defect::Malformed("addr".into()))
    );
}

#[test]
fn the_access_word_names_a_fetch_before_a_write_before_a_read()
{
    use syscall_abi::{
        FAULT_ACCESS_EXEC, FAULT_ACCESS_PRESENT, FAULT_ACCESS_READ, FAULT_ACCESS_WRITE,
    };
    assert_eq!(
        Access::from_flags(FAULT_ACCESS_READ | FAULT_ACCESS_EXEC),
        Access::Fetch
    );
    assert_eq!(
        Access::from_flags(FAULT_ACCESS_WRITE | FAULT_ACCESS_PRESENT),
        Access::Write
    );
    assert_eq!(Access::from_flags(FAULT_ACCESS_READ), Access::Read);
    assert_eq!(Access::from_flags(0), Access::Read);
}

#[test]
fn an_unrecognized_exception_code_is_the_unknown_class()
{
    assert_eq!(
        exception_name(syscall_abi::FAULT_EXC_PROTECTION),
        "protection"
    );
    assert_eq!(exception_name(syscall_abi::FAULT_EXC_FP + 1), "unknown");
}

#[test]
fn the_scan_keeps_aligned_words_inside_text_in_stack_order_up_to_its_limit()
{
    let words: [u64; 6] = [
        IMAGE.text_start - 1,
        IMAGE.text_start,
        0,
        IMAGE.text_end - 1,
        IMAGE.text_end,
        IMAGE.text_start + 8,
    ];
    let mut stack: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    stack.extend_from_slice(&[0x10, 0x10, 0, 0]);
    let all: Vec<u64> = walk::scan(&stack, IMAGE.text_start, IMAGE.text_end, 10).collect();
    assert_eq!(
        all,
        [IMAGE.text_start, IMAGE.text_end - 1, IMAGE.text_start + 8]
    );
    let two: Vec<u64> = walk::scan(&stack, IMAGE.text_start, IMAGE.text_end, 2).collect();
    assert_eq!(two, [IMAGE.text_start, IMAGE.text_end - 1]);
}
