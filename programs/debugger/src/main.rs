// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// programs/debugger/src/main.rs

//! Debugger fixture: a debugger thread drives a debuggee thread of the same
//! process, then a debuggee process, through the fault and upcall handlers
//! and the thread-memory syscalls (docs/fault-handling.md § Debugging).
//!
//! The debugger (the main thread) binds the debuggee thread's exception and
//! upcall classes to an endpoint of its own, then:
//!
//! 1. receives the debuggee's software breakpoint (`int3` on x86-64, `ebreak`
//!    on riscv64) as `FAULT_EXC_BREAKPOINT`, checks the reported instruction
//!    pointer against the breakpoint's address, inspects and modifies the
//!    debuggee's memory while it is stopped, and resumes it past the
//!    breakpoint;
//! 2. on x86-64, single-steps the debuggee through three instructions with the
//!    trap flag, one `FAULT_EXC_DEBUG` each;
//! 3. async-breaks the debuggee, now spinning in a loop that makes no syscall,
//!    with an `UPCALL_ANY_INSTRUCTION` upcall, checks that it computes nothing
//!    while stopped, writes the flag that ends its loop, and resumes it;
//! 4. spawns itself with `--debuggee` as a debuggee process, and through the
//!    child's main-thread cap reads and writes its data
//!    (`SYS_THREAD_READ_MEM`, `SYS_THREAD_WRITE_MEM`), plants a software
//!    breakpoint in its text (`THREAD_MEM_TEXT`), takes the breakpoint,
//!    restores the text, and resumes the child at the restored instruction.
//!
//! The fixture prints `PASS` once both debuggees have seen the debugger's
//! memory writes. Driven by its per-program tester (`tester/`), which
//! `usertest` runs.

// A test fixture, where unwrap and expect are permitted
// (docs/coding-standards.md § Error Handling): a failed step must abort the
// fixture, and the panic's non-zero exit is its FAIL verdict for the tester.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::io::{BufRead, BufReader};
use std::os::seraph::process::ChildExt;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use ipc::IpcMessage;
use syscall_abi::{
    FAULT_CLASS_EXCEPTION, FAULT_CLASS_UPCALL, FAULT_EXC_BREAKPOINT, FAULT_KIND_EXCEPTION,
    FAULT_KIND_UPCALL, FAULT_LABEL, FAULT_REPLY_RESUME, THREAD_MEM_TEXT, UPCALL_ANY_INSTRUCTION,
    UPCALL_POINT_INTERRUPT,
};

/// Register-file buffer, large enough for either architecture's.
const REGS_BYTES: usize = 512;

/// The value the debugger writes into the debuggee's memory at the breakpoint.
const POKED: u64 = 0x0DEB_BEEF;

/// The cookie of the async-break upcall.
const BREAK_COOKIE: u64 = 0xB4EA_C001;

/// The debuggee's own Thread cap, published once it runs.
static DEBUGGEE: AtomicU64 = AtomicU64::new(0);

/// Released by the debugger once the debuggee's handlers are bound.
static GO: AtomicBool = AtomicBool::new(false);

/// The debuggee's breakpoint address, published once it is resumed past it.
static BREAKPOINT_AT: AtomicU64 = AtomicU64::new(0);

/// Memory the debugger inspects and modifies while the debuggee is stopped.
static PEEK: AtomicU64 = AtomicU64::new(1);

/// The debuggee's loop progress, and the flag the debugger sets to end it.
static SPINS: AtomicU64 = AtomicU64::new(0);

/// What the debuggee read back from [`PEEK`] once resumed past its breakpoint.
static SEEN: AtomicU64 = AtomicU64::new(0);
static LEAVE: AtomicBool = AtomicBool::new(false);
static DONE: AtomicBool = AtomicBool::new(false);

/// The debuggee process's data, which the debugger reads, then rewrites to
/// [`POKED`]. A nonzero initial value keeps it in a loaded data segment, so
/// its page is present.
static CHILD_DATA: AtomicU64 = AtomicU64::new(0xC41D_DA7A);

/// The debuggee process waits while this holds 1; the debugger writes 2.
static CHILD_GO: AtomicU64 = AtomicU64::new(1);

#[cfg(target_arch = "x86_64")]
mod arch
{
    pub const IP: usize = syscall_abi::REGS_X86_64_IP_OFFSET;

    /// Bytes the debugger advances the pointer by to resume past the
    /// breakpoint: none, since `#BP` reports the next instruction.
    pub const RESUME_ADVANCE: u64 = 0;

    /// The software breakpoint the debugger plants in a debuggee's text:
    /// `int3`.
    pub const BREAKPOINT: [u8; 1] = [0xCC];

    /// The pointer the breakpoint at `addr` reports.
    pub fn reported(addr: u64) -> u64
    {
        addr + 1
    }

    /// Hit a breakpoint followed by three one-byte `nop`s, the instructions
    /// [`single_step`] steps; returns the breakpoint's address.
    pub fn breakpoint() -> u64
    {
        let at: u64;
        // SAFETY: `lea` writes only `at`; `int3` raises #BP and the `nop`s do
        // nothing. A resuming debugger returns the thread to the next
        // instruction with its registers as they were, and clears any trap
        // flag it set before the last resume, so nothing else is clobbered.
        unsafe {
            core::arch::asm!(
                "lea {at}, [rip + 2f]",
                "2: int3",
                "nop",
                "nop",
                "nop",
                at = out(reg) at,
                options(nostack, preserves_flags),
            );
        }
        at
    }

    /// Arm a single-step in the breakpoint's register file: set the trap
    /// flag, so the resumed debuggee traps after each instruction.
    pub fn arm_step(regs: &mut [u8])
    {
        let flags = super::read_word(regs, syscall_abi::REGS_X86_64_FLAGS_OFFSET);
        super::write_word(
            regs,
            syscall_abi::REGS_X86_64_FLAGS_OFFSET,
            flags | syscall_abi::X86_64_RFLAGS_TF,
        );
    }

    /// Step 2: single-step the three `nop`s after the breakpoint that reported
    /// `reported`, one `FAULT_EXC_DEBUG` each, clearing the trap flag at the
    /// last.
    pub fn single_step(ep: u64, ipc_buf: *mut u64, th: u64, reported: u64)
    {
        for k in 1..=3
        {
            let ip = super::recv_exception(ep, ipc_buf, syscall_abi::FAULT_EXC_DEBUG);
            assert_eq!(ip, reported + k, "a step reported the wrong instruction");
            if k == 3
            {
                let mut regs = [0u8; super::REGS_BYTES];
                syscall::thread_read_regs(th, &mut regs).expect("read the stepped registers");
                let flags = super::read_word(&regs, syscall_abi::REGS_X86_64_FLAGS_OFFSET);
                super::write_word(
                    &mut regs,
                    syscall_abi::REGS_X86_64_FLAGS_OFFSET,
                    flags & !syscall_abi::X86_64_RFLAGS_TF,
                );
                // SAFETY: the frame was read from the debuggee, fault-blocked at its
                // last step; only its trap flag is cleared.
                unsafe { syscall::thread_write_regs(th, &regs) }
                    .expect("clear the debuggee's trap flag");
            }
            super::reply(ipc_buf);
        }
        println!("debugger: single-stepped 3 instructions");
    }
}

#[cfg(target_arch = "riscv64")]
mod arch
{
    pub const IP: usize = syscall_abi::REGS_RISCV64_IP_OFFSET;

    /// Bytes the debugger advances the pointer by to resume past the
    /// breakpoint: the 4-byte `ebreak`.
    pub const RESUME_ADVANCE: u64 = 4;

    /// The software breakpoint the debugger plants in a debuggee's text: the
    /// 4-byte `ebreak` (0x00100073), little-endian.
    pub const BREAKPOINT: [u8; 4] = [0x73, 0x00, 0x10, 0x00];

    /// The pointer the breakpoint at `addr` reports.
    pub fn reported(addr: u64) -> u64
    {
        addr
    }

    /// Hit a 4-byte `ebreak`; returns its address.
    pub fn breakpoint() -> u64
    {
        let at: u64;
        // SAFETY: `lla` writes only `at`; the word is `ebreak`, spelled out so
        // the assembler cannot compress it, and raises a breakpoint and does
        // nothing else. A resuming debugger returns the thread past it with
        // its registers as they were.
        unsafe {
            core::arch::asm!(
                "lla {at}, 2f",
                "2: .4byte 0x00100073",
                at = out(reg) at,
                options(nostack),
            );
        }
        at
    }

    /// Arm a single-step: nothing to arm. RISC-V has no user-mode single-step
    /// without a debug trigger, which the kernel does not program
    /// (docs/fault-handling.md § Debugging; #820), so the register file is
    /// left as it is.
    pub fn arm_step(_regs: &mut [u8]) {}

    /// Step 2: no single-step on RISC-V (see [`arm_step`]); the debuggee runs
    /// on from its breakpoint.
    pub fn single_step(_ep: u64, _ipc_buf: *mut u64, _th: u64, _reported: u64) {}
}

fn main()
{
    if std::env::args().nth(1).as_deref() == Some("--debuggee")
    {
        debuggee_process();
        return;
    }
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let ep = std::os::seraph::object_slab_retype(std::os::seraph::ENDPOINT_RETYPE_BYTES, |slab| {
        syscall::cap_create_endpoint(slab).ok()
    })
    .expect("create the debugger endpoint");

    let _debuggee = std::thread::spawn(debuggee);
    while DEBUGGEE.load(Ordering::Acquire) == 0
    {
        std::thread::sleep(Duration::from_millis(1));
    }
    let th = DEBUGGEE.load(Ordering::Acquire);
    syscall::thread_set_fault_handler(th, ep, FAULT_CLASS_EXCEPTION | FAULT_CLASS_UPCALL)
        .expect("bind the debuggee's exception and upcall classes");
    GO.store(true, Ordering::Release);

    // 1. The breakpoint.
    let reported = recv_exception(ep, ipc_buf, FAULT_EXC_BREAKPOINT);
    let mut regs = [0u8; REGS_BYTES];
    syscall::thread_read_regs(th, &mut regs).expect("read the debuggee's registers");
    assert_eq!(
        read_word(&regs, arch::IP),
        reported,
        "the register file's pointer differs"
    );
    assert_eq!(
        PEEK.load(Ordering::Acquire),
        1,
        "the debuggee's memory read back wrong"
    );
    PEEK.store(POKED, Ordering::Release);
    write_word(&mut regs, arch::IP, reported + arch::RESUME_ADVANCE);
    arch::arm_step(&mut regs);
    // SAFETY: the frame was read from the debuggee, fault-blocked at its
    // breakpoint; only its instruction pointer (to the next instruction) and,
    // on x86-64, its trap flag change.
    unsafe { syscall::thread_write_regs(th, &regs) }.expect("write the debuggee's registers");
    reply(ipc_buf);
    println!("debugger: breakpoint reported at {reported:#x}, memory inspected and modified");

    // 2. Single-step (x86-64; nothing on RISC-V).
    arch::single_step(ep, ipc_buf, th, reported);

    // 3. Async-break of the spinning debuggee.
    let stopped_at = async_break(ep, ipc_buf, th);
    let at = BREAKPOINT_AT.load(Ordering::Acquire);
    assert_eq!(
        reported,
        arch::reported(at),
        "the breakpoint reported the wrong pointer"
    );
    assert_eq!(
        SEEN.load(Ordering::Acquire),
        POKED,
        "the debugger's memory write was lost"
    );
    println!("debugger: async break after {stopped_at} spins");

    // 4. The debuggee process.
    cross_process(ep, ipc_buf);
    println!("PASS");
}

/// The debuggee process (`--debuggee`): report its addresses, wait for the
/// debugger's go, call [`child_target`], in whose text the debugger has
/// planted a breakpoint, and report what it read.
fn debuggee_process()
{
    println!(
        "ADDR {:x} {:x} {:x}",
        core::ptr::addr_of!(CHILD_DATA) as u64,
        core::ptr::addr_of!(CHILD_GO) as u64,
        child_target as *const () as u64
    );
    while CHILD_GO.load(Ordering::Acquire) == 1
    {
        std::thread::sleep(Duration::from_millis(1));
    }
    println!("SEEN {:x}", child_target());
}

/// The function whose first instruction the debugger replaces with a
/// breakpoint; returns the data the debugger rewrote.
#[inline(never)]
fn child_target() -> u64
{
    CHILD_DATA.load(Ordering::Acquire)
}

/// Step 4: debug the debuggee process through its main-thread cap.
fn cross_process(ep: u64, ipc_buf: *mut u64)
{
    let mut child = Command::new("/programs/debugger")
        .arg("--debuggee")
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn the debuggee process");
    let th = child.main_thread_cap();
    let mut out = BufReader::new(child.stdout.take().expect("piped stdout"));
    let mut line = String::new();
    out.read_line(&mut line)
        .expect("read the debuggee's addresses");
    let addrs: Vec<u64> = line
        .trim()
        .strip_prefix("ADDR ")
        .expect("an ADDR line")
        .split(' ')
        .map(|w| u64::from_str_radix(w, 16).expect("a hex address"))
        .collect();
    let [data, go, target] = addrs[..]
    else
    {
        panic!("three addresses")
    };

    syscall::thread_set_fault_handler(th, ep, FAULT_CLASS_EXCEPTION)
        .expect("bind the debuggee process's exception class");
    let mut word = [0u8; 8];
    syscall::thread_read_mem(th, data, &mut word).expect("read the child's data");
    assert_eq!(
        u64::from_le_bytes(word),
        0xC41D_DA7A,
        "the child's data read back wrong"
    );
    // SAFETY: the thread runs in the child's address space, not this one.
    unsafe { syscall::thread_write_mem(th, data, &POKED.to_le_bytes(), 0) }
        .expect("write the child's data");

    let mut original = arch::BREAKPOINT;
    syscall::thread_read_mem(th, target, &mut original).expect("read the child's text");
    // SAFETY: as above. The child's loader gave its text frames to it alone,
    // so the write needs only THREAD_MEM_TEXT.
    unsafe { syscall::thread_write_mem(th, target, &arch::BREAKPOINT, THREAD_MEM_TEXT) }
        .expect("plant the breakpoint in the child's text");
    // SAFETY: as above.
    unsafe { syscall::thread_write_mem(th, go, &2u64.to_le_bytes(), 0) }
        .expect("release the child");

    let reported = recv_exception(ep, ipc_buf, FAULT_EXC_BREAKPOINT);
    assert_eq!(
        reported,
        arch::reported(target),
        "the child's breakpoint reported the wrong pointer"
    );
    // SAFETY: as above.
    unsafe { syscall::thread_write_mem(th, target, &original, THREAD_MEM_TEXT) }
        .expect("restore the child's text");
    let mut regs = [0u8; REGS_BYTES];
    syscall::thread_read_regs(th, &mut regs).expect("read the child's registers");
    write_word(&mut regs, arch::IP, target);
    // SAFETY: the frame was read from the child's thread, fault-blocked at its
    // breakpoint; only its pointer moves, back to the restored instruction.
    unsafe { syscall::thread_write_regs(th, &regs) }.expect("write the child's registers");
    reply(ipc_buf);

    line.clear();
    out.read_line(&mut line).expect("read the child's report");
    assert_eq!(
        line.trim(),
        format!("SEEN {POKED:x}"),
        "the child missed the debugger's write"
    );
    let status = child.wait().expect("wait for the debuggee process");
    assert!(status.success(), "the debuggee process exited non-clean");
    println!("debugger: debuggee process inspected, modified, and broken into at {target:#x}");
}

/// Step 3: async-break the spinning debuggee, check that it does not run
/// while broken in, release its loop, and resume it; returns its progress at
/// the break.
fn async_break(ep: u64, ipc_buf: *mut u64, th: u64) -> u64
{
    while SPINS.load(Ordering::Relaxed) == 0
    {
        std::thread::sleep(Duration::from_millis(1));
    }
    syscall::thread_post_upcall(th, BREAK_COOKIE, UPCALL_ANY_INSTRUCTION)
        .expect("post the async-break upcall");
    // SAFETY: ipc_buf is this thread's registered IPC buffer page.
    let msg = unsafe { ipc::ipc_recv(ep, ipc_buf) }.expect("receive the async break");
    assert!(
        msg.label == FAULT_LABEL
            && msg.word(0) == FAULT_KIND_UPCALL
            && msg.word(1) == BREAK_COOKIE
            && msg.word(2) == UPCALL_POINT_INTERRUPT,
        "unexpected async-break message"
    );
    let stopped_at = SPINS.load(Ordering::Relaxed);
    std::thread::sleep(Duration::from_millis(20));
    assert_eq!(
        SPINS.load(Ordering::Relaxed),
        stopped_at,
        "the debuggee ran while broken in"
    );
    LEAVE.store(true, Ordering::Release);
    reply(ipc_buf);
    while !DONE.load(Ordering::Acquire)
    {
        std::thread::sleep(Duration::from_millis(1));
    }
    stopped_at
}

/// The debuggee: wait for the debugger, hit the breakpoint, read back the
/// debugger's memory write, then spin with no syscall until told to leave.
fn debuggee()
{
    DEBUGGEE.store(
        std::os::seraph::thread::current_thread_cap(),
        Ordering::Release,
    );
    while !GO.load(Ordering::Acquire)
    {
        std::thread::sleep(Duration::from_millis(1));
    }
    let at = arch::breakpoint();
    BREAKPOINT_AT.store(at, Ordering::Release);
    SEEN.store(PEEK.load(Ordering::Acquire), Ordering::Release);
    while !LEAVE.load(Ordering::Acquire)
    {
        SPINS.fetch_add(1, Ordering::Relaxed);
        core::hint::spin_loop();
    }
    DONE.store(true, Ordering::Release);
}

/// Receive an exception fault on `ep` with normalized code `code`; returns its
/// reported instruction pointer.
fn recv_exception(ep: u64, ipc_buf: *mut u64, code: u64) -> u64
{
    // SAFETY: ipc_buf is this thread's registered IPC buffer page.
    let msg = unsafe { ipc::ipc_recv(ep, ipc_buf) }.expect("receive a debuggee fault");
    assert!(
        msg.label == FAULT_LABEL && msg.word(0) == FAULT_KIND_EXCEPTION && msg.word(1) == code,
        "unexpected debuggee fault (code {:#x}, expected {code:#x})",
        msg.word(1)
    );
    msg.word(3)
}

/// Reply RESUME to the fault or upcall the debugger holds.
fn reply(ipc_buf: *mut u64)
{
    // SAFETY: ipc_buf is this thread's registered IPC buffer page.
    unsafe { ipc::ipc_reply(&IpcMessage::new(FAULT_REPLY_RESUME), ipc_buf) }
        .expect("resume the debuggee");
}

/// The register-file word at `offset`.
fn read_word(regs: &[u8], offset: usize) -> u64
{
    let mut word = [0u8; 8];
    word.copy_from_slice(&regs[offset..offset + 8]);
    u64::from_le_bytes(word)
}

/// Set the register-file word at `offset` to `value`.
fn write_word(regs: &mut [u8], offset: usize, value: u64)
{
    regs[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
