// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// programs/crashme/tester/src/main.rs

//! Per-program tester for `/programs/crashme`. Runs it in each mode the
//! crash-report check reads, `vm`, `exception`, and `worker`, and checks
//! that it reached its fault and died of it: a non-clean exit whose reason
//! is a fault class, so the crash service's decline ended the thread as the
//! kernel would have. It also runs `registry-declare`, which faults on
//! nothing, and checks that it passed, and `oom-touch` beside `oom-fill`,
//! which checks the crash service's hold of a fault memmgr declined for want
//! of memory ([`check_oom_hold`]). The report block each
//! death leaves in the log is checked host-side, from the boot's serial log,
//! by `cargo xtask test-crash-report` (docs/testing.md § Crash reports).
//!
//! The usertest boot stages a crash service whose `CORE_DUMP` names
//! crashme, so each faulting mode also leaves one ELF core in `/crash`; the
//! tester checks it (services/crashd/docs/core-format.md): an `ET_CORE` of
//! this machine whose first `NT_PRSTATUS` carries the fault's signal, an
//! instruction pointer in a written `PT_LOAD` (at the illegal instruction,
//! for the modes that execute it) and a stack pointer in one, and, for
//! `worker`, more than one thread.
//!
//! See [docs/testing.md](../../../docs/testing.md) for the protocol.

#![expect(
    clippy::expect_used,
    reason = "a per-program tester is test code, where unwrap and expect are permitted \
              (docs/coding-standards.md § Error Handling): a failed spawn, read, or wait must \
              abort the tester, and the panic's non-zero exit is its FAIL verdict"
)]

use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

/// Base exit reason for a fault-induced death (`abi/syscall`
/// `EXIT_FAULT_BASE`); faults occupy `[EXIT_FAULT_BASE, EXIT_KILLED)`.
const EXIT_FAULT_BASE: u64 = 0x1000;
/// The first reason past the fault range (`abi/syscall` `EXIT_KILLED`).
const EXIT_KILLED: u64 = 0x2000;

/// The directory the crash service writes cores to.
const CORE_DIR: &str = "/crash";
/// The suffix of a complete core's name, after its `<seq>-<name>` stem.
const CORE_SUFFIX: &str = "-crashme.core";

/// ELF constants the check reads (the ELF and Linux core formats).
const ET_CORE: u16 = 4;
const PT_LOAD: u32 = 1;
const PT_NOTE: u32 = 4;
const NT_PRSTATUS: u32 = 1;
const SIGILL: u32 = 4;
const SIGSEGV: u32 = 11;
/// `NT_PRSTATUS`'s bytes before `pr_reg`.
const PRSTATUS_HEAD: usize = 112;

#[cfg(target_arch = "x86_64")]
mod machine
{
    /// `EM_X86_64`.
    pub const EM: u16 = 62;
    /// `pr_reg` indices of the instruction and stack pointers (`rip`, `rsp`).
    pub const IP_INDEX: usize = 16;
    pub const SP_INDEX: usize = 19;
    /// `ud2`.
    pub const ILLEGAL: &[u8] = &[0x0f, 0x0b];
}

#[cfg(target_arch = "riscv64")]
mod machine
{
    /// `EM_RISCV`.
    pub const EM: u16 = 243;
    /// `pr_reg` indices of the instruction and stack pointers (`pc`, `sp`).
    pub const IP_INDEX: usize = 0;
    pub const SP_INDEX: usize = 2;
    /// `unimp`, as the assembler encodes it with the C extension
    /// (`c.unimp`, all zeros).
    pub const ILLEGAL: &[u8] = &[0x00, 0x00];
}

fn fail(msg: &str) -> !
{
    println!("[crashme-tester] FAIL {msg}");
    std::process::exit(1);
}

/// Run `/programs/crashme <mode>` and check it reached its fault and died of
/// it.
#[expect(
    clippy::cast_sign_loss,
    reason = "ExitStatus::code() is i32, but exit reasons are non-negative (fault 0x1000+vector); \
              the u64 cast preserves the value"
)]
fn check(mode: &str)
{
    let before = cores();
    let mut child = Command::new("/programs/crashme")
        .arg(mode)
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn /programs/crashme");
    let mut bytes = Vec::new();
    child
        .stdout
        .take()
        .expect("piped stdout")
        .read_to_end(&mut bytes)
        .expect("read /programs/crashme stdout");
    let status = child.wait().expect("wait /programs/crashme");
    let out = String::from_utf8_lossy(&bytes);
    if !out.contains(&format!("faulting ({mode})"))
    {
        fail(&format!(
            "{mode}: the fixture never reached its fault: {out:?}"
        ));
    }
    if status.success()
    {
        fail(&format!("{mode}: the fixture exited cleanly"));
    }
    let reason = status.code().expect("a fault death carries a reason") as u64;
    if !(EXIT_FAULT_BASE..EXIT_KILLED).contains(&reason)
    {
        fail(&format!(
            "{mode}: exit reason {reason:#x} is not a fault class"
        ));
    }
    let new: Vec<String> = cores().difference(&before).cloned().collect();
    let [name] = new.as_slice()
    else
    {
        fail(&format!(
            "{mode}: expected one new core in {CORE_DIR}, found {new:?}"
        ));
    };
    let path = format!("{CORE_DIR}/{name}");
    let core = std::fs::read(&path).expect("read the core");
    if let Err(why) = check_core(&core, mode)
    {
        fail(&format!("{mode}: {path}: {why}"));
    }
}

/// The names of crashme's complete cores in [`CORE_DIR`].
fn cores() -> BTreeSet<String>
{
    std::fs::read_dir(CORE_DIR)
        .expect("read the core directory")
        .map(|entry| {
            entry
                .expect("read a core directory entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .filter(|name| name.ends_with(CORE_SUFFIX))
        .collect()
}

/// A little-endian integer of `N` bytes at `offset` in `bytes`.
fn le<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], String>
{
    offset
        .checked_add(N)
        .and_then(|end| bytes.get(offset..end))
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| format!("truncated at {offset:#x}"))
}

fn u16_at(bytes: &[u8], offset: usize) -> Result<u16, String>
{
    le::<2>(bytes, offset).map(u16::from_le_bytes)
}

fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, String>
{
    le::<4>(bytes, offset).map(u32::from_le_bytes)
}

fn u64_at(bytes: &[u8], offset: usize) -> Result<u64, String>
{
    le::<8>(bytes, offset).map(u64::from_le_bytes)
}

fn usize_at(bytes: &[u8], offset: usize) -> Result<usize, String>
{
    let value = u64_at(bytes, offset)?;
    usize::try_from(value).map_err(|_| format!("{value:#x} at {offset:#x} is not an offset"))
}

/// One program header: type, file offset, address, and file bytes.
struct Segment
{
    kind: u32,
    offset: usize,
    vaddr: u64,
    filesz: usize,
}

impl Segment
{
    /// The file offset of `va`, when the segment's file bytes hold it.
    fn file_offset(&self, va: u64) -> Option<usize>
    {
        let into = usize::try_from(va.checked_sub(self.vaddr)?).ok()?;
        (self.kind == PT_LOAD && into < self.filesz).then(|| self.offset.saturating_add(into))
    }
}

/// Check the core of a death in `mode`.
fn check_core(core: &[u8], mode: &str) -> Result<(), String>
{
    if core.get(..4) != Some(b"\x7fELF".as_slice()) || core.get(4..6) != Some([2, 1].as_slice())
    {
        return Err("not a 64-bit little-endian ELF file".into());
    }
    if u16_at(core, 16)? != ET_CORE
    {
        return Err("not ET_CORE".into());
    }
    if u16_at(core, 18)? != machine::EM
    {
        return Err(format!(
            "e_machine {} is not this machine's",
            u16_at(core, 18)?
        ));
    }
    let phoff = usize_at(core, 32)?;
    let phentsize = usize::from(u16_at(core, 54)?);
    let segments = (0..usize::from(u16_at(core, 56)?))
        .map(|i| {
            let at = phoff.saturating_add(i.saturating_mul(phentsize));
            Ok(Segment {
                kind: u32_at(core, at)?,
                offset: usize_at(core, at.saturating_add(8))?,
                vaddr: u64_at(core, at.saturating_add(16))?,
                filesz: usize_at(core, at.saturating_add(32))?,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let note = segments
        .iter()
        .find(|s| s.kind == PT_NOTE)
        .ok_or("no PT_NOTE")?;
    let statuses = prstatus_notes(
        core.get(note.offset..note.offset.saturating_add(note.filesz))
            .ok_or("PT_NOTE past the file")?,
    )?;
    let first = statuses.first().ok_or("no NT_PRSTATUS")?;
    let signal = u32_at(first, 0)?;
    let expected = if mode == "vm" { SIGSEGV } else { SIGILL };
    if signal != expected
    {
        return Err(format!("signal {signal}, expected {expected}"));
    }
    let ip = u64_at(first, PRSTATUS_HEAD + 8 * machine::IP_INDEX)?;
    let sp = u64_at(first, PRSTATUS_HEAD + 8 * machine::SP_INDEX)?;
    let at_ip = segments
        .iter()
        .find_map(|s| s.file_offset(ip))
        .ok_or_else(|| format!("ip {ip:#x} is in no written PT_LOAD"))?;
    if mode != "vm"
        && core.get(at_ip..at_ip.saturating_add(machine::ILLEGAL.len())) != Some(machine::ILLEGAL)
    {
        return Err(format!(
            "the bytes at ip {ip:#x} are not the illegal instruction"
        ));
    }
    if !segments.iter().any(|s| s.file_offset(sp).is_some())
    {
        return Err(format!("sp {sp:#x} is in no written PT_LOAD"));
    }
    if mode == "worker" && statuses.len() < 2
    {
        return Err(format!(
            "{} thread recorded, expected more than one",
            statuses.len()
        ));
    }
    Ok(())
}

/// The descriptors of the `NT_PRSTATUS` notes in `notes`, in order.
fn prstatus_notes(notes: &[u8]) -> Result<Vec<&[u8]>, String>
{
    let pad = |n: usize| n.next_multiple_of(4);
    let mut out = Vec::new();
    let mut at = 0;
    while at < notes.len()
    {
        let namesz = usize::try_from(u32_at(notes, at)?).map_err(|e| e.to_string())?;
        let descsz =
            usize::try_from(u32_at(notes, at.saturating_add(4))?).map_err(|e| e.to_string())?;
        let kind = u32_at(notes, at.saturating_add(8))?;
        let desc = at.saturating_add(12).saturating_add(pad(namesz));
        let body = notes
            .get(desc..desc.saturating_add(descsz))
            .ok_or("a note past PT_NOTE")?;
        if kind == NT_PRSTATUS
        {
            out.push(body);
        }
        at = desc.saturating_add(pad(descsz));
    }
    Ok(out)
}

/// Run `/programs/crashme registry-declare`, which faults on nothing, and
/// check that it passed: its declaration unbound a registered thread's crash
/// binding with the main thread's.
fn check_declare()
{
    let out = Command::new("/programs/crashme")
        .arg("registry-declare")
        .output()
        .expect("run /programs/crashme registry-declare");
    let text = String::from_utf8_lossy(&out.stdout);
    if !out.status.success() || !text.contains("registry-declare: PASS")
    {
        fail(&format!("registry-declare: {}: {text:?}", out.status));
    }
}

/// The stall the usertest boot's crash service holds a fault for
/// (`CRASHD_OOM_STALL_MS` in rootfs/config/svcmgr/tests/crashd.svc).
const STALL_MS: u64 = 3000;
/// How long the filler keeps the pool full after `full` for the fault that
/// resumes: well inside [`STALL_MS`].
const RESUME_FILL_MS: u64 = 1000;
/// How long a fault that resumes was held at least: half of
/// [`RESUME_FILL_MS`], the rest being the filler's tick and the tester's
/// write after `full`.
const RESUME_HELD_MIN_MS: u128 = 500;
/// How long the filler keeps the pool full after `full` for the fault that
/// times out: past [`STALL_MS`], by enough for the crash service to see the
/// deadline pass first.
const TIMEOUT_FILL_MS: u64 = STALL_MS + 1500;
/// How long a fault that times out was held at least, from the write.
const TIMEOUT_HELD_MIN_MS: u128 = 1000;
/// How long the tester waits for either fixture to exit.
const OOM_WAIT: Duration = Duration::from_secs(30);
/// Bytes of stack the tester touches before a window, below its frame.
const STACK_TOUCH_BYTES: usize = 16 * 1024;
/// The pages `oom-touch` writes: 1024, 64 chunks. No process the tester ends
/// frees memory between the filler's `full` and the writes, but memmgr goes on
/// evicting at `CRITICAL`, and once the restore headroom has reached the
/// reserve each eviction it completes frees pages above the growth floor until
/// the filler's next top-up takes them back (services/memmgr/docs/memory-pool.md
/// § Eviction). Each write's fault backs a chunk, so the writes spend those
/// pages and memmgr declines the first write past them.
const TOUCH_PAGES: &str = "1024";

/// One `oom-touch` fixture, between its `ready` and its write.
struct Toucher
{
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    line: String,
}

/// Start `/programs/crashme oom-touch` [`TOUCH_PAGES`] and wait for its
/// `ready`.
fn start_toucher() -> Toucher
{
    let mut child = Command::new("/programs/crashme")
        .arg("oom-touch")
        .arg(TOUCH_PAGES)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn /programs/crashme oom-touch");
    let mut stdin = child.stdin.take().expect("piped stdin");
    let mut stdout = BufReader::new(child.stdout.take().expect("piped stdout"));
    let mut line = String::with_capacity(256);
    stdin.write_all(b"start\n").expect("write to oom-touch");
    stdout.read_line(&mut line).expect("read oom-touch stdout");
    if line.trim() != "ready"
    {
        fail(&format!("oom-touch: expected ready, read {line:?}"));
    }
    line.clear();
    Toucher {
        child,
        stdin,
        stdout,
        line,
    }
}

/// Start `/programs/crashme oom-fill <hold_ms>` and wait for its `full`: the
/// pool is then full down to the growth floor, and memmgr declines a demand
/// fault of any process outside it.
#[expect(
    clippy::zombie_processes,
    reason = "the child is returned at `full`, and the caller waits on it (`wait_bounded`)"
)]
fn start_filler(hold_ms: u64) -> Child
{
    let mut child = Command::new("/programs/crashme")
        .arg("oom-fill")
        .arg(hold_ms.to_string())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn /programs/crashme oom-fill");
    let mut stdout = BufReader::new(child.stdout.take().expect("piped stdout"));
    let mut line = String::new();
    loop
    {
        line.clear();
        if stdout.read_line(&mut line).expect("read oom-fill stdout") == 0
        {
            let status = wait_bounded(&mut child, "oom-fill");
            fail(&format!("oom-fill: exited before full: {status}"));
        }
        if line.trim() == "full"
        {
            return child;
        }
    }
}

/// Wait for `child` up to [`OOM_WAIT`], killing it and failing past that.
fn wait_bounded(child: &mut Child, what: &str) -> ExitStatus
{
    let start = Instant::now();
    loop
    {
        if let Some(status) = child.try_wait().expect("try_wait")
        {
            return status;
        }
        if start.elapsed() > OOM_WAIT
        {
            let _ = child.kill();
            fail(&format!("{what}: still running after {OOM_WAIT:?}"));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Touch [`STACK_TOUCH_BYTES`] of the stack below this frame, so the window
/// faults no new stack page of the tester.
#[inline(never)]
#[expect(
    clippy::large_stack_frames,
    reason = "the frame is the touch: its array is the stack the window may use, written once before it"
)]
fn touch_stack()
{
    let mut probe = [0u8; STACK_TOUCH_BYTES];
    std::hint::black_box(&mut probe);
}

/// The crash service's hold of a fault memmgr declined for want of memory
/// (services/crashd/docs/operation.md § Hold). A fixture writes the pages of a
/// demand region while a filler keeps the pool full down to the growth floor:
/// when the filler gives it back within the stall, the writes complete and the
/// fixture prints how long the held one took; when it holds the pool past the stall, the hold times
/// out and the fixture dies of the fault, with no core written, since memory
/// was still critical.
///
/// Between the filler's `full` and its exit the tester allocates nothing and
/// touches no new stack page, since a fault of its own would be held too.
#[expect(
    clippy::cast_sign_loss,
    reason = "ExitStatus::code() is i32, but exit reasons are non-negative (fault 0x1000+vector); \
              the u64 cast preserves the value"
)]
fn check_oom_hold()
{
    // A fault the hold resumes.
    let mut toucher = start_toucher();
    touch_stack();
    let mut filler = start_filler(RESUME_FILL_MS);
    toucher
        .stdin
        .write_all(b"go\n")
        .expect("write to oom-touch");
    // The fixture prints its line when the write completes, or dies of the
    // fault and closes its stdout when the hold times out.
    toucher
        .stdout
        .read_line(&mut toucher.line)
        .expect("read oom-touch stdout");
    let status = wait_bounded(&mut toucher.child, "oom-touch (resume)");
    let fill = wait_bounded(&mut filler, "oom-fill (resume)");
    if !fill.success()
    {
        fail(&format!("oom-fill (resume): {fill}"));
    }
    let held = toucher
        .line
        .trim()
        .strip_prefix("touched held_ms=")
        .and_then(|ms| ms.parse::<u128>().ok());
    match held
    {
        Some(ms) if status.success() && ms >= RESUME_HELD_MIN_MS =>
        {}
        _ => fail(&format!(
            "oom-touch (resume): {status}, {:?}: the write was not held and resumed",
            toucher.line
        )),
    }

    // A fault the hold times out on.
    let before = cores();
    let mut toucher = start_toucher();
    touch_stack();
    let mut filler = start_filler(TIMEOUT_FILL_MS);
    toucher
        .stdin
        .write_all(b"go\n")
        .expect("write to oom-touch");
    let start = Instant::now();
    let status = wait_bounded(&mut toucher.child, "oom-touch (timeout)");
    let died_after = start.elapsed().as_millis();
    let fill = wait_bounded(&mut filler, "oom-fill (timeout)");
    if !fill.success()
    {
        fail(&format!("oom-fill (timeout): {fill}"));
    }
    let reason = status.code().map(|code| code as u64);
    if status.success()
        || !reason.is_some_and(|r| (EXIT_FAULT_BASE..EXIT_KILLED).contains(&r))
        || died_after < TIMEOUT_HELD_MIN_MS
    {
        fail(&format!(
            "oom-touch (timeout): {status} after {died_after} ms: the fault was not held and \
             declined"
        ));
    }
    let new: Vec<String> = cores().difference(&before).cloned().collect();
    if !new.is_empty()
    {
        fail(&format!(
            "oom-touch (timeout): a core was written while memory was critical: {new:?}"
        ));
    }
}

fn main()
{
    check("vm");
    check("exception");
    check("worker");
    check_declare();
    check_oom_hold();
    println!("[crashme-tester] PASS");
}
