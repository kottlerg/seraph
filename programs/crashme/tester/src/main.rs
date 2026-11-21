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
//! It also asks the crash service for a live core of `crashme live`
//! ([`check_live`]) through the `crashd.core` seed usertest's recipe declares
//! for it, and checks the fixture ran on unchanged and the core holds every
//! registered thread, stopped nowhere, and the fixture's marked page; then
//! asks for one of `crashme live-no-core`, which declared itself on the core
//! path, and checks the refusal ([`check_live_no_core`]).
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

/// One program header: type, file offset, address, file bytes and memory
/// bytes.
struct Segment
{
    kind: u32,
    offset: usize,
    vaddr: u64,
    filesz: usize,
    memsz: u64,
}

impl Segment
{
    /// The file offset of `va`, when the segment's file bytes hold it.
    fn file_offset(&self, va: u64) -> Option<usize>
    {
        let into = usize::try_from(va.checked_sub(self.vaddr)?).ok()?;
        (self.kind == PT_LOAD && into < self.filesz).then(|| self.offset.saturating_add(into))
    }

    /// Whether the segment is a `PT_LOAD` whose memory holds `va`, file
    /// bytes or none.
    fn covers(&self, va: u64) -> bool
    {
        self.kind == PT_LOAD
            && va
                .checked_sub(self.vaddr)
                .is_some_and(|into| into < self.memsz)
    }
}

/// The program headers of `core`, an `ET_CORE` of this machine, and the
/// descriptors of its `NT_PRSTATUS` notes, in order.
fn read_core(core: &[u8]) -> Result<(Vec<Segment>, Vec<&[u8]>), String>
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
                memsz: u64_at(core, at.saturating_add(40))?,
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
    Ok((segments, statuses))
}

/// Check the core of a death in `mode`.
fn check_core(core: &[u8], mode: &str) -> Result<(), String>
{
    let (segments, statuses) = read_core(core)?;
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

/// Threads `crashme live` runs: its main thread and the two it parks.
const LIVE_THREADS: usize = 3;
/// The word `crashme live` fills its marked page with.
const LIVE_MARK: u64 = 0x4c49_5645_434f_5245;
/// Bytes of the marked page.
const LIVE_MARK_BYTES: usize = 4096;

/// Take the one seed usertest's recipe declares for this tester
/// (`crashd.core`) over the bootstrap protocol, start `crashme live`, and
/// ask the crash service for a live core of it, charged to this tester's own
/// memmgr account. Check the reply, that the fixture then ran on with its
/// threads and its marked page unchanged and exited cleanly, and the core
/// ([`check_live_core`]).
/// Defect guarded: a live core that stops or changes its process, or one
/// that does not record its threads, their stacks or its memory.
fn check_live(crashd: u64)
{
    let info = std::os::seraph::startup_info();
    #[expect(
        clippy::cast_ptr_alignment,
        reason = "the IPC buffer page is 4 KiB-aligned, stricter than u64"
    )]
    let ipc_buf = info.ipc_buffer.cast::<u64>();

    let before = cores();
    let mut child = Command::new("/programs/crashme")
        .arg("live")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn /programs/crashme live");
    let mut stdin = child.stdin.take().expect("piped stdin");
    let mut stdout = BufReader::new(child.stdout.take().expect("piped stdout"));
    let mut line = String::new();
    stdout
        .read_line(&mut line)
        .expect("read crashme live stdout");
    let mark = line
        .trim()
        .strip_prefix("ready mark=0x")
        .and_then(|hex| u64::from_str_radix(hex, 16).ok())
        .unwrap_or_else(|| fail(&format!("live: expected ready, read {line:?}")));

    let request = live_core_request("live");
    // SAFETY: ipc_buf is the registered IPC buffer.
    let reply = match unsafe { ipc::ipc_call(crashd, &request, ipc_buf) }
    {
        Ok(reply) => reply,
        Err(e) => fail(&format!("live: the LIVE_CORE call failed ({e})")),
    };
    if reply.label != ipc::crashd_errors::SUCCESS
    {
        fail(&format!(
            "live: LIVE_CORE answered {:#x} ({:#x})",
            reply.label,
            reply.word(0)
        ));
    }

    stdin.write_all(b"check\n").expect("write to crashme live");
    line.clear();
    stdout
        .read_line(&mut line)
        .expect("read crashme live stdout");
    let status = child.wait().expect("wait /programs/crashme live");
    if !status.success() || !line.contains("live: PASS")
    {
        fail(&format!(
            "live: the fixture did not run on unchanged: {status}, {line:?}"
        ));
    }

    let new: Vec<String> = cores().difference(&before).cloned().collect();
    let [name] = new.as_slice()
    else
    {
        fail(&format!(
            "live: expected one new core in {CORE_DIR}, found {new:?}"
        ));
    };
    if !name.starts_with(&format!("{:010}-", reply.word(1)))
    {
        fail(&format!(
            "live: the new core {name} is not core {}",
            reply.word(1)
        ));
    }
    let path = format!("{CORE_DIR}/{name}");
    let core = std::fs::read(&path).expect("read the live core");
    if core.len() as u64 != reply.word(2)
    {
        fail(&format!(
            "live: {path} holds {} bytes, the reply named {}",
            core.len(),
            reply.word(2)
        ));
    }
    if let Err(why) = check_live_core(&core, mark)
    {
        fail(&format!("live: {path}: {why}"));
    }
}

/// Take the one seed usertest's recipe declares for this tester
/// (`crashd.core`) over the bootstrap protocol.
fn crashd_seed() -> u64
{
    let info = std::os::seraph::startup_info();
    if info.creator_endpoint == 0
    {
        fail("live: no creator endpoint for the declared seed");
    }
    #[expect(
        clippy::cast_ptr_alignment,
        reason = "the IPC buffer page is 4 KiB-aligned, stricter than u64"
    )]
    let ipc_buf = info.ipc_buffer.cast::<u64>();
    // SAFETY: the IPC buffer is registered by `_start` and page-aligned.
    let slots = unsafe { ipc::bootstrap::request_slots::<1>(info.creator_endpoint, ipc_buf) };
    match slots
    {
        Ok([cap]) if cap != 0 => cap,
        other => fail(&format!(
            "live: the declared seed was not delivered: {other:?}"
        )),
    }
}

/// A `LIVE_CORE` request for the fixture, charged to a copy of this tester's
/// own memmgr account. It names the fixture by its whole path: `crashme`
/// alone would name this tester too, `/tests/programs/crashme`, by its last
/// component.
fn live_core_request(what: &str) -> ipc::IpcMessage
{
    let account = syscall::cap_derive(
        std::os::seraph::startup_info().memmgr_endpoint,
        syscall::RIGHTS_EP_SEND,
    )
    .unwrap_or_else(|e| fail(&format!("{what}: no copy of the memmgr account ({e})")));
    ipc::with_name_block(
        ipc::IpcMessage::builder(ipc::crashd_labels::LIVE_CORE),
        0,
        b"/programs/crashme",
        ipc::svcmgr_labels::NAME_MAX,
    )
    .expect("a name within NAME_MAX")
    .cap(account)
    .build()
}

/// The pages charged to this tester's own memmgr account
/// (`QUERY_MEMORY_USAGE` `data[0]`).
fn own_charge(ipc_buf: *mut u64) -> u64
{
    let request = ipc::IpcMessage::new(ipc::memmgr_labels::QUERY_MEMORY_USAGE);
    // SAFETY: ipc_buf is the registered IPC buffer.
    match unsafe {
        ipc::ipc_call(
            std::os::seraph::startup_info().memmgr_endpoint,
            &request,
            ipc_buf,
        )
    }
    {
        Ok(reply) if reply.label == ipc::memmgr_errors::SUCCESS => reply.word(0),
        Ok(reply) => fail(&format!("QUERY_MEMORY_USAGE answered {:#x}", reply.label)),
        Err(e) => fail(&format!("QUERY_MEMORY_USAGE failed ({e})")),
    }
}

/// Start `crashme live-no-core`, which declares itself on the core path, and
/// ask the crash service for a live core of it, charged to this tester's own
/// account. Check that the crash service refused with `NO_CORE`, wrote no
/// core, and left the account charged as before the request, its snapshot
/// released; and that the fixture ran on and exited cleanly.
/// Defect guarded: a live core of a process on the core path (a core of
/// another process's pages it handled), or a refused snapshot left charged to
/// the requester.
fn check_live_no_core(crashd: u64)
{
    let info = std::os::seraph::startup_info();
    #[expect(
        clippy::cast_ptr_alignment,
        reason = "the IPC buffer page is 4 KiB-aligned, stricter than u64"
    )]
    let ipc_buf = info.ipc_buffer.cast::<u64>();
    let before = cores();
    let mut child = Command::new("/programs/crashme")
        .arg("live-no-core")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn /programs/crashme live-no-core");
    let mut stdin = child.stdin.take().expect("piped stdin");
    let mut stdout = BufReader::new(child.stdout.take().expect("piped stdout"));
    let mut line = String::new();
    stdout
        .read_line(&mut line)
        .expect("read crashme live-no-core stdout");
    if line.trim() != "ready"
    {
        fail(&format!("live-no-core: expected ready, read {line:?}"));
    }

    // Nothing between the two reads of the charge allocates or touches a new
    // page of this tester.
    let request = live_core_request("live-no-core");
    let charged = own_charge(ipc_buf);
    // SAFETY: ipc_buf is the registered IPC buffer.
    let reply = unsafe { ipc::ipc_call(crashd, &request, ipc_buf) };
    let after = own_charge(ipc_buf);
    match reply
    {
        Ok(r) if r.label == ipc::crashd_errors::NO_CORE =>
        {}
        Ok(r) => fail(&format!(
            "live-no-core: LIVE_CORE answered {:#x}, expected NO_CORE",
            r.label
        )),
        Err(e) => fail(&format!("live-no-core: the LIVE_CORE call failed ({e})")),
    }
    if after != charged
    {
        fail(&format!(
            "live-no-core: the account holds {after} pages after the refusal, {charged} before"
        ));
    }

    stdin
        .write_all(b"exit\n")
        .expect("write to crashme live-no-core");
    let status = child.wait().expect("wait /programs/crashme live-no-core");
    if !status.success()
    {
        fail(&format!("live-no-core: the fixture exited {status}"));
    }
    let new: Vec<String> = cores().difference(&before).cloned().collect();
    if !new.is_empty()
    {
        fail(&format!("live-no-core: a core was written: {new:?}"));
    }
}

/// Check a live core of `crashme live`, whose marked page is at `mark`: an
/// `ET_CORE` of this machine with an `NT_PRSTATUS` of signal 0 for each of
/// its [`LIVE_THREADS`] threads, each stack pointer in a written `PT_LOAD`,
/// and every word of the marked bytes in one, holding the mark.
fn check_live_core(core: &[u8], mark: u64) -> Result<(), String>
{
    let (segments, statuses) = read_core(core)?;
    if statuses.len() < LIVE_THREADS
    {
        return Err(format!(
            "{} threads recorded, expected {LIVE_THREADS}",
            statuses.len()
        ));
    }
    for status in &statuses
    {
        let signal = u32_at(status, 0)?;
        if signal != 0
        {
            return Err(format!("signal {signal}, expected 0 for a live core"));
        }
        let sp = u64_at(status, PRSTATUS_HEAD + 8 * machine::SP_INDEX)?;
        if !segments.iter().any(|s| s.file_offset(sp).is_some())
        {
            return Err(format!("sp {sp:#x} is in no written PT_LOAD"));
        }
    }
    // The main thread waits in the binary's text, whose pages the image
    // shares: a live core lists none of them, so a debugger reads them from
    // the binary rather than as zeros.
    let first = statuses.first().ok_or("no NT_PRSTATUS")?;
    let ip = u64_at(first, PRSTATUS_HEAD + 8 * machine::IP_INDEX)?;
    if segments.iter().any(|s| s.covers(ip))
    {
        return Err(format!("ip {ip:#x}, in the image's text, is in a PT_LOAD"));
    }
    // The mark spans two pages, which may lie in two runs.
    for offset in (0..LIVE_MARK_BYTES).step_by(8)
    {
        let va = mark.saturating_add(offset as u64);
        let at = segments
            .iter()
            .find_map(|s| s.file_offset(va))
            .ok_or_else(|| format!("the marked word at {va:#x} is in no written PT_LOAD"))?;
        if u64_at(core, at)? != LIVE_MARK
        {
            return Err(format!("the marked word at {va:#x} does not hold the mark"));
        }
    }
    Ok(())
}

fn main()
{
    check("vm");
    check("exception");
    check("worker");
    check_declare();
    check_oom_hold();
    let crashd = crashd_seed();
    check_live(crashd);
    check_live_no_core(crashd);
    println!("[crashme-tester] PASS");
}
