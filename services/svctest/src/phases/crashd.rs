// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/crashd.rs

//! Crash-service surfaces, driven through `/tests/fixtures/programs/crashme`. The faults phase
//! (`crashd_faults`) runs it in each mode the crash-report check reads, `vm`, `exception`, and
//! `worker`, and checks that it reached its fault and died of it: a non-clean exit whose reason
//! is a fault class, so the crash service's decline ended the thread as the kernel would have. It
//! also runs `registry-declare`, which faults on nothing, and checks that it passed. The report
//! block each death leaves in the log is checked host-side, from the boot's serial log, by
//! `cargo xtask run --crash-reports` (docs/testing.md § Crash reports).
//!
//! svctest's staging stages a crash service whose `CORE_DUMP` names crashme
//! (rootfs/config/svcmgr/tests/crashd.svc), so each faulting mode also leaves one ELF core in
//! `/crash`; the cores phase (`crashd_cores`) checks the ones the faults phase recorded
//! (services/crashd/docs/core-format.md): an `ET_CORE` of this machine whose first
//! `NT_PRSTATUS` carries the fault's signal, an instruction pointer in a written `PT_LOAD` (at
//! the illegal instruction, for the modes that execute it) and a stack pointer in one, and, for
//! `worker`, more than one thread.
//!
//! The live-core phase (`crashd_live_core`) first checks that a spawn returns with its runtime
//! thread's pages charged ([`check_spawn_charge`]). It then asks the crash service for a live core
//! of `crashme live` ([`check_live`]) through `caps.crashd_core`, and checks the fixture ran on
//! unchanged and the core holds every registered thread, stopped nowhere, and the fixture's marked
//! page; asks for one of `crashme live-no-core`, which declared itself on the core path, on an
//! account that cannot fund a snapshot, and checks the refusal ([`check_live_no_core`]); and asks
//! for one procmgr refuses after it took frames ([`check_live_refused`]) and one the crash service
//! refuses after the capture, for a declaration made during the request ([`check_live_declared`]),
//! and checks that each left this process's charge as it was.
//!
//! The hold phase (`crashd_oom_hold`) runs `oom-touch` beside `oom-fill`, which checks the
//! crash service's hold of a fault memmgr declined for want of memory ([`check_oom_hold`]).

use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::seraph::thread::BuilderExt;
use std::process::{Child, ChildStdin, ChildStdout, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::bootstrap::Caps;
use crate::runner::Phase;

/// The fault, core and live-core phases.
pub fn faults_and_cores() -> &'static [Phase]
{
    &[
        Phase {
            name: "crashd_faults",
            run: crashd_faults_phase,
        },
        Phase {
            name: "crashd_cores",
            run: crashd_cores_phase,
        },
        Phase {
            name: "crashd_live_core",
            run: crashd_live_core_phase,
        },
    ]
}

/// The hold phase, which the phase order places after the swap phases
/// (`super::all`).
pub fn oom_hold() -> &'static [Phase]
{
    &[Phase {
        name: "crashd_oom_hold",
        run: crashd_oom_hold_phase,
    }]
}

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

/// Run `/tests/fixtures/programs/crashme <mode>` and check it reached its fault and died of
/// it.
#[expect(
    clippy::cast_sign_loss,
    reason = "ExitStatus::code() is i32, but exit reasons are non-negative (fault 0x1000+vector); \
              the u64 cast preserves the value"
)]
fn check(mode: &str)
{
    let before = cores();
    let mut child = Command::new("/tests/fixtures/programs/crashme")
        .arg(mode)
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn /tests/fixtures/programs/crashme");
    let mut bytes = Vec::new();
    child
        .stdout
        .take()
        .expect("piped stdout")
        .read_to_end(&mut bytes)
        .expect("read /tests/fixtures/programs/crashme stdout");
    let status = child.wait().expect("wait /tests/fixtures/programs/crashme");
    let out = String::from_utf8_lossy(&bytes);
    assert!(
        out.contains(&format!("faulting ({mode})")),
        "crashd_faults: {mode}: the fixture never reached its fault: {out:?}"
    );
    assert!(
        !status.success(),
        "crashd_faults: {mode}: the fixture exited cleanly"
    );
    let reason = status.code().expect("a fault death carries a reason") as u64;
    assert!(
        (EXIT_FAULT_BASE..EXIT_KILLED).contains(&reason),
        "crashd_faults: {mode}: exit reason {reason:#x} is not a fault class"
    );
    let new: Vec<String> = cores().difference(&before).cloned().collect();
    let [name] = new.as_slice()
    else
    {
        panic!("crashd_faults: {mode}: expected one new core in {CORE_DIR}, found {new:?}");
    };
    RECORDED
        .lock()
        .expect("lock the recorded cores")
        .push((mode.to_string(), name.clone()));
}

/// The cores [`check`] found, as (mode, name) in the order the modes ran, for
/// [`crashd_cores_phase`].
static RECORDED: Mutex<Vec<(String, String)>> = Mutex::new(Vec::new());

/// Check the core each faulting mode left, as [`check`] recorded it.
fn crashd_cores_phase(_: &Caps)
{
    let recorded = RECORDED.lock().expect("lock the recorded cores");
    assert!(
        !recorded.is_empty(),
        "crashd_cores: crashd_faults recorded no core"
    );
    for (mode, name) in recorded.iter()
    {
        let path = format!("{CORE_DIR}/{name}");
        let core = std::fs::read(&path).expect("read the core");
        if let Err(why) = check_core(&core, mode)
        {
            panic!("crashd_cores: {mode}: {path}: {why}");
        }
    }
}

fn crashd_faults_phase(_: &Caps)
{
    check("vm");
    check("exception");
    check("worker");
    check_declare();
}

fn crashd_live_core_phase(caps: &Caps)
{
    assert_ne!(
        caps.crashd_core, 0,
        "crashd_live_core: no crashd.core authority delivered"
    );
    check_spawn_charge();
    check_live(caps.crashd_core);
    check_live_no_core(caps.crashd_core);
    check_live_refused(caps.crashd_core);
    check_live_declared(caps.crashd_core);
}

fn crashd_oom_hold_phase(_: &Caps)
{
    check_oom_hold();
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

/// Run `/tests/fixtures/programs/crashme registry-declare`, which faults on nothing, and
/// check that it passed: its declaration unbound a registered thread's crash
/// binding with the main thread's.
fn check_declare()
{
    let out = Command::new("/tests/fixtures/programs/crashme")
        .arg("registry-declare")
        .output()
        .expect("run /tests/fixtures/programs/crashme registry-declare");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && text.contains("registry-declare: PASS"),
        "crashd_faults: registry-declare: {}: {text:?}",
        out.status
    );
}

/// How long the filler keeps the pool full after `full` for the fault that
/// resumes: well inside the stall `crashd_stall` names.
const RESUME_FILL_MS: u64 = 1000;
/// How long a fault that resumes was held at least: half of
/// [`RESUME_FILL_MS`], the rest being the filler's tick and the phase's
/// write after `full`.
const RESUME_HELD_MIN_MS: u128 = 500;
/// How long the phase waits for either fixture to exit, past the stall for
/// the fixture whose hold times out.
const OOM_WAIT: Duration = Duration::from_secs(30);
/// Bytes of stack the phase touches before a window, below its frame.
const STACK_TOUCH_BYTES: usize = 16 * 1024;
/// The pages `oom-touch` writes: 1024, 64 chunks. No process the phase ends
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

/// Start `/tests/fixtures/programs/crashme oom-touch` [`TOUCH_PAGES`] and wait for its
/// `ready`.
fn start_toucher() -> Toucher
{
    let mut child = Command::new("/tests/fixtures/programs/crashme")
        .arg("oom-touch")
        .arg(TOUCH_PAGES)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn /tests/fixtures/programs/crashme oom-touch");
    let mut stdin = child.stdin.take().expect("piped stdin");
    let mut stdout = BufReader::new(child.stdout.take().expect("piped stdout"));
    let mut line = String::with_capacity(256);
    stdin.write_all(b"start\n").expect("write to oom-touch");
    stdout.read_line(&mut line).expect("read oom-touch stdout");
    assert!(
        line.trim() == "ready",
        "crashd_oom_hold: oom-touch: expected ready, read {line:?}"
    );
    line.clear();
    Toucher {
        child,
        stdin,
        stdout,
        line,
    }
}

/// Start `/tests/fixtures/programs/crashme oom-fill <hold_ms>` and wait for its `full`: the
/// pool is then full down to the growth floor, and memmgr declines a demand
/// fault of any process outside it.
#[expect(
    clippy::zombie_processes,
    reason = "the child is returned at `full`, and the caller waits on it (`wait_bounded`)"
)]
fn start_filler(hold_ms: u64) -> Child
{
    let mut child = Command::new("/tests/fixtures/programs/crashme")
        .arg("oom-fill")
        .arg(hold_ms.to_string())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn /tests/fixtures/programs/crashme oom-fill");
    let mut stdout = BufReader::new(child.stdout.take().expect("piped stdout"));
    let mut line = String::new();
    loop
    {
        line.clear();
        if stdout.read_line(&mut line).expect("read oom-fill stdout") == 0
        {
            let status = wait_bounded(&mut child, "oom-fill");
            panic!("crashd_oom_hold: oom-fill: exited before full: {status}");
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
    wait_within(child, what, OOM_WAIT)
}

/// Wait for `child` up to `bound`, killing it and failing past that.
fn wait_within(child: &mut Child, what: &str, bound: Duration) -> ExitStatus
{
    let start = Instant::now();
    loop
    {
        if let Some(status) = child.try_wait().expect("try_wait")
        {
            return status;
        }
        if start.elapsed() > bound
        {
            let _ = child.kill();
            panic!("crashd_oom_hold: {what}: still running after {bound:?}");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Touch [`STACK_TOUCH_BYTES`] of the stack below this frame, so the window
/// faults no new stack page of the phase.
#[inline(never)]
#[expect(
    clippy::large_stack_frames,
    reason = "the frame is the touch: its array is the stack the window may use, written once \
              before it"
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
/// fixture prints how long the held one took; when it holds the pool until the
/// fixture has died, the hold times out and the fixture dies of the fault, at
/// least the stall after its write, with no core written, since memory was
/// still critical.
///
/// oomd stops its candidates while the level reads `CRITICAL`, a grace and
/// then a cooldown apart, and a stop that frees memory ends the hold it finds;
/// the fixture's next write is then held anew. The timeout case's filler
/// therefore keeps the pool full until the fixture has died, and the phase
/// then kills it: only the last hold has to outlast the stall.
///
/// Between the filler's `full` and its exit the phase allocates nothing and
/// touches no new stack page, since a fault of its own would be held too.
#[expect(
    clippy::cast_sign_loss,
    reason = "ExitStatus::code() is i32, but exit reasons are non-negative (fault 0x1000+vector); \
              the u64 cast preserves the value"
)]
fn check_oom_hold()
{
    let stall_ms = super::oom::crashd_stall("crashd_oom_hold")
        .expect("crashd_oom_hold: crashd's recipe is not staged or holds no fault");
    let stall = Duration::from_millis(stall_ms);
    let toucher_bound = OOM_WAIT.saturating_add(stall);
    // Longer than the phase waits for the fixture, so only the phase's kill
    // ends it.
    let timeout_fill_ms =
        u64::try_from(toucher_bound.saturating_add(OOM_WAIT).as_millis()).unwrap_or(u64::MAX);
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
    assert!(fill.success(), "crashd_oom_hold: oom-fill (resume): {fill}");
    let held = toucher
        .line
        .trim()
        .strip_prefix("touched held_ms=")
        .and_then(|ms| ms.parse::<u128>().ok());
    match held
    {
        Some(ms) if status.success() && ms >= RESUME_HELD_MIN_MS =>
        {}
        _ => panic!(
            "crashd_oom_hold: oom-touch (resume): {status}, {:?}: the write was not held and \
             resumed",
            toucher.line
        ),
    }

    // A fault the hold times out on.
    let before = cores();
    let mut toucher = start_toucher();
    touch_stack();
    let mut filler = start_filler(timeout_fill_ms);
    toucher
        .stdin
        .write_all(b"go\n")
        .expect("write to oom-touch");
    let start = Instant::now();
    let status = wait_within(&mut toucher.child, "oom-touch (timeout)", toucher_bound);
    let died_after = start.elapsed().as_millis();
    let filling = filler.try_wait().expect("try_wait").is_none();
    let _ = filler.kill();
    let _ = wait_bounded(&mut filler, "oom-fill (timeout)");
    assert!(
        filling,
        "crashd_oom_hold: oom-fill (timeout): exited before oom-touch died"
    );
    let reason = status.code().map(|code| code as u64);
    if status.success()
        || !reason.is_some_and(|r| (EXIT_FAULT_BASE..EXIT_KILLED).contains(&r))
        || died_after < stall.as_millis()
    {
        panic!(
            "crashd_oom_hold: oom-touch (timeout): {status} after {died_after} ms: the fault was \
             not held and declined"
        );
    }
    let new: Vec<String> = cores().difference(&before).cloned().collect();
    assert!(
        new.is_empty(),
        "crashd_oom_hold: oom-touch (timeout): a core was written while memory was critical: \
             {new:?}"
    );
}

/// Threads `crashme live` runs: its main thread and the two it parks.
const LIVE_THREADS: usize = 3;
/// The word `crashme live` fills its marked page with.
const LIVE_MARK: u64 = 0x4c49_5645_434f_5245;
/// Bytes of the marked page.
const LIVE_MARK_BYTES: usize = 4096;

/// With `caps.crashd_core`, start `crashme live`, and
/// ask the crash service for a live core of it, charged to this phase's own
/// memmgr account. Check the reply, that the fixture then ran on with its
/// threads and its marked page unchanged and exited cleanly, and the core
/// ([`check_live_core`]).
/// Defect guarded: a live core that stops or changes its process, or one
/// that does not record its threads, their stacks or its memory.
fn check_live(crashd: u64)
{
    let ipc_buf = std::os::seraph::current_ipc_buf();

    let before = cores();
    let mut child = Command::new("/tests/fixtures/programs/crashme")
        .arg("live")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn /tests/fixtures/programs/crashme live");
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
        .unwrap_or_else(|| panic!("crashd_live_core: live: expected ready, read {line:?}"));

    let request = live_core_request(own_account("live"));
    // SAFETY: ipc_buf is the registered IPC buffer.
    let reply = match unsafe { ipc::ipc_call(crashd, &request, ipc_buf) }
    {
        Ok(reply) => reply,
        Err(e) => panic!("crashd_live_core: live: the LIVE_CORE call failed ({e})"),
    };
    assert!(
        reply.label == ipc::crashd_errors::SUCCESS,
        "crashd_live_core: live: LIVE_CORE answered {:#x} ({:#x})",
        reply.label,
        reply.word(0)
    );

    stdin.write_all(b"check\n").expect("write to crashme live");
    line.clear();
    stdout
        .read_line(&mut line)
        .expect("read crashme live stdout");
    let status = child
        .wait()
        .expect("wait /tests/fixtures/programs/crashme live");
    assert!(
        status.success() && line.contains("live: PASS"),
        "crashd_live_core: live: the fixture did not run on unchanged: {status}, {line:?}"
    );

    let new: Vec<String> = cores().difference(&before).cloned().collect();
    let [name] = new.as_slice()
    else
    {
        panic!("crashd_live_core: live: expected one new core in {CORE_DIR}, found {new:?}");
    };
    assert!(
        name.starts_with(&format!("{:010}-", reply.word(1))),
        "crashd_live_core: live: the new core {name} is not core {}",
        reply.word(1)
    );
    let path = format!("{CORE_DIR}/{name}");
    let core = std::fs::read(&path).expect("read the live core");
    assert!(
        core.len() as u64 == reply.word(2),
        "crashd_live_core: live: {path} holds {} bytes, the reply named {}",
        core.len(),
        reply.word(2)
    );
    if let Err(why) = check_live_core(&core, mark)
    {
        panic!("crashd_live_core: live: {path}: {why}");
    }
}

/// A copy of this process's own memmgr account, for a `LIVE_CORE` request
/// about the fixture mode `what`.
fn own_account(what: &str) -> u64
{
    syscall::cap_derive(
        std::os::seraph::startup_info().memmgr_endpoint,
        syscall::RIGHTS_EP_SEND,
    )
    .unwrap_or_else(|e| panic!("crashd_live_core: {what}: no copy of the memmgr account ({e})"))
}

/// A `LIVE_CORE` request for the fixture, charged to `account`, which the
/// request carries. It names the fixture by its whole path.
fn live_core_request(account: u64) -> ipc::IpcMessage
{
    ipc::with_name_block(
        ipc::IpcMessage::builder(ipc::crashd_labels::LIVE_CORE),
        0,
        b"/tests/fixtures/programs/crashme",
        ipc::svcmgr_labels::NAME_MAX,
    )
    .expect("a name within NAME_MAX")
    .cap(account)
    .build()
}

/// The charge of this process's own memmgr account, in pages
/// (`QUERY_MEMORY_USAGE` `data[0]`), for the check of the fixture mode
/// `what`.
fn own_charge(what: &str) -> u64
{
    let request = ipc::IpcMessage::new(ipc::memmgr_labels::QUERY_MEMORY_USAGE);
    // SAFETY: the calling thread's registered IPC buffer.
    match unsafe {
        ipc::ipc_call(
            std::os::seraph::startup_info().memmgr_endpoint,
            &request,
            std::os::seraph::current_ipc_buf(),
        )
    }
    {
        Ok(reply) if reply.label == ipc::memmgr_errors::SUCCESS => reply.word(0),
        Ok(reply) => panic!(
            "crashd_live_core: {what}: QUERY_MEMORY_USAGE answered {:#x}",
            reply.label
        ),
        Err(e) => panic!("crashd_live_core: {what}: QUERY_MEMORY_USAGE failed ({e})"),
    }
}

/// Bytes of the longest line [`read_line_raw`] reads.
const LINE_BYTES: usize = 64;

/// Read one line of `out` a byte at a time into `buf`, and return it
/// without its newline. The read allocates nothing, so a check can take it
/// between two readings of its charge. The end of the stream, a failed read,
/// or a full `buf` ends the line early.
fn read_line_raw<'a>(out: &mut ChildStdout, buf: &'a mut [u8; LINE_BYTES]) -> &'a [u8]
{
    let mut len = 0usize;
    while len < LINE_BYTES
    {
        let mut byte = [0u8; 1];
        if !matches!(out.read(&mut byte), Ok(1))
        {
            break;
        }
        let [b] = byte;
        if b == b'\n'
        {
            break;
        }
        if let Some(slot) = buf.get_mut(len)
        {
            *slot = b;
        }
        len = len.saturating_add(1);
    }
    buf.get(..len).unwrap_or_default()
}

/// Check that a spawn starting a runtime thread returns with the thread's
/// pages charged: run [`spawn_and_read`] on a thread of the strict-priority
/// class ([`SPAWN_CHECK_LEVEL`]) pinned to the highest CPU, while a spinning
/// thread at the same level holds each other CPU ([`hold_cpus`]) until the
/// check's first reading is asked for. No fair-class thread runs on a CPU a
/// strict-priority one holds, so the death bridge, a fair-class thread of this
/// process, first runs on the check's CPU once the check blocks: when its
/// spawn waits for it, before the spawn returns; when the spawn does not, only
/// once the first reading is asked for, and the bridge's first stack chunk is
/// charged between the readings. Logs both readings.
fn check_spawn_charge()
{
    let cpus = syscall::system_info(syscall_abi::SystemInfoType::CpuCount as u64)
        .expect("crashd_live_core: spawn: the CPU count");
    let cpu = u32::try_from(cpus.saturating_sub(1)).expect("crashd_live_core: spawn: a CPU index");
    let spin = Arc::new(AtomicBool::new(true));
    let exit = Arc::new(AtomicBool::new(false));
    let holders = hold_cpus(cpu, &spin, &exit);
    let checker = std::thread::Builder::new()
        .name("crashd_live_core_spawn".into())
        .spawn_at_priority(SPAWN_CHECK_LEVEL, move || {
            pin(cpu);
            touch_stack();
            spawn_and_read(&spin)
        })
        .expect("crashd_live_core: spawn: the check's thread");
    let readings = checker.join();
    exit.store(true, Ordering::Relaxed);
    for holder in holders
    {
        let _ = holder.join();
    }
    let (spawned, settled) =
        readings.unwrap_or_else(|_| panic!("crashd_live_core: spawn: the check's thread panicked"));
    std::os::seraph::log!("crashd_live_core: spawn: charge {spawned} then {settled} pages");
    assert!(
        spawned == settled,
        "crashd_live_core: spawn: the account holds {settled} pages once the fixture is ready, \
         {spawned} when the spawn returned: a runtime thread was charged after its spawn"
    );
}

/// Pin the calling thread to `cpu` and yield, so it runs there from now on.
fn pin(cpu: u32)
{
    let cap = std::os::seraph::thread::current_thread_cap();
    syscall::thread_set_affinity(cap, cpu)
        .unwrap_or_else(|e| panic!("crashd_live_core: spawn: pin to CPU {cpu} ({e})"));
    std::thread::yield_now();
}

/// Start a thread at [`SPAWN_CHECK_LEVEL`] pinned to each CPU below `cpu`,
/// which spins while `spin` is set, for at most [`SPIN_BOUND`], then sleeps
/// until `exit` is set and ends; return once every one is pinned. A holder
/// that has stopped spinning stays alive, so its stack stays charged, until
/// `exit`.
fn hold_cpus(cpu: u32, spin: &Arc<AtomicBool>, exit: &Arc<AtomicBool>) -> Vec<JoinHandle<()>>
{
    let (pinned_tx, pinned) = mpsc::channel::<()>();
    let holders: Vec<JoinHandle<()>> = (0..cpu)
        .map(|other| {
            let spin = Arc::clone(spin);
            let exit = Arc::clone(exit);
            let pinned_tx = pinned_tx.clone();
            std::thread::Builder::new()
                .name("crashd_live_core_hold".into())
                .spawn_at_priority(SPAWN_CHECK_LEVEL, move || {
                    pin(other);
                    let _ = pinned_tx.send(());
                    let start = Instant::now();
                    while spin.load(Ordering::Relaxed) && start.elapsed() < SPIN_BOUND
                    {
                        std::hint::spin_loop();
                    }
                    while !exit.load(Ordering::Relaxed)
                    {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                })
                .expect("crashd_live_core: spawn: a CPU's holder")
        })
        .collect();
    drop(pinned_tx);
    for _ in &holders
    {
        pinned
            .recv()
            .expect("crashd_live_core: spawn: a CPU's holder ended before it was pinned");
    }
    holders
}

/// How long a [`hold_cpus`] holder spins at most: the check's first reading
/// comes well within it, and a spawn that cannot go on while the other CPUs
/// are held goes on once it has passed.
const SPIN_BOUND: Duration = Duration::from_millis(500);

/// The level [`check_spawn_charge`] runs at: the floor of the
/// strict-priority class, the top of svctest's band (svctest.svc's
/// `sched_max`).
const SPAWN_CHECK_LEVEL: u8 = 21;

/// Spawn `crashme live-no-core` with its stdin and stdout piped, which starts
/// std's death-bridge runtime thread, and read this process's charge as soon
/// as the spawn returns, then clear `spin`, and read it again once the
/// fixture printed `ready` and a pause has passed, the reads between them
/// allocating nothing. Check that the fixture exited cleanly, and return the
/// two readings, which are equal.
/// Defect guarded: a spawn that returns before its runtime thread reached its
/// wait (`std::os::seraph::runtime_spawn`), so the pages the thread touches on
/// the way, its first stack chunk among them, are charged after the spawn
/// returned and move a charge its spawner reads.
fn spawn_and_read(spin: &AtomicBool) -> (u64, u64)
{
    let mut child = Command::new("/tests/fixtures/programs/crashme")
        .arg("live-no-core")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn /tests/fixtures/programs/crashme live-no-core");
    let spawned = own_charge("spawn");
    spin.store(false, Ordering::Relaxed);
    let mut stdin = child.stdin.take().expect("piped stdin");
    let mut stdout = child.stdout.take().expect("piped stdout");
    let mut buf = [0u8; LINE_BYTES];
    let ready = read_line_raw(&mut stdout, &mut buf) == b"ready";
    std::thread::sleep(SPAWN_SETTLE);
    let settled = own_charge("spawn");
    stdin
        .write_all(b"exit\n")
        .expect("write to crashme live-no-core");
    let status = child
        .wait()
        .expect("wait /tests/fixtures/programs/crashme live-no-core");
    assert!(
        ready && status.success(),
        "crashd_live_core: spawn: the fixture did not run: ready {ready}, {status}"
    );
    (spawned, settled)
}

/// How long [`check_spawn_charge`] waits after `ready` before its second
/// reading, for a runtime thread that had not yet run to reach its stack.
const SPAWN_SETTLE: Duration = Duration::from_millis(20);

/// Badge of the SEND that stops [`serve_account`]; the account's SEND
/// carries none.
const ACCOUNT_STOP_BADGE: u64 = 1;

/// What [`serve_account`] does with a call on the account.
enum Answer
{
    /// Forward it to this process's own memmgr account, which then funds it.
    Forward,
    /// Refuse it with memmgr's `LIMIT`, as memmgr refuses a request its
    /// node's max cannot take.
    Refuse,
}

/// The calls [`serve_account`] forwarded and refused.
#[derive(Clone, Copy, Debug)]
struct Calls
{
    forwarded: u64,
    refused: u64,
}

/// Serve `ep` as a request's account until a call under
/// [`ACCOUNT_STOP_BADGE`], answering each other call as `decide` says:
/// forwarded unchanged, its words and the caps it carried, on this process's
/// own memmgr endpoint, and memmgr's reply, its caps with it, passed back; or
/// refused, its caps deleted. procmgr cannot tell that an account names
/// memmgr (services/procmgr/docs/ipc-interface.md § Label 33: `SNAPSHOT`), so
/// a forwarded call is charged to this process as one on a copy of its memmgr
/// endpoint would be. Returns the calls forwarded and refused.
fn serve_account(ep: u64, mut decide: impl FnMut(&ipc::IpcMessage) -> Answer) -> Calls
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let memmgr = std::os::seraph::startup_info().memmgr_endpoint;
    let mut calls = Calls {
        forwarded: 0,
        refused: 0,
    };
    loop
    {
        // SAFETY: ipc_buf is this thread's registered IPC buffer.
        let msg = unsafe { ipc::ipc_recv(ep, ipc_buf) }
            .expect("crashd_live_core: the account's ipc_recv");
        if msg.badge == ACCOUNT_STOP_BADGE
        {
            for &cap in msg.caps()
            {
                let _ = syscall::cap_delete(cap);
            }
            // SAFETY: as above.
            let _ = unsafe {
                ipc::ipc_reply(&ipc::IpcMessage::new(ipc::memmgr_errors::SUCCESS), ipc_buf)
            };
            return calls;
        }
        let forwarded = match decide(&msg)
        {
            // SAFETY: as above. The call moves the caps msg carried to memmgr.
            Answer::Forward => unsafe { ipc::ipc_call(memmgr, &msg, ipc_buf) }.ok(),
            Answer::Refuse => None,
        };
        let reply = if let Some(reply) = forwarded
        {
            calls.forwarded = calls.forwarded.saturating_add(1);
            reply
        }
        else
        {
            for &cap in msg.caps()
            {
                let _ = syscall::cap_delete(cap);
            }
            calls.refused = calls.refused.saturating_add(1);
            ipc::IpcMessage::new(ipc::memmgr_errors::LIMIT)
        };
        // SAFETY: as above. The reply moves the caps memmgr's reply carried.
        let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
    }
}

/// An account endpoint of this process's own, served on a thread of its own
/// by [`serve_account`] until [`Account::finish`].
struct Account<R>
{
    /// The endpoint the thread serves.
    ep: u64,
    /// The SEND a request carries as its account.
    send: u64,
    /// The SEND that stops the thread.
    stop: u64,
    server: JoinHandle<R>,
}

impl<R: Send + 'static> Account<R>
{
    /// Create the endpoint and start `serve` on it, returning once the
    /// thread has run and touched its stack, so a reading of the charge taken
    /// after it holds the thread's pages.
    fn start(what: &str, serve: impl FnOnce(u64) -> R + Send + 'static) -> Self
    {
        let ep = std::os::seraph::create_endpoint()
            .unwrap_or_else(|| panic!("crashd_live_core: {what}: an account endpoint"));
        let send = syscall::cap_derive(ep, syscall::RIGHTS_EP_SEND)
            .unwrap_or_else(|e| panic!("crashd_live_core: {what}: the account SEND ({e})"));
        let stop = syscall::cap_derive_badge(ep, syscall::RIGHTS_EP_SEND, ACCOUNT_STOP_BADGE)
            .unwrap_or_else(|e| panic!("crashd_live_core: {what}: the account's stop SEND ({e})"));
        let (started_tx, started) = std::sync::mpsc::channel::<()>();
        let server = std::thread::Builder::new()
            .name("crashd_live_core_account".into())
            .spawn(move || {
                touch_stack();
                let _ = started_tx.send(());
                serve(ep)
            })
            .unwrap_or_else(|e| panic!("crashd_live_core: {what}: the account thread ({e})"));
        started
            .recv()
            .unwrap_or_else(|_| panic!("crashd_live_core: {what}: the account thread ended"));
        Self {
            ep,
            send,
            stop,
            server,
        }
    }

    /// Stop the thread and return what it returned. The crash service deletes
    /// the account before it replies, and procmgr ends every call on an
    /// account before its own reply, so after the request's reply no call on
    /// the account follows the stop.
    fn finish(self, what: &str) -> R
    {
        // SAFETY: the calling thread's registered IPC buffer.
        let stopped = unsafe {
            ipc::ipc_call(
                self.stop,
                &ipc::IpcMessage::new(0),
                std::os::seraph::current_ipc_buf(),
            )
        };
        let served = self
            .server
            .join()
            .unwrap_or_else(|_| panic!("crashd_live_core: {what}: the account thread panicked"));
        let _ = syscall::cap_delete(self.stop);
        let _ = syscall::cap_delete(self.ep);
        assert!(
            stopped.is_ok(),
            "crashd_live_core: {what}: the account's stop call failed"
        );
        served
    }
}

/// Start `crashme live-no-core`, which declares itself on the core path, and
/// ask the crash service for a live core of it, charged to an account that
/// cannot fund one: an endpoint of this process's own whose server refuses
/// every call ([`serve_account`]). Check that the crash service refused
/// with `NO_CORE`, that nothing called the account, so no snapshot was asked
/// for and nothing was charged to it, that no core was written, and that the
/// fixture ran on and exited cleanly.
/// Defect guarded: a live core of a process on the core path (a core of
/// another process's pages it handled), or a snapshot taken before the
/// declaration was read, which charges the requester for a capture the
/// refusal discards and answers a requester that cannot fund it
/// `SNAPSHOT_REFUSED`.
fn check_live_no_core(crashd: u64)
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let before = cores();
    let account = Account::start("live-no-core", |ep| serve_account(ep, |_| Answer::Refuse));
    let mut child = Command::new("/tests/fixtures/programs/crashme")
        .arg("live-no-core")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn /tests/fixtures/programs/crashme live-no-core");
    let mut stdin = child.stdin.take().expect("piped stdin");
    let mut stdout = BufReader::new(child.stdout.take().expect("piped stdout"));
    let mut line = String::new();
    stdout
        .read_line(&mut line)
        .expect("read crashme live-no-core stdout");
    assert!(
        line.trim() == "ready",
        "crashd_live_core: live-no-core: expected ready, read {line:?}"
    );

    // SAFETY: ipc_buf is the registered IPC buffer.
    let reply = unsafe { ipc::ipc_call(crashd, &live_core_request(account.send), ipc_buf) };
    let calls = account.finish("live-no-core");
    match reply
    {
        Ok(r) if r.label == ipc::crashd_errors::NO_CORE =>
        {}
        Ok(r) => panic!(
            "crashd_live_core: live-no-core: LIVE_CORE answered {:#x} (data[0] {:#x}), \
             expected NO_CORE",
            r.label,
            r.word(0)
        ),
        Err(e) => panic!("crashd_live_core: live-no-core: the LIVE_CORE call failed ({e})"),
    }
    assert!(
        calls.refused == 0,
        "crashd_live_core: live-no-core: the account was called {} time(s) before the \
         refusal: a snapshot was asked for",
        calls.refused
    );

    stdin
        .write_all(b"exit\n")
        .expect("write to crashme live-no-core");
    let status = child
        .wait()
        .expect("wait /tests/fixtures/programs/crashme live-no-core");
    assert!(
        status.success(),
        "crashd_live_core: live-no-core: the fixture exited {status}"
    );
    let new: Vec<String> = cores().difference(&before).cloned().collect();
    assert!(
        new.is_empty(),
        "crashd_live_core: live-no-core: a core was written: {new:?}"
    );
}

/// Start `crashme live` and ask the crash service for a live core of it,
/// charged to an account of this process's own that funds the snapshot's
/// first frame request from this process's memmgr account and refuses each
/// later one ([`serve_account`]), so procmgr fails the capture after it took
/// frames. Check that the crash service answered `SNAPSHOT_REFUSED`, that the
/// account funded a request and refused one, that this process's charge after
/// the reply is the charge before the request, that no core was written, and
/// that the fixture ran on unchanged.
/// Defect guarded: a refused snapshot left charged to the requester, its
/// frames not returned to the account when the capture fails.
fn check_live_refused(crashd: u64)
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let before = cores();
    let mut child = Command::new("/tests/fixtures/programs/crashme")
        .arg("live")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn /tests/fixtures/programs/crashme live");
    let mut stdin = child.stdin.take().expect("piped stdin");
    let mut stdout = BufReader::new(child.stdout.take().expect("piped stdout"));
    let mut line = String::new();
    stdout
        .read_line(&mut line)
        .expect("read crashme live stdout");
    assert!(
        line.starts_with("ready"),
        "crashd_live_core: live-refused: expected ready, read {line:?}"
    );
    let account = Account::start("live-refused", |ep| {
        let mut requests = 0u64;
        serve_account(ep, move |msg| {
            if msg.label != ipc::memmgr_labels::REQUEST_MEMORY_CAPS
            {
                return Answer::Forward;
            }
            requests = requests.saturating_add(1);
            if requests == 1
            {
                Answer::Forward
            }
            else
            {
                Answer::Refuse
            }
        })
    });

    let charged = own_charge("live-refused");
    // SAFETY: ipc_buf is the registered IPC buffer.
    let reply = unsafe { ipc::ipc_call(crashd, &live_core_request(account.send), ipc_buf) };
    let after = own_charge("live-refused");
    let calls = account.finish("live-refused");
    match reply
    {
        Ok(r) if r.label == ipc::crashd_errors::SNAPSHOT_REFUSED =>
        {}
        Ok(r) => panic!(
            "crashd_live_core: live-refused: LIVE_CORE answered {:#x} (data[0] {:#x}), \
             expected SNAPSHOT_REFUSED",
            r.label,
            r.word(0)
        ),
        Err(e) => panic!("crashd_live_core: live-refused: the LIVE_CORE call failed ({e})"),
    }
    assert!(
        calls.forwarded >= 1 && calls.refused >= 1,
        "crashd_live_core: live-refused: the account forwarded {} call(s) and refused {}: the \
         capture did not take frames before its refusal",
        calls.forwarded,
        calls.refused
    );
    assert!(
        after == charged,
        "crashd_live_core: live-refused: the account holds {after} pages after the refusal, \
         {charged} before the request: the refused snapshot was left charged"
    );

    stdin.write_all(b"check\n").expect("write to crashme live");
    line.clear();
    stdout
        .read_line(&mut line)
        .expect("read crashme live stdout");
    let status = child
        .wait()
        .expect("wait /tests/fixtures/programs/crashme live");
    assert!(
        status.success() && line.contains("live: PASS"),
        "crashd_live_core: live-refused: the fixture did not run on unchanged: {status}, {line:?}"
    );
    let new: Vec<String> = cores().difference(&before).cloned().collect();
    assert!(
        new.is_empty(),
        "crashd_live_core: live-refused: a core was written: {new:?}"
    );
}

/// Start `crashme live-declare` and ask the crash service for a live core of
/// it, charged to an account of this process's own that forwards every call
/// to this process's memmgr account ([`serve_account`]) and, at the first,
/// has the fixture declare itself on the core path and waits for its
/// `declared`. The crash service's check before the snapshot read no
/// declaration, and procmgr took this one on another of its workers while the
/// snapshot was under way, so the check after the capture refuses it. Check
/// that the crash service answered `NO_CORE`, that the account funded the
/// snapshot, that this process's charge after the reply is the charge before
/// the request, that no core was written, and that the fixture exited
/// cleanly.
/// Defect guarded: a snapshot the check after the capture refused, a
/// declaration made during the request, left charged to the requester, the
/// crash service not releasing it.
fn check_live_declared(crashd: u64)
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let before = cores();
    let mut child = Command::new("/tests/fixtures/programs/crashme")
        .arg("live-declare")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn /tests/fixtures/programs/crashme live-declare");
    let mut stdin = child.stdin.take().expect("piped stdin");
    let mut stdout = child.stdout.take().expect("piped stdout");
    let mut buf = [0u8; LINE_BYTES];
    let ready = read_line_raw(&mut stdout, &mut buf) == b"ready";
    assert!(
        ready,
        "crashd_live_core: live-declare: the fixture did not print ready"
    );
    let account = Account::start("live-declare", move |ep| {
        let mut declared = None;
        let calls = serve_account(ep, |_| {
            if declared.is_none()
            {
                let mut buf = [0u8; LINE_BYTES];
                let sent = stdin.write_all(b"declare\n").is_ok();
                declared = Some(sent && read_line_raw(&mut stdout, &mut buf) == b"declared");
            }
            Answer::Forward
        });
        (calls, declared, stdin)
    });

    let charged = own_charge("live-declare");
    // SAFETY: ipc_buf is the registered IPC buffer.
    let reply = unsafe { ipc::ipc_call(crashd, &live_core_request(account.send), ipc_buf) };
    let after = own_charge("live-declare");
    let (calls, declared, mut stdin) = account.finish("live-declare");
    assert!(
        declared == Some(true),
        "crashd_live_core: live-declare: the fixture did not declare during the snapshot \
         ({declared:?})"
    );
    match reply
    {
        Ok(r) if r.label == ipc::crashd_errors::NO_CORE =>
        {}
        Ok(r) => panic!(
            "crashd_live_core: live-declare: LIVE_CORE answered {:#x} (data[0] {:#x}), \
             expected NO_CORE",
            r.label,
            r.word(0)
        ),
        Err(e) => panic!("crashd_live_core: live-declare: the LIVE_CORE call failed ({e})"),
    }
    assert!(
        calls.forwarded >= 1 && calls.refused == 0,
        "crashd_live_core: live-declare: the account forwarded {} call(s) and refused {}: no \
         snapshot was funded",
        calls.forwarded,
        calls.refused
    );
    assert!(
        after == charged,
        "crashd_live_core: live-declare: the account holds {after} pages after the refusal, \
         {charged} before the request: the refused snapshot was left charged"
    );

    stdin
        .write_all(b"exit\n")
        .expect("write to crashme live-declare");
    let status = child
        .wait()
        .expect("wait /tests/fixtures/programs/crashme live-declare");
    assert!(
        status.success(),
        "crashd_live_core: live-declare: the fixture exited {status}"
    );
    let new: Vec<String> = cores().difference(&before).cloned().collect();
    assert!(
        new.is_empty(),
        "crashd_live_core: live-declare: a core was written: {new:?}"
    );
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
