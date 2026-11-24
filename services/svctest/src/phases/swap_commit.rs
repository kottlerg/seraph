// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/swap_commit.rs

//! Commitment backed by swap slots (services/memmgr/docs/memory-pool.md
//! § Commit, Overcommit), after [`super::swapd`], with the swap service's slots
//! registered, so memmgr's overcommit allowance (`QUERY_POOL_STATUS`
//! `data[15]`) is above 0.
//!
//! The admission part runs in every boot. A commitment that takes, with its
//! page-table reservation and metadata bound ([`commit_fitting`]), what the
//! free pool alone admits (the free pages less `promised` and the growth
//! floor) and half the allowance more is admitted; one of the free pages and
//! the allowance less `promised` and the floor, and [`PAST_MARGIN_PAGES`]
//! more, is refused with `OUT_OF_MEMORY_BEST_EFFORT`.
//!
//! The write part runs when crashd holds faults declined for want of memory
//! (its recipe staged with a non-zero `CRASHD_OOM_STALL_MS`): without it a
//! commit overrun kills its process at once. A child ([`WRITER_ROLE`]) commits
//! at most [`WRITE_PAGES`] pages, so few that `promised` stays within the
//! system reserve ([`write_pages`]); svctest then takes the free pool down to
//! the growth floor with grants ([`super::swap::Hog`]). The free frames then
//! cover `promised`, but a committed draw keeps off the growth floor while swap
//! slots are registered, so the reserve stays the reserve nodes' and the
//! restore headroom the uncommitted restores': the commitment lies past the
//! draw room, and the child writes every page of it with an incompressible
//! pattern, [`STEP_PAGES`] at a time. A fault memmgr cannot back at once is
//! declined as a commit overrun (code 11) and held by crashd, and resumed once
//! write-out frees frames above the floor. After each step svctest counts
//! crashd's new lines in logd's history before the child goes on, so none
//! leaves the history uncounted. svctest then returns its grants, and the child
//! reads every page back. The phase requires the child's exit 0 (every page
//! read back as written), crashd's lines since the phase began holding at least
//! one hold for want of commit draw room and one resume on it, and no hold that
//! timed out, no fault crashd did not hold, and no crash report: no process was
//! killed.

use std::io::{BufRead, BufReader, Write};
use std::os::seraph::{reserve_pages, unreserve_pages};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio, exit};
use std::time::{Duration, Instant};

use ipc::{IpcMessage, memmgr_errors, memmgr_labels};
use syscall_abi::PAGE_SIZE;

use crate::bootstrap::Caps;
use crate::phases::heap_commit::commit_fitting;
use crate::runner::Phase;

/// The phase's name, which its failure messages carry.
const PHASE: &str = "memmgr_swap_commit";
/// argv[1] of the child that commits and writes past the draw room; argv[2]
/// is the pages it commits.
const WRITER_ROLE: &str = "swap-commit-writer";

/// The most pages the child commits and writes: 16 MiB, which memmgr backs by
/// writing chunks to the swap slots.
const WRITE_PAGES: u64 = 4096;
/// The fewest pages the child commits: four steps.
const MIN_WRITE_PAGES: u64 = 4 * STEP_PAGES;
/// Pages the child writes between svctest's counts of crashd's lines: four
/// demand chunks, each at most one commit overrun, a hold and a resume, so a
/// step's lines stay within the 16 entries logd keeps of one sender
/// (services/logd/README.md § History buffer).
const STEP_PAGES: u64 = 64;
const _: () = assert!(WRITE_PAGES.is_multiple_of(STEP_PAGES));
/// Pages past what memmgr may still promise the refused commitment asks:
/// more than other processes free between the phase's read and its call.
const PAST_MARGIN_PAGES: u64 = 256;
/// Attempts at the refused commitment: each one memmgr admits means other
/// processes freed more than [`PAST_MARGIN_PAGES`] after the read.
const PAST_ATTEMPTS: u32 = 8;
/// The least allowance the admission part takes as derived from the slots:
/// twice the margin, so half of it clears what the free pool alone admits by
/// more than the margin.
const MIN_ALLOWANCE_PAGES: u64 = 4 * PAST_MARGIN_PAGES;

/// Bytes of svctest's stack the window may use, touched before it.
const STACK_TOUCH_BYTES: usize = 16 * 1024;
/// How long the phase waits for crashd's lines after the child's exit: crashd
/// logs a resume after its reply. A test wait bound.
const LOG_WAIT: Duration = Duration::from_secs(10);
/// How often the phase reads logd's history while it waits.
const LOG_POLL: Duration = Duration::from_millis(50);

/// crashd's line for a hold of a commit overrun.
const HELD_LINE: &[u8] = b"held: no commit draw room";
/// crashd's line for a resume of one.
const RESUMED_LINE: &[u8] = b"commit draw room open";
/// crashd's line for a hold its stall ended.
const TIMED_OUT_LINE: &[u8] = b"hold timed out";
/// crashd's line for a fault declined for want of memory it did not hold.
const NOT_HELD_LINE: &[u8] = b"not held:";
/// crashd's line for a held fault whose hold never received it.
const NOT_DELIVERED_LINE: &[u8] = b"not delivered to its hold";
/// The first line of crashd's report of a crash.
const CRASH_LINE: &[u8] = b"CRASH id=";

/// The child's exit code: memmgr refused its commitment.
const WRITER_COMMIT_REFUSED: i32 = 2;
/// The child's exit code: a line from svctest was not the one expected.
const WRITER_BAD_LINE: i32 = 3;
/// The child's exit code: a page read back other than written.
const WRITER_CORRUPT: i32 = 4;
/// The child's exit code: its range could not be reserved.
const WRITER_RESERVE_FAILED: i32 = 5;
/// The child's exit code: its argv named no page count.
const WRITER_BAD_ARGS: i32 = 6;

pub fn phases() -> &'static [Phase]
{
    &[Phase {
        name: PHASE,
        run: swap_commit_phase,
    }]
}

/// Child-mode dispatch for the argv token this module owns. A match
/// diverges; on a miss control returns to the caller.
pub fn reentry_main(role: &str)
{
    if role == WRITER_ROLE
    {
        writer_main();
    }
}

/// The phase: the admission part, then, with crashd holding, the write part.
fn swap_commit_phase(caps: &Caps)
{
    let (within, past) = admission();
    let Some(stall_ms) = super::oom::crashd_stall(PHASE)
    else
    {
        std::os::seraph::log!(
            "{PHASE} phase passed (a commitment of {within} pages within the allowance \
             admitted, one of {past} past it refused; crashd not holding, no write)"
        );
        return;
    };
    let (pages, lines) = write_past_draw_room(caps.logd_query);
    std::os::seraph::log!(
        "{PHASE} phase passed (a commitment of {within} pages within the allowance admitted, one \
         of {past} past it refused; {pages} pages written past the draw room and read back, \
         crashd holding {} faults and resuming {} within its {stall_ms} ms stall)",
        lines.held,
        lines.resumed
    );
}

// ── Admission ────────────────────────────────────────────────────────────────

/// memmgr's status in pages: the free pages, `promised`, the growth floor
/// and the allowance.
fn status_pages() -> (u64, u64, u64, u64)
{
    let s = super::swap::pool();
    (
        s.free / PAGE_SIZE,
        s.promised / PAGE_SIZE,
        s.floor / PAGE_SIZE,
        s.allowance / PAGE_SIZE,
    )
}

/// A commitment within the allowance admitted and one past it refused; the
/// pages of each.
fn admission() -> (u64, u64)
{
    let (free, promised, floor, allowance) = status_pages();
    assert!(
        allowance >= MIN_ALLOWANCE_PAGES,
        "{PHASE}: an allowance of {allowance} pages with the swap service's slots registered, \
         below {MIN_ALLOWANCE_PAGES}"
    );
    let alone = free.saturating_sub(promised).saturating_sub(floor);
    let within = commit_fitting(alone.saturating_add(allowance / 2));
    let got = commit_once(within);
    assert_eq!(
        got,
        memmgr_errors::SUCCESS,
        "{PHASE}: a commitment of {within} pages refused ({got:#x}): {free} free, {promised} \
         promised, a floor of {floor} and an allowance of {allowance} pages admit up to {} with \
         the page-table reservation and metadata bound ({} on the free pool alone)",
        commit_fitting(
            free.saturating_add(allowance)
                .saturating_sub(promised)
                .saturating_sub(floor)
        ),
        commit_fitting(alone)
    );
    for _ in 0..PAST_ATTEMPTS
    {
        let (free, promised, floor, allowance) = status_pages();
        let past = free
            .saturating_add(allowance)
            .saturating_sub(promised)
            .saturating_sub(floor)
            .saturating_add(PAST_MARGIN_PAGES);
        match commit_once(past)
        {
            memmgr_errors::SUCCESS =>
            {}
            memmgr_errors::OUT_OF_MEMORY_BEST_EFFORT => return (within, past),
            other => panic!(
                "{PHASE}: a commitment of {past} pages past the allowance replied {other:#x}, not \
                 OUT_OF_MEMORY_BEST_EFFORT"
            ),
        }
    }
    panic!("{PHASE}: a commitment past the allowance admitted in each of {PAST_ATTEMPTS} attempts");
}

/// Register a committed region of `pages` pages over a range reserved for
/// it, and unregister it when memmgr admits it; memmgr's reply label.
fn commit_once(pages: u64) -> u64
{
    let range = reserve_pages(pages)
        .unwrap_or_else(|e| panic!("{PHASE}: reserving {pages} pages failed: {e:?}"));
    let (base, len) = (range.va_start(), pages.saturating_mul(PAGE_SIZE));
    let got = register(base, len);
    if got == memmgr_errors::SUCCESS
    {
        let msg = IpcMessage::builder(memmgr_labels::UNREGISTER_REGION)
            .word(0, base)
            .word(1, len)
            .build();
        let freed = super::swap::memmgr_call(&msg, "UNREGISTER_REGION").label;
        assert_eq!(
            freed,
            memmgr_errors::SUCCESS,
            "{PHASE}: UNREGISTER_REGION of the committed region replied {freed:#x}"
        );
    }
    unreserve_pages(range);
    got
}

/// memmgr's reply label to `REGISTER_REGION` with `REGION_COMMIT` of
/// `len` bytes at `base`, writable.
fn register(base: u64, len: u64) -> u64
{
    let msg = IpcMessage::builder(memmgr_labels::REGISTER_REGION)
        .word(0, base)
        .word(1, len)
        .word(2, syscall::MAP_WRITABLE)
        .word(3, memmgr_labels::REGION_COMMIT)
        .build();
    super::swap::memmgr_call(&msg, "REGISTER_REGION with REGION_COMMIT").label
}

// ── The write part, parent side ──────────────────────────────────────────────

/// crashd's lines since the phase began, counted, and the newest history
/// entry counted.
#[derive(Default)]
struct Lines
{
    held: usize,
    resumed: usize,
    timed_out: usize,
    not_held: usize,
    crashes: usize,
    last: u64,
}

impl Lines
{
    /// No lines counted, with the history entries up to sequence number `seq`
    /// taken as counted.
    fn after(seq: u64) -> Self
    {
        Self {
            last: seq,
            ..Self::default()
        }
    }

    /// Count the entries logd's history holds past the newest counted, read
    /// through `query`. It allocates nothing.
    fn read(&mut self, query: u64)
    {
        let mut newest = self.last;
        super::procmgr::logd_history_each(query, None, |e| {
            if e.seq <= self.last
            {
                return false;
            }
            newest = newest.max(e.seq);
            let has = |needle: &[u8]| e.bytes.windows(needle.len()).any(|w| w == needle);
            let count = |n: &mut usize, hit: bool| *n = n.saturating_add(usize::from(hit));
            count(&mut self.held, has(HELD_LINE));
            count(&mut self.resumed, has(RESUMED_LINE));
            count(&mut self.timed_out, has(TIMED_OUT_LINE));
            count(
                &mut self.not_held,
                has(NOT_HELD_LINE) || has(NOT_DELIVERED_LINE),
            );
            count(&mut self.crashes, has(CRASH_LINE));
            true
        });
        self.last = newest;
    }
}

/// The newest sequence number logd's history holds; 0 when it holds none.
fn newest_seq(query: u64) -> u64
{
    super::procmgr::logd_history_with(query, None, |e| e.seq)
        .into_iter()
        .max()
        .unwrap_or(0)
}

/// The child and its pipes.
struct Writer
{
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    line: String,
}

impl Writer
{
    /// Spawn the child to commit `pages` pages and wait for its `ready`, which
    /// it prints with its commitment made.
    fn start(pages: u64) -> Self
    {
        let mut child = Command::new("/tests/svctest")
            .arg(WRITER_ROLE)
            .arg(pages.to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| panic!("{PHASE}: spawning the writer failed: {e:?}"));
        let stdin = child.stdin.take().expect("piped stdin");
        let stdout = BufReader::new(child.stdout.take().expect("piped stdout"));
        let mut writer = Self {
            child,
            stdin,
            stdout,
            line: String::with_capacity(256),
        };
        writer.expect("ready");
        writer
    }

    /// Send the line `cmd`.
    fn send(&mut self, cmd: &[u8])
    {
        self.stdin
            .write_all(cmd)
            .unwrap_or_else(|e| panic!("{PHASE}: write to the writer: {e:?}"));
    }

    /// Read the child's next line during the write: `true` for `written`,
    /// `false` for `step`, the end of a step.
    fn written(&mut self) -> bool
    {
        self.line.clear();
        let _ = self.stdout.read_line(&mut self.line);
        match self.line.trim()
        {
            "written" => true,
            "step" => false,
            _ =>
            {
                let status = self.child.wait().ok();
                panic!(
                    "{PHASE}: the writer printed {:?} during the write and exited {status:?} (a \
                     fault=it was killed)",
                    self.line
                );
            }
        }
    }

    /// Read the child's next line and require it to be `want`.
    fn expect(&mut self, want: &str)
    {
        self.line.clear();
        let _ = self.stdout.read_line(&mut self.line);
        if self.line.trim() != want
        {
            let status = self.child.wait().ok();
            panic!(
                "{PHASE}: the writer printed {:?} for {want:?} and exited {status:?} \
                 ({WRITER_COMMIT_REFUSED}=its commitment refused, {WRITER_RESERVE_FAILED}=its \
                 range not reserved, {WRITER_BAD_ARGS}=no page count in its argv, a fault=it was \
                 killed)",
                self.line
            );
        }
    }
}

/// The pages the child commits: [`WRITE_PAGES`], or fewer, in whole steps, so
/// that `promised` stays within the system reserve, a step's pages left for
/// the page-table reservation the commitment promises too. At the growth
/// floor, which holds the reserve, the free frames then cover `promised`, and
/// the write shows that a committed draw keeps off the floor all the same
/// (services/memmgr/docs/memory-pool.md § Commit, Overcommit).
fn write_pages() -> u64
{
    let s = super::swap::pool();
    let (promised, reserve) = (s.promised / PAGE_SIZE, s.reserve / PAGE_SIZE);
    let pages = reserve
        .saturating_sub(promised)
        .saturating_sub(STEP_PAGES)
        .min(WRITE_PAGES);
    let pages = pages.saturating_sub(pages.checked_rem(STEP_PAGES).unwrap_or(0));
    assert!(
        pages >= MIN_WRITE_PAGES,
        "{PHASE}: a reserve of {reserve} pages with {promised} promised leaves room for a \
         commitment of {pages} pages, below {MIN_WRITE_PAGES}"
    );
    pages
}

/// The write part: the child writes its commitment past the draw room, held
/// by crashd where memmgr cannot back a page at once, and reads it back once
/// svctest's grants are returned. Returns the pages written and crashd's
/// lines.
fn write_past_draw_room(query: u64) -> (u64, Lines)
{
    let mut lines = Lines::after(newest_seq(query));
    let pages = write_pages();
    let mut writer = Writer::start(pages);
    let (_, promised, _, allowance) = status_pages();
    assert!(
        allowance >= promised,
        "{PHASE}: an allowance of {allowance} pages below the {promised} pages promised with the \
         writer's {pages} committed: the grants would leave free frames above the growth floor"
    );
    let mut hog = super::swap::Hog::new();
    touch_stack();
    // From here until the grants are returned the pool stands at the floor:
    // svctest allocates nothing new.
    let filled = hog.fill_to_floor();
    writer.send(b"go\n");
    while !writer.written()
    {
        lines.read(query);
        writer.send(b"next\n");
    }
    lines.read(query);
    hog.release_all();
    writer.send(b"check\n");
    let status = writer
        .child
        .wait()
        .unwrap_or_else(|e| panic!("{PHASE}: waiting for the writer failed: {e:?}"));
    assert!(
        status.success(),
        "{PHASE}: the writer exited {status:?} after its read-back ({WRITER_CORRUPT}=a page read \
         back other than written, {WRITER_BAD_LINE}=a line from svctest was not the one expected)"
    );
    let waited = Instant::now();
    loop
    {
        lines.read(query);
        if (lines.held > 0 && lines.resumed >= lines.held) || waited.elapsed() > LOG_WAIT
        {
            break;
        }
        std::thread::sleep(LOG_POLL);
    }
    assert!(
        lines.held > 0 && lines.resumed > 0,
        "{PHASE}: crashd logged {} holds and {} resumes for want of commit draw room: no write \
         past the draw room was declined and held (the fill left {} pages free against a floor \
         of {})",
        lines.held,
        lines.resumed,
        filled.free / PAGE_SIZE,
        filled.floor / PAGE_SIZE
    );
    assert_eq!(
        (lines.timed_out, lines.not_held, lines.crashes),
        (0, 0, 0),
        "{PHASE}: crashd logged holds that timed out, faults it did not hold, and crash reports \
         while the writer ran"
    );
    (pages, lines)
}

/// Touch [`STACK_TOUCH_BYTES`] of the stack below this frame, so the phase
/// faults no new stack page while the pool stands at the floor.
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

// ── The write part, child side ───────────────────────────────────────────────

/// The pattern's word at word index `index` of the region: a `SplitMix64`
/// output, which no compressor shortens.
const fn pattern(index: u64) -> u64
{
    let mut z = index.wrapping_add(0x9e37_79b9_7f4a_7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// Words of a page.
const PAGE_WORDS: u64 = PAGE_SIZE / 8;

/// Child role: commit the pages its argv's next word names and print `ready`, or
/// exit [`WRITER_BAD_ARGS`] when it names none; on `go`, write
/// every word of them with [`pattern`], [`STEP_PAGES`] at a time, printing
/// `step` after each step but the last and waiting for `next`, and print
/// `written`; on `check`, read
/// every word back and exit 0, or [`WRITER_CORRUPT`] at the first that
/// differs.
fn writer_main() -> !
{
    let Some(pages) = std::env::args().nth(2).and_then(|a| a.parse::<u64>().ok())
    else
    {
        exit(WRITER_BAD_ARGS)
    };
    let Ok(range) = reserve_pages(pages)
    else
    {
        exit(WRITER_RESERVE_FAILED)
    };
    let base = range.va_start();
    if register(base, pages.saturating_mul(PAGE_SIZE)) != memmgr_errors::SUCCESS
    {
        exit(WRITER_COMMIT_REFUSED);
    }
    let words = pages.saturating_mul(PAGE_WORDS);
    let mut line = String::with_capacity(64);
    let stdin = std::io::stdin();
    let mut out = std::io::stdout();
    let mut step = |out: &mut std::io::Stdout, said: &[u8], want: &str| {
        let _ = out.write_all(said);
        let _ = out.flush();
        line.clear();
        let _ = stdin.read_line(&mut line);
        if line.trim() != want
        {
            exit(WRITER_BAD_LINE);
        }
    };
    step(&mut out, b"ready\n", "go");
    let step_words = STEP_PAGES * PAGE_WORDS;
    for i in 0..words
    {
        if i != 0 && i.is_multiple_of(step_words)
        {
            step(&mut out, b"step\n", "next");
        }
        let va = base.saturating_add(i.saturating_mul(8));
        // SAFETY: `va` is 8-aligned inside the range this process reserved
        // and registered with memmgr as a writable committed region, which no
        // Rust object aliases; memmgr backs it on the fault.
        unsafe { core::ptr::write_volatile(va as *mut u64, pattern(i)) };
    }
    step(&mut out, b"written\n", "check");
    for i in 0..words
    {
        let va = base.saturating_add(i.saturating_mul(8));
        // SAFETY: as for the write above; every word of the range was written.
        let got = unsafe { core::ptr::read_volatile(va as *const u64) };
        if got != pattern(i)
        {
            exit(WRITER_CORRUPT);
        }
    }
    exit(0)
}
