// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/snapshot.rs

//! procmgr's `SNAPSHOT` of a live process (`procmgr_labels::SNAPSHOT`;
//! services/procmgr/docs/ipc-interface.md § `SNAPSHOT`).
//!
//! The phase spawns a `snapshot-child`, whose writer thread, created raw so
//! it never registers with procmgr, writes a counter to the first word of
//! [`PAGES`] pages in address order, pass after pass. It snapshots the child
//! through svctest's debug authority, charged to svctest's own memmgr SEND,
//! and requires of the object ([`capture`]):
//!
//! - the layout decodes, is complete, and maps every page of the child's
//!   pages to an object page;
//! - the pages are one point in time: each holds at most the value of the
//!   page before it, and the first at most one more than the last, which a
//!   copy made while the writer ran would break;
//! - svctest's usage grows by the object's pages, the child's does not, and
//!   the object's release gives them back;
//! - the child runs on: its writer passes the value the snapshot holds.
//!
//! It then requires the refusals ([`refusals`]): `UNAUTHORIZED` without the
//! debug authority, `INVALID_ARGUMENT` without an account, and
//! `INVALID_BADGE` for the badge of the child once it has exited.

use std::io::{BufRead, BufReader, Write};
use std::os::seraph::{current_ipc_buf, startup_info};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::{Duration, Instant};

use ipc::procmgr_snapshot::{Header, NO_OBJECT_PAGE, RUN_ABSENT, Run, SNAPSHOT_COMPLETE};
use ipc::{IpcMessage, memmgr_errors, memmgr_labels, procmgr_errors, procmgr_labels};
use syscall_abi::{MAP_READ, PAGE_SIZE};

use crate::bootstrap::Caps;
use crate::phases::heap_commit::{expect_region_reply, own_usage};
use crate::phases::memmgr::try_request_contiguous;
use crate::phases::memory_objects::{call, handle_copy};
use crate::phases::swap::listed_badges;
use crate::runner::Phase;

pub fn phases() -> &'static [Phase]
{
    &[Phase {
        name: "procmgr_snapshot",
        run: snapshot_phase,
    }]
}

/// Child-mode dispatch for the argv token this module owns. A match
/// diverges; on a miss control returns to the caller.
pub fn reentry_main(role: &str)
{
    if role == CHILD_ROLE
    {
        child_main();
    }
}

const PHASE: &str = "procmgr_snapshot";

/// argv[1] of the child the phase snapshots.
const CHILD_ROLE: &str = "snapshot-child";

/// Pages the child's writer writes.
const PAGES: usize = 32;

/// Words in a page.
const PAGE_WORDS: usize = 512;
const _: () = assert!(PAGE_WORDS as u64 * 8 == PAGE_SIZE);

/// The last of the writer's pages.
const LAST_PAGE: u64 = PAGES as u64 - 1;

/// Words of the child's buffer: [`PAGES`] pages, and a page to align them.
const BUFFER_WORDS: usize = (PAGES + 1) * PAGE_WORDS;

/// Words of the writer thread's stack.
const STACK_WORDS: usize = 2048;

/// How long the child waits for its writer to reach a value.
const WRITER_BOUND: Duration = Duration::from_secs(10);

/// The address of page `page` from `base`.
const fn page_at(base: u64, page: u64) -> u64
{
    base.wrapping_add(page.wrapping_mul(PAGE_SIZE))
}

/// The first word of the page at `va`.
fn first_word(va: u64) -> u64
{
    // SAFETY: the caller maps or attaches the page at `va` readable; no Rust
    // reference points into it, and a read of an unmapped attached page
    // faults to memmgr, which maps it.
    unsafe { std::ptr::read_volatile(va as *const u64) }
}

// ── The child ────────────────────────────────────────────────────────────────

/// What the writer thread writes: [`PAGES`] pages from `base`.
struct Written
{
    base: u64,
}

/// The writer thread: write the pass count to the first word of each page in
/// address order, pass after pass. It runs no runtime code, so it needs no
/// TLS and no IPC buffer, and it never returns.
extern "C" fn writer_entry(arg: u64) -> !
{
    // SAFETY: `arg` is the address of the `Written` the child leaked for
    // this thread, which lives as long as the process.
    let base = unsafe { (*(arg as *const Written)).base };
    let mut pass: u64 = 1;
    loop
    {
        for page in 0..PAGES as u64
        {
            // SAFETY: the page is one of the child's leaked buffer's, touched
            // before this thread started; only this thread writes it.
            unsafe { std::ptr::write_volatile(page_at(base, page) as *mut u64, pass) };
        }
        pass = pass.wrapping_add(1);
    }
}

/// Start the writer on the [`PAGES`] pages at `base`: a thread created
/// from a grant of its own, outside the runtime, so procmgr's registry never
/// learns of it, with the main thread's fault handlers.
fn start_writer(base: u64)
{
    let fail = |what: &str| -> ! {
        eprintln!("{PHASE}: child: {what}");
        std::process::exit(2)
    };
    let info = startup_info();
    let stack: &'static mut [u64] = Box::leak(vec![0u64; STACK_WORDS].into_boxed_slice());
    for word in stack.iter_mut().step_by(PAGE_WORDS)
    {
        // SAFETY: `word` is a live element of `stack`; the write makes its
        // page present before the writer runs on it.
        unsafe { std::ptr::write_volatile(word, 1) };
    }
    let top = (stack.as_ptr() as u64).wrapping_add((STACK_WORDS as u64).wrapping_mul(8)) & !15;
    let arg = std::ptr::from_ref::<Written>(Box::leak(Box::new(Written { base }))) as u64;

    let bytes = syscall::system_info(syscall_abi::SystemInfoType::ThreadRetypeBytes as u64)
        .unwrap_or_else(|_| fail("ThreadRetypeBytes failed"));
    let pages = u32::try_from(bytes.div_ceil(PAGE_SIZE)).unwrap_or_else(|_| fail("thread size"));
    let (memory, _) =
        try_request_contiguous(pages).unwrap_or_else(|_| fail("the thread's grant failed"));
    let thread = syscall::cap_create_thread(memory, info.self_aspace, info.self_cspace, 0, 0)
        .unwrap_or_else(|_| fail("cap_create_thread failed"));
    let entry = writer_entry as *const () as u64;
    // SAFETY: the thread runs in this process's space; `writer_entry` takes
    // `arg`, a leaked `Written`, and touches nothing but the leaked buffer;
    // `top` is the 16-byte-aligned top of a leaked stack no other code uses.
    unsafe { syscall::thread_configure(thread, entry, top, arg) }
        .unwrap_or_else(|_| fail("thread_configure failed"));
    syscall::thread_inherit_fault_handler(
        thread,
        std::os::seraph::thread::current_thread_cap(),
        syscall_abi::FAULT_CLASS_ALL,
    )
    .unwrap_or_else(|_| fail("thread_inherit_fault_handler failed"));
    loop
    {
        match syscall::thread_start(thread)
        {
            Ok(()) => break,
            Err(e) if e == syscall_abi::SyscallError::Interrupted as i64 =>
            {}
            Err(_) => fail("thread_start failed"),
        }
    }
}

/// Wait, within [`WRITER_BOUND`], for the last page at `base` to hold more
/// than `value`.
fn passes(base: u64, value: u64) -> bool
{
    let start = Instant::now();
    while first_word(page_at(base, LAST_PAGE)) <= value
    {
        if start.elapsed() > WRITER_BOUND
        {
            return false;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    true
}

/// The `snapshot-child` role: start the writer, print `ready <base>` once
/// it has made a pass, and answer the parent's lines until `exit` or the end
/// of stdin: `usage` prints `usage <own pages>`, `past <value>` prints
/// `ok` once the writer passes `value`, or `stuck`.
fn child_main() -> !
{
    let buffer: &'static mut [u64] = Box::leak(vec![0u64; BUFFER_WORDS].into_boxed_slice());
    let base = (buffer.as_ptr() as u64).next_multiple_of(PAGE_SIZE);
    for page in 0..PAGES as u64
    {
        // SAFETY: the page lies in `buffer`, leaked above, which no
        // reference reads; the write makes it present before the writer runs.
        unsafe { std::ptr::write_volatile(page_at(base, page) as *mut u64, 0) };
    }
    start_writer(base);
    if !passes(base, 0)
    {
        println!("stuck");
        std::process::exit(2);
    }
    println!("ready {base:x}");

    let mut line = String::new();
    loop
    {
        line.clear();
        if std::io::stdin().read_line(&mut line).unwrap_or(0) == 0
        {
            std::process::exit(0);
        }
        let mut words = line.split_ascii_whitespace();
        match words.next()
        {
            Some("usage") =>
            {
                let own = crate::phases::budget::memory_usage().map_or(u64::MAX, |u| u.0);
                println!("usage {own}");
            }
            Some("past") =>
            {
                let value = words
                    .next()
                    .and_then(|w| w.parse().ok())
                    .unwrap_or(u64::MAX);
                println!("{}", if passes(base, value) { "ok" } else { "stuck" });
            }
            _ => std::process::exit(0),
        }
    }
}

// ── The parent ───────────────────────────────────────────────────────────────

/// The child and its pipes.
struct Snapped
{
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    /// The child's badge, which `SNAPSHOT` names.
    badge: u64,
    /// The first of the writer's pages in the child's space.
    base: u64,
}

impl Snapped
{
    /// Spawn the child and find its badge.
    fn spawn(authority: u64) -> Self
    {
        let before = listed_badges(authority);
        let mut child = Command::new("/tests/svctest")
            .arg(CHILD_ROLE)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| panic!("{PHASE}: spawning the child failed: {e}"));
        let stdin = child.stdin.take().expect("the child's stdin is piped");
        let stdout = BufReader::new(child.stdout.take().expect("the child's stdout is piped"));
        let mut snapped = Self {
            child,
            stdin,
            stdout,
            badge: 0,
            base: 0,
        };
        let ready = snapped.line("ready");
        snapped.base = ready
            .strip_prefix("ready ")
            .and_then(|w| u64::from_str_radix(w.trim(), 16).ok())
            .unwrap_or_else(|| panic!("{PHASE}: the child printed {ready:?}"));
        let new: Vec<u64> = listed_badges(authority)
            .into_iter()
            .filter(|badge| !before.contains(badge))
            .collect();
        let [badge] = new[..]
        else
        {
            panic!("{PHASE}: LIST_PROCESSES lists {new:#x?} as new since the child's spawn");
        };
        snapped.badge = badge;
        snapped
    }

    /// The child's next line.
    fn line(&mut self, what: &str) -> String
    {
        let mut line = String::new();
        let read = self
            .stdout
            .read_line(&mut line)
            .unwrap_or_else(|e| panic!("{PHASE}: reading the child's {what} line failed: {e}"));
        assert_ne!(
            read, 0,
            "{PHASE}: the child closed its stdout before its {what} line"
        );
        line
    }

    /// Send `cmd` and return the child's answer.
    fn ask(&mut self, cmd: &str) -> String
    {
        self.stdin
            .write_all(format!("{cmd}\n").as_bytes())
            .and_then(|()| self.stdin.flush())
            .unwrap_or_else(|e| panic!("{PHASE}: writing {cmd:?} to the child failed: {e}"));
        self.line(cmd).trim().to_owned()
    }

    /// The child's own usage, in pages.
    fn usage(&mut self) -> u64
    {
        let answer = self.ask("usage");
        answer
            .strip_prefix("usage ")
            .and_then(|w| w.parse().ok())
            .unwrap_or_else(|| panic!("{PHASE}: the child answered usage with {answer:?}"))
    }

    /// Close the child's stdin and require its exit with status 0.
    fn finish(mut self)
    {
        drop(self.stdin);
        let status = self.child.wait().expect("wait of the child");
        assert!(status.success(), "{PHASE}: the child exited {status:?}");
    }
}

/// A `SNAPSHOT` of `badge` over `procmgr`, carrying `account` as `caps[0]`.
pub(super) fn snapshot(procmgr: u64, badge: u64, account: Option<u64>, phase: &str) -> IpcMessage
{
    let b = IpcMessage::builder(procmgr_labels::SNAPSHOT).word(0, badge);
    let msg = match account
    {
        Some(cap) => b.cap(cap).build(),
        None => b.build(),
    };
    // SAFETY: `current_ipc_buf` is this thread's registered IPC buffer page.
    unsafe { ipc::ipc_call(procmgr, &msg, current_ipc_buf()) }
        .unwrap_or_else(|e| panic!("{phase}: SNAPSHOT: ipc_call failed ({e})"))
}

/// A copy of svctest's own memmgr SEND, the account a `SNAPSHOT` carries.
pub(super) fn account() -> u64
{
    let info = startup_info();
    syscall::cap_copy(
        info.memmgr_endpoint,
        info.self_cspace,
        syscall::RIGHTS_EP_SEND,
    )
    .expect("snapshot: copying svctest's memmgr SEND")
}

/// The phase; see the module documentation.
fn snapshot_phase(caps: &Caps)
{
    let authority = caps.debug_authority;
    assert_ne!(authority, 0, "{PHASE}: no debug authority");
    let mut child = Snapped::spawn(authority);
    capture(authority, &mut child);
    let badge = child.badge;
    child.finish();
    refusals(authority, badge);
    std::os::seraph::log!("procmgr_snapshot phase passed");
}

/// Snapshot the child and check the object; see the module documentation.
fn capture(authority: u64, child: &mut Snapped)
{
    let mut values = Vec::with_capacity(PAGES);
    let child_before = child.usage();
    let before = own_usage();
    let reply = snapshot(authority, child.badge, Some(account()), PHASE);
    let after = own_usage();
    assert_eq!(
        reply.label,
        procmgr_errors::SUCCESS,
        "{PHASE}: SNAPSHOT of the child replied {:#x}",
        reply.label
    );
    let handle = *reply.caps().first().expect("SNAPSHOT replied no handle");
    let pages = reply.word(0);
    assert_eq!(
        reply.word(1),
        SNAPSHOT_COMPLETE,
        "{PHASE}: SNAPSHOT of a resident child replied flags {:#x}",
        reply.word(1)
    );
    assert!(
        after >= before.saturating_add(pages),
        "{PHASE}: svctest's usage went from {before} to {after} for a {pages}-page snapshot"
    );
    let child_after = child.usage();
    assert_eq!(
        child_after, child_before,
        "{PHASE}: the child's usage went from {child_before} to {child_after}"
    );

    read_object(handle, pages, child.base, &mut values);
    let released = own_usage();
    assert!(
        released.saturating_add(pages) <= after,
        "{PHASE}: svctest's usage went from {after} to {released} on the release of a \
         {pages}-page snapshot"
    );

    let first = values.first().copied().unwrap_or(0);
    let last = values.last().copied().unwrap_or(0);
    assert!(
        first >= 1,
        "{PHASE}: the snapshot holds no pass of the writer: {values:?}"
    );
    assert!(
        values.windows(2).all(|w| matches!(w, [a, b] if b <= a)) && first.saturating_sub(last) <= 1,
        "{PHASE}: the snapshot's pages are not one point in time: {values:?}"
    );
    let answer = child.ask(&format!("past {first}"));
    assert_eq!(
        answer, "ok",
        "{PHASE}: the child's writer did not pass {first}: {answer:?}"
    );
}

/// The object of a snapshot, attached read-only and private to svctest, its
/// layout decoded.
pub(super) struct Attached
{
    handle: u64,
    va: u64,
    pages: u64,
    range: std::os::seraph::ReservedRange,
    header: Header,
    runs: Vec<Run>,
    /// The caller's phase, which a failure names.
    phase: String,
}

impl Attached
{
    /// Attach the `pages`-page object `handle` names and decode its layout,
    /// requiring the header's pages to lie within the object. `phase` names the
    /// caller in a failure.
    pub(super) fn attach(handle: u64, pages: u64, phase: &str) -> Self
    {
        let range = std::os::seraph::reserve_pages(pages)
            .unwrap_or_else(|_| panic!("{phase}: reserving a range for the snapshot failed"));
        let va = range.va_start();
        let attach = IpcMessage::builder(memmgr_labels::ATTACH_OBJECT)
            .word(0, va)
            .word(1, page_at(0, pages))
            .word(2, MAP_READ)
            .word(3, 0)
            .word(4, memmgr_labels::ATTACH_PRIVATE)
            .cap(handle_copy(handle))
            .build();
        let got = call(startup_info().memmgr_endpoint, &attach, "ATTACH_OBJECT").label;
        assert_eq!(
            got,
            memmgr_errors::SUCCESS,
            "{phase}: ATTACH_OBJECT replied {got:#x}"
        );
        let page_bytes = |at: u64, count: u64| {
            let len = usize::try_from(count.saturating_mul(PAGE_SIZE)).unwrap_or(0);
            // SAFETY: the `count` pages at `at` lie in the object's attachment,
            // read-only and private; the slice is read here only, while attached.
            unsafe { std::slice::from_raw_parts(at as *const u8, len) }
        };
        let header = Header::decode(page_bytes(va, 1))
            .unwrap_or_else(|| panic!("{phase}: the snapshot's header does not decode"));
        assert!(
            header.layout_pages.saturating_add(header.data_pages) <= pages,
            "{phase}: the header {header:?} names more than the object's {pages} pages"
        );
        let layout = page_bytes(va, header.layout_pages);
        let count = usize::try_from(header.run_count).unwrap_or(usize::MAX);
        let runs: Vec<Run> = (0..count)
            .map(|i| {
                Run::decode(layout, i)
                    .unwrap_or_else(|| panic!("{phase}: run {i} of {header:?} does not decode"))
            })
            .collect();
        Self {
            handle,
            va,
            pages,
            range,
            header,
            runs,
            phase: phase.to_owned(),
        }
    }

    /// The object's header.
    pub(super) fn header(&self) -> &Header
    {
        &self.header
    }

    /// The object page holding the target's page at address `at`: `None` when
    /// no run covers it, or its run is absent or places no object page. Panics
    /// when the run places it outside the object's data pages.
    pub(super) fn page(&self, at: u64) -> Option<&[u8]>
    {
        let run = self
            .runs
            .iter()
            .find(|r| at >= r.va && at < page_at(r.va, r.pages))?;
        if run.flags & RUN_ABSENT != 0 || run.object_page == NO_OBJECT_PAGE
        {
            return None;
        }
        let header = &self.header;
        let object_page = run
            .object_page
            .saturating_add(at.saturating_sub(run.va) / PAGE_SIZE);
        assert!(
            object_page >= header.layout_pages
                && object_page < header.layout_pages.saturating_add(header.data_pages),
            "{}: the run {run:?} places {at:#x} at object page {object_page}",
            self.phase
        );
        // SAFETY: the page lies in the object's attachment, read-only and
        // private, which lasts until `release` consumes `self`.
        Some(unsafe {
            std::slice::from_raw_parts(
                page_at(self.va, object_page) as *const u8,
                usize::try_from(PAGE_SIZE).unwrap_or(0),
            )
        })
    }

    /// Detach the object and release it.
    pub(super) fn release(self)
    {
        expect_region_reply(
            memmgr_labels::UNREGISTER_REGION,
            self.va,
            page_at(0, self.pages),
            memmgr_errors::SUCCESS,
            "UNREGISTER_REGION of the snapshot",
        );
        std::os::seraph::unreserve_pages(self.range);
        let got = call(
            self.handle,
            &IpcMessage::new(memmgr_labels::OBJECT_RELEASE),
            "OBJECT_RELEASE",
        )
        .label;
        assert_eq!(
            got,
            memmgr_errors::SUCCESS,
            "{}: OBJECT_RELEASE replied {got:#x}",
            self.phase
        );
    }
}

/// Attach the `pages`-page object `handle` names, read the writer's pages
/// from it to `values`, detach it and release it.
fn read_object(handle: u64, pages: u64, base: u64, values: &mut Vec<u64>)
{
    let object = Attached::attach(handle, pages, PHASE);
    assert_eq!(
        object.header().flags,
        SNAPSHOT_COMPLETE,
        "{PHASE}: the header {:?} of a complete snapshot",
        object.header()
    );
    for page in 0..PAGES as u64
    {
        let at = page_at(base, page);
        let bytes = object
            .page(at)
            .unwrap_or_else(|| panic!("{PHASE}: the snapshot holds no bytes of {at:#x}"));
        let word = bytes
            .first_chunk::<8>()
            .copied()
            .map_or(0, u64::from_ne_bytes);
        values.push(word);
    }
    object.release();
}

/// The refusals: `UNAUTHORIZED` over svctest's procmgr cap, which carries no
/// debug authority; `INVALID_ARGUMENT` without an account; `INVALID_BADGE`
/// for `gone`, the badge of a process that has exited.
fn refusals(authority: u64, gone: u64)
{
    let procmgr = startup_info().procmgr_endpoint;
    for (cap, account, want, what) in [
        (
            procmgr,
            Some(account()),
            procmgr_errors::UNAUTHORIZED,
            "without the debug authority",
        ),
        (
            authority,
            None,
            procmgr_errors::INVALID_ARGUMENT,
            "without an account",
        ),
        (
            authority,
            Some(account()),
            procmgr_errors::INVALID_BADGE,
            "of an exited process",
        ),
    ]
    {
        let reply = snapshot(cap, gone, account, PHASE);
        assert_eq!(
            reply.label, want,
            "{PHASE}: SNAPSHOT {what} replied {:#x}",
            reply.label
        );
        assert!(
            reply.caps().is_empty(),
            "{PHASE}: SNAPSHOT {what} replied caps"
        );
    }
}
