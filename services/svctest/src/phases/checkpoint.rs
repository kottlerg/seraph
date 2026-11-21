// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/checkpoint.rs

//! A checkpoint of a process at its quiesce point
//! (`std::os::seraph::checkpoint`; `procmgr_labels::QUIESCE`,
//! `procmgr_labels::CHECKPOINT`; docs/checkpoint-restore.md § Quiesce point,
//! § Checkpoint).
//!
//! The phase spawns a `checkpoint-child` and requires:
//!
//! - a `CHECKPOINT` of the child before it quiesces is refused
//!   `NOT_QUIESCED`, one without an account `INVALID_ARGUMENT`, and one on
//!   svctest's own procmgr cap, which is no process handle, `UNAUTHORIZED`;
//!   a `QUIESCE` on the child's process handle is refused `INVALID_BADGE`;
//! - the child's quiesce with a `std::fs::File` open is refused
//!   `ResourceBusy`, and once the file is closed the fs release handler, the
//!   runtime's own thread, does not refuse it;
//! - a checkpoint of the child quiesced with no time bound
//!   (`Duration::MAX`) is complete, memmgr reports its object marked a
//!   checkpoint (`OBJECT_READ`), its header marks it a checkpoint, and its section holds the child's bootstrap layout: two
//!   argv entries, a page-aligned IPC buffer, a restore stack pointer below
//!   the stack top in a page the object holds bytes of, the `ProcessInfo`
//!   page among the pages it holds, and the image the header names, which
//!   the child shares, so its declarations do not mark it private; the
//!   child's quiesce then returns `Captured`;
//! - a second checkpoint, dropped past svctest's call deadline, is released:
//!   svctest's usage falls by its pages;
//! - a quiesce inside a call deadline that has passed still enters its
//!   point, and ends it with `NotCaptured`;
//! - a `CHECKPOINT` after the point ended, after the point under the passed
//!   deadline, and after a point that timed out with `NotCaptured`, is
//!   refused `NOT_QUIESCED`;
//! - a pinned child's `QUIESCE` is refused `NOT_RESTORABLE`.

use std::io::{BufRead, BufReader, ErrorKind, Write};
use std::os::seraph::checkpoint::{Checkpoint, Quiesced, quiesce, take};
use std::os::seraph::process::{ChildExt, CommandExt};
use std::os::seraph::{startup_info, with_call_deadline};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::{Duration, Instant};

use ipc::procmgr_snapshot::{
    CHECKPOINT_PRIVATE_IMAGE, SNAPSHOT_CHECKPOINT, SNAPSHOT_COMPLETE, SNAPSHOT_IMAGE,
};
use ipc::{IpcMessage, memmgr_labels, procmgr_errors, procmgr_labels};
use syscall_abi::PAGE_SIZE;

use crate::bootstrap::Caps;
use crate::phases::heap_commit::own_usage;
use crate::phases::memory_objects::call;
use crate::phases::object_io::object_flags;
use crate::phases::snapshot::{Attached, account};
use crate::runner::Phase;

pub fn phases() -> &'static [Phase]
{
    &[Phase {
        name: "procmgr_checkpoint",
        run: checkpoint_phase,
    }]
}

/// Child-mode dispatch for the argv tokens this module owns. A match
/// diverges; on a miss control returns to the caller.
pub fn reentry_main(role: &str)
{
    if role == CHILD_ROLE
    {
        child_main();
    }
    if role == PINNED_ROLE
    {
        pinned_main();
    }
}

const PHASE: &str = "procmgr_checkpoint";

/// argv[1] of the child the phase checkpoints.
const CHILD_ROLE: &str = "checkpoint-child";

/// argv[1] of the pinned child whose `QUIESCE` is refused.
const PINNED_ROLE: &str = "checkpoint-pinned";

/// How long the phase retries a `CHECKPOINT` while the child enters its
/// point, and how long the child's point lasts at most.
const POINT_BOUND: Duration = Duration::from_secs(10);

/// The answer the child prints for a quiesce's outcome.
fn outcome(result: std::io::Result<Quiesced>) -> String
{
    match result
    {
        Ok(Quiesced::Captured) => "captured".to_owned(),
        Ok(Quiesced::NotCaptured) => "not-captured".to_owned(),
        Ok(Quiesced::Restored(_)) => "restored".to_owned(),
        Err(e) => format!("refused {:?}", e.kind()),
    }
}

/// The child: answers each command on stdin with one line, and exits at
/// the end of stdin.
fn child_main() -> !
{
    println!("ready");
    let mut line = String::new();
    loop
    {
        line.clear();
        if std::io::stdin().read_line(&mut line).unwrap_or(0) == 0
        {
            std::process::exit(0);
        }
        let mut words = line.split_ascii_whitespace();
        match (
            words.next(),
            words.next().and_then(|w| w.parse::<u64>().ok()),
        )
        {
            (Some("file"), None) =>
            {
                let file = std::fs::File::open("/tests/svctest");
                let result = quiesce(Duration::from_millis(50));
                drop(file);
                println!("{}", outcome(result));
            }
            (Some("quiesce"), Some(ms)) =>
            {
                println!("quiescing");
                println!("{}", outcome(quiesce(Duration::from_millis(ms))));
            }
            (Some("forever"), None) =>
            {
                println!("quiescing");
                println!("{}", outcome(quiesce(Duration::MAX)));
            }
            (Some("deadline"), None) =>
            {
                println!("quiescing");
                let result =
                    with_call_deadline(Instant::now(), || quiesce(Duration::from_millis(100)));
                println!("{}", outcome(result));
            }
            _ =>
            {
                println!("unknown");
            }
        }
    }
}

/// The pinned child: sends `QUIESCE` itself, past the runtime's check, and
/// prints the reply's label.
fn pinned_main() -> !
{
    let notification =
        std::os::seraph::object_slab_retype(std::os::seraph::NOTIFICATION_RETYPE_BYTES, |slab| {
            syscall::cap_create_notification(slab).ok()
        })
        .expect("checkpoint-pinned: notification");
    let marker = 0u8;
    let msg = IpcMessage::builder(procmgr_labels::QUIESCE)
        .word(0, std::ptr::addr_of!(marker) as u64)
        .cap(notification)
        .build();
    let got = call(startup_info().procmgr_endpoint, &msg, "QUIESCE").label;
    println!("label {got}");
    std::process::exit(0);
}

/// The child the phase checkpoints, with its stdio.
pub(super) struct Quiescer
{
    pub(super) child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl Quiescer
{
    pub(super) fn spawn() -> Self
    {
        let mut child = Command::new("/tests/svctest")
            .arg(CHILD_ROLE)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| panic!("{PHASE}: spawning the child failed: {e}"));
        let stdin = child.stdin.take().expect("the child's stdin is piped");
        let stdout = BufReader::new(child.stdout.take().expect("the child's stdout is piped"));
        let mut quiescer = Self {
            child,
            stdin,
            stdout,
        };
        assert_eq!(quiescer.line("ready"), "ready");
        quiescer
    }

    /// The child's next line, trimmed.
    pub(super) fn line(&mut self, what: &str) -> String
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
        line.trim().to_owned()
    }

    /// Send `cmd`.
    pub(super) fn say(&mut self, cmd: &str)
    {
        self.stdin
            .write_all(format!("{cmd}\n").as_bytes())
            .and_then(|()| self.stdin.flush())
            .unwrap_or_else(|e| panic!("{PHASE}: writing {cmd:?} to the child failed: {e}"));
    }

    /// Close the child's stdin and require its exit with status 0.
    pub(super) fn finish(mut self)
    {
        drop(self.stdin);
        let status = self.child.wait().expect("wait of the child");
        assert!(status.success(), "{PHASE}: the child exited {status:?}");
    }
}

/// A raw `CHECKPOINT` on `cap`, carrying `account` as `caps[0]`, and the
/// reply's label; the reply carries no cap on a refusal.
fn raw_checkpoint(cap: u64, account: Option<u64>) -> u64
{
    let b = IpcMessage::builder(procmgr_labels::CHECKPOINT);
    let msg = match account
    {
        Some(account) => b.cap(account).build(),
        None => b.build(),
    };
    call(cap, &msg, "CHECKPOINT").label
}

/// The phase; see the module documentation.
fn checkpoint_phase(_: &Caps)
{
    let mut child = Quiescer::spawn();
    let handle = child.child.process_handle();
    refusals(handle);

    assert_eq!(
        {
            child.say("file");
            child.line("file")
        },
        "refused ResourceBusy",
        "{PHASE}: a quiesce with a file open"
    );

    // A point with no time bound, which waits for the checkpoint.
    child.say("forever");
    assert_eq!(child.line("quiescing"), "quiescing");
    let checkpoint = take_at_point(handle);
    let (object, pages) = checkpoint.into_raw();
    assert_eq!(
        object_flags(object, PHASE),
        (memmgr_labels::OBJECT_CHECKPOINT, pages),
        "{PHASE}: OBJECT_READ of a complete checkpoint's object"
    );
    let object = Attached::attach(object, pages, PHASE);
    check_section(&object);
    object.release();
    assert_eq!(child.line("quiesce outcome"), "captured");
    assert_eq!(
        take(handle).map(|_| ()).map_err(|e| e.kind()),
        Err(ErrorKind::ResourceBusy),
        "{PHASE}: a CHECKPOINT after the point ended"
    );

    // A checkpoint dropped past the caller's call deadline is released.
    child.say("forever");
    assert_eq!(child.line("quiescing"), "quiescing");
    let checkpoint = take_at_point(handle);
    let pages = checkpoint.pages();
    let held = own_usage();
    with_call_deadline(Instant::now(), || drop(checkpoint));
    let released = own_usage();
    assert!(
        released.saturating_add(pages) <= held,
        "{PHASE}: svctest's usage went from {held} to {released} on the drop of a \
         {pages}-page checkpoint past its call deadline"
    );
    assert_eq!(child.line("second outcome"), "captured");

    // A quiesce inside a call deadline that has passed still enters and
    // ends its point.
    child.say("deadline");
    assert_eq!(child.line("quiescing"), "quiescing");
    assert_eq!(child.line("deadline outcome"), "not-captured");
    assert_eq!(
        take(handle).map(|_| ()).map_err(|e| e.kind()),
        Err(ErrorKind::ResourceBusy),
        "{PHASE}: a CHECKPOINT after a point under a passed deadline"
    );

    child.say("quiesce 100");
    assert_eq!(child.line("quiescing"), "quiescing");
    assert_eq!(child.line("timed-out outcome"), "not-captured");
    assert_eq!(
        take(handle).map(|_| ()).map_err(|e| e.kind()),
        Err(ErrorKind::ResourceBusy),
        "{PHASE}: a CHECKPOINT after a point timed out"
    );
    child.finish();

    pinned();
    std::os::seraph::log!("procmgr_checkpoint phase passed");
}

/// A complete checkpoint of the child `handle` names, taken once the child
/// has entered its point.
pub(super) fn take_at_point(handle: u64) -> Checkpoint
{
    let start = Instant::now();
    let checkpoint = loop
    {
        match take(handle)
        {
            Ok(checkpoint) => break checkpoint,
            Err(e) if e.kind() == ErrorKind::ResourceBusy && start.elapsed() < POINT_BOUND =>
            {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(e) => panic!("{PHASE}: CHECKPOINT of the quiesced child failed: {e}"),
        }
    };
    assert!(
        checkpoint.is_complete(),
        "{PHASE}: the checkpoint is incomplete"
    );
    checkpoint
}

/// The refusals before the child quiesces.
fn refusals(handle: u64)
{
    assert_eq!(
        raw_checkpoint(handle, Some(account())),
        procmgr_errors::NOT_QUIESCED,
        "{PHASE}: a CHECKPOINT of a child at no quiesce point"
    );
    assert_eq!(
        raw_checkpoint(handle, None),
        procmgr_errors::INVALID_ARGUMENT,
        "{PHASE}: a CHECKPOINT without an account"
    );
    assert_eq!(
        raw_checkpoint(startup_info().procmgr_endpoint, Some(account())),
        procmgr_errors::UNAUTHORIZED,
        "{PHASE}: a CHECKPOINT on a cap that is no process handle"
    );
    let quiesce = IpcMessage::builder(procmgr_labels::QUIESCE).build();
    assert_eq!(
        call(handle, &quiesce, "QUIESCE").label,
        procmgr_errors::INVALID_BADGE,
        "{PHASE}: a QUIESCE on a process handle"
    );
}

/// The checkpoint's header and section; see the module documentation.
fn check_section(object: &Attached)
{
    let header = object.header();
    let want = SNAPSHOT_COMPLETE | SNAPSHOT_CHECKPOINT | SNAPSHOT_IMAGE;
    assert_eq!(header.flags & want, want, "{PHASE}: header {header:?}");
    let section = object
        .checkpoint()
        .unwrap_or_else(|| panic!("{PHASE}: the layout has no checkpoint section"));
    assert_eq!(section.args_count, 2, "{PHASE}: section {section:?}");
    assert!(
        section.ipc_buffer_va != 0 && section.ipc_buffer_va.is_multiple_of(PAGE_SIZE),
        "{PHASE}: section {section:?}"
    );
    assert!(
        section.restore_sp != 0 && section.restore_sp < section.stack_top,
        "{PHASE}: section {section:?}"
    );
    assert!(
        object.page(section.restore_sp).is_some(),
        "{PHASE}: the object holds no bytes of the restore stack pointer's page"
    );
    assert!(
        object.page(section.process_info_va).is_some(),
        "{PHASE}: the object holds no bytes of the ProcessInfo page"
    );
    assert!(section.image.len != 0, "{PHASE}: section {section:?}");
    assert_eq!(
        section.image, header.image,
        "{PHASE}: the section's image is not the header's"
    );
    assert_eq!(
        section.declarations & CHECKPOINT_PRIVATE_IMAGE,
        0,
        "{PHASE}: a shared image is declared private"
    );
}

/// A pinned child's `QUIESCE` is refused `NOT_RESTORABLE`.
fn pinned()
{
    let mut child = Command::new("/tests/svctest")
        .arg(PINNED_ROLE)
        .pinned(true)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("{PHASE}: spawning the pinned child failed: {e}"));
    let mut stdout = BufReader::new(child.stdout.take().expect("the pinned child's stdout"));
    let mut line = String::new();
    let _ = stdout.read_line(&mut line);
    assert_eq!(
        line.trim(),
        format!("label {}", procmgr_errors::NOT_RESTORABLE),
        "{PHASE}: a pinned child's QUIESCE"
    );
    drop(stdout);
    let status = child.wait().expect("wait of the pinned child");
    assert!(
        status.success(),
        "{PHASE}: the pinned child exited {status:?}"
    );
}
