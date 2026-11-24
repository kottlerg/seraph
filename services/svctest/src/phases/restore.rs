// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/restore.rs

//! A restore of a checkpoint by an ordinary creation
//! (`std::os::seraph::process::CommandExt::restore`;
//! `procmgr_labels::CREATE_RESTORE`; docs/checkpoint-restore.md § Quiesce point,
//! § Restore creation, § Restore entry and handle rebinding).
//!
//! The phase spawns a `restore-child` and requires:
//!
//! - its quiesce is refused `ResourceBusy` while it holds the join handle of
//!   a thread that has ended, a `std::fs::ReadDir`, a `VerifiedData`, a
//!   `Checkpoint` (of a grandchild), an `ArgvEnvCap`, a `SessionStdio` or a
//!   `Command` holding a bootstrap cap, and ends `NotCaptured` once it has joined
//!   the thread or dropped the value; a thread it detached does not refuse it
//!   once it has ended;
//! - a checkpoint of it, quiesced with a heap value, a static and its
//!   `HashMap` keys set, on a frame below its committed stack pages, restored twice by `Command::restore`, gives two new
//!   processes whose quiesce returns `Restored` with a notice no later than
//!   now; each holds the captured heap value, static and argv, and through
//!   the new process's caps reads the time as svctest does, finds a file,
//!   logs, joins a thread and parks on a channel; the two take distinct
//!   `HashMap` keys; the original's quiesce returns `Captured`, and all exit 0;
//!   the `Command` of each restore, spawned again, creates a new child of the
//!   binary, not another restore;
//! - a restore request that also carries argv and env (`CREATE_ARGV_ENV`) is
//!   refused `INVALID_ARGUMENT`, a pinned restore `InvalidInput`, a restore
//!   under another binary's name `Unsupported` (`NOT_RESTORABLE`), a restore
//!   of a debug `SNAPSHOT`'s object `Unsupported`, and one given a SEND on an
//!   endpoint of svctest's own as the object `InvalidInput`; none of them
//!   creates a process.

use std::collections::hash_map::RandomState;
use std::hash::BuildHasher;
use std::io::{BufRead, BufReader, Write};
use std::os::seraph::checkpoint::{Checkpoint, Quiesced, RollbackNotice, quiesce};
use std::os::seraph::process::{ArgvEnvCap, ChildExt, CommandExt, SessionStdio};
use std::os::seraph::{
    VerifiedRole, namespace_lookup_file, read_verified, root_dir_cap, startup_info,
};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ipc::{IpcMessage, memmgr_labels, procmgr_errors, procmgr_labels};

use crate::bootstrap::Caps;
use crate::phases::checkpoint::{Quiescer, take_at_point};
use crate::phases::memory_objects::call;
use crate::phases::object_io::Foreign;
use crate::phases::snapshot::{account, snapshot};
use crate::phases::swap::{listed_badges, spawned_badge};
use crate::phases::verified_read::VERIFIED_PATH;
use crate::runner::Phase;

pub fn phases() -> &'static [Phase]
{
    &[Phase {
        name: "procmgr_restore",
        run: restore_phase,
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

const PHASE: &str = "procmgr_restore";

/// argv[1] of the child the phase checkpoints and restores.
const CHILD_ROLE: &str = "restore-child";

/// The binary the child runs, which a restore names.
const BINARY: &str = "/tests/svctest";

/// The heap value the child holds across its point.
const HEAP_VALUE: u64 = 0x5e4a_9417_c0de_0001;

/// The value the child stores in [`STATIC`] before its point.
const STATIC_VALUE: u64 = 0x7e57_0000_0000_0042;

/// A static the child sets before its point, which a restore keeps.
static STATIC: AtomicU64 = AtomicU64::new(0);

/// How long the child retries a quiesce a thread that is ending refuses.
const ENDING_BOUND: Duration = Duration::from_secs(5);

/// The answer the child prints for a quiesce's outcome.
fn outcome(result: &std::io::Result<Quiesced>) -> String
{
    match result
    {
        Ok(Quiesced::Captured) => "captured".to_owned(),
        Ok(Quiesced::NotCaptured) => "not-captured".to_owned(),
        Ok(Quiesced::Restored(_)) => "restored".to_owned(),
        Err(e) => format!("refused {:?}", e.kind()),
    }
}

/// A quiesce point of 20 ms, which no checkpoint is taken at.
fn brief() -> String
{
    outcome(&quiesce(Duration::from_millis(20)))
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
        match line.trim()
        {
            "thread" => joined_thread(),
            "detached" => detached_thread(),
            "readdir" => held(std::fs::read_dir("/tests")),
            "verified" => held(verified()),
            "checkpoint" => held(grandchild_checkpoint()),
            "argv-env" => held(argv_env()),
            "session" => held(
                SessionStdio::new().unwrap_or_else(|e| panic!("{PHASE}: SessionStdio::new: {e}")),
            ),
            "command" => held(command_with_cap()),
            "restore" => restore_point(),
            _ => println!("unknown"),
        }
    }
}

/// Print the outcome of a brief point with `value` held, then of one once it
/// is dropped.
fn held<T>(value: T)
{
    let first = brief();
    drop(value);
    println!("{first} {}", brief());
}

/// A thread that has ended, its handle held and then joined.
fn joined_thread()
{
    let handle = std::thread::spawn(|| ());
    while !handle.is_finished()
    {
        std::thread::sleep(Duration::from_millis(1));
    }
    let first = brief();
    let _ = handle.join();
    println!("{first} {}", brief());
}

/// A thread detached once it has ended. It counts among the live threads
/// until its last step, after its handle reports it finished, so the point
/// is retried while that refuses it.
fn detached_thread()
{
    let handle = std::thread::spawn(|| ());
    while !handle.is_finished()
    {
        std::thread::sleep(Duration::from_millis(1));
    }
    drop(handle);
    let start = Instant::now();
    let mut answer = brief();
    while answer != "not-captured" && start.elapsed() < ENDING_BOUND
    {
        std::thread::sleep(Duration::from_millis(5));
        answer = brief();
    }
    println!("{answer}");
}

/// svctest's verified data fixture, read through procmgr.
fn verified() -> std::os::seraph::VerifiedData
{
    let (cap, size) = namespace_lookup_file(root_dir_cap(), VERIFIED_PATH)
        .unwrap_or_else(|e| panic!("{PHASE}: look up {VERIFIED_PATH}: {e}"));
    read_verified(cap, size, VERIFIED_PATH, VerifiedRole::Data)
        .unwrap_or_else(|e| panic!("{PHASE}: verified read: {e}"))
}

/// A packed argv, held unsent.
fn argv_env() -> ArgvEnvCap
{
    ArgvEnvCap::new(b"restore\0", 1, b"", 0)
        .ok()
        .flatten()
        .unwrap_or_else(|| panic!("{PHASE}: ArgvEnvCap::new"))
}

/// A `Command` holding a bootstrap cap it has not sent, a copy of the
/// process's procmgr SEND, which its drop deletes.
fn command_with_cap() -> Command
{
    let cap = syscall::cap_derive(startup_info().procmgr_endpoint, syscall::RIGHTS_EP_SEND)
        .unwrap_or_else(|e| panic!("{PHASE}: derive a procmgr SEND: {e:?}"));
    let mut command = Command::new(BINARY);
    command.bootstrap_caps(&[cap]);
    command
}

/// A checkpoint of a grandchild, which has exited since.
fn grandchild_checkpoint() -> Checkpoint
{
    let mut grandchild = Quiescer::spawn();
    grandchild.say("forever");
    assert_eq!(grandchild.line("quiescing"), "quiescing");
    let checkpoint = take_at_point(grandchild.child.process_handle());
    assert_eq!(grandchild.line("quiesce outcome"), "captured");
    grandchild.finish();
    checkpoint
}

/// The bytes the point's frame holds, past the committed main stack, so the
/// point lies in the stack's demand growth.
const DEEP_BYTES: usize = (crate::SVCTEST_STACK_PAGES as usize + 4) * 4096;

/// The point the phase checkpoints: the heap value, the static and the
/// `HashMap` keys set, then a point with no time bound, on a frame below the
/// committed stack pages.
#[expect(
    clippy::large_stack_arrays,
    clippy::large_stack_frames,
    reason = "the frame is past the committed stack pages on purpose, so the point lies in the \
              stack's demand growth"
)]
fn restore_point()
{
    let mut deep = [0u8; DEEP_BYTES];
    std::hint::black_box(&mut deep);
    let info = startup_info();
    let committed = info
        .stack_top_vaddr
        .saturating_sub(u64::from(info.stack_pages).saturating_mul(4096));
    assert!(
        (deep.as_ptr() as u64) < committed,
        "{PHASE}: the point's frame lies in the committed stack"
    );
    let heap = Box::new(HEAP_VALUE);
    STATIC.store(STATIC_VALUE, Ordering::Relaxed);
    let _ = RandomState::new();
    println!("quiescing");
    match quiesce(Duration::MAX)
    {
        Ok(Quiesced::Restored(notice)) => restored(*heap, notice),
        other => println!("{}", outcome(&other)),
    }
    std::hint::black_box(&deep);
}

/// The restored process's report, on its own stdout; see the module
/// documentation.
fn restored(heap: u64, notice: RollbackNotice)
{
    std::os::seraph::log!("restore-child: restored");
    println!("restored");
    println!(
        "heap {:x} static {:x}",
        heap,
        STATIC.load(Ordering::Relaxed)
    );
    println!(
        "argv {}",
        std::env::args().skip(1).collect::<Vec<_>>().join(" ")
    );
    println!("notice {}", notice.quiesced_at() <= Instant::now());
    println!("time {}", SystemTime::now() > UNIX_EPOCH);
    println!("fs {}", std::fs::metadata(BINARY).is_ok());
    println!(
        "thread {}",
        std::thread::spawn(|| 7u8).join().ok() == Some(7)
    );
    let (tx, rx) = std::sync::mpsc::channel();
    let sender = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(20));
        let _ = tx.send(5u8);
    });
    let parked = rx.recv() == Ok(5);
    let _ = sender.join();
    println!("park {parked}");
    println!("keys {:x}", RandomState::new().hash_one(0u64));
}

/// The child the phase restores, or a restore of it, with its stdio.
struct Peer
{
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl Peer
{
    fn new(mut child: Child) -> Self
    {
        let stdin = child.stdin.take().expect("the child's stdin is piped");
        let stdout = BufReader::new(child.stdout.take().expect("the child's stdout is piped"));
        Self {
            child,
            stdin,
            stdout,
        }
    }

    /// The child's next line, trimmed.
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
        line.trim().to_owned()
    }

    /// Send `cmd` and return the child's answer.
    fn ask(&mut self, cmd: &str) -> String
    {
        self.stdin
            .write_all(format!("{cmd}\n").as_bytes())
            .and_then(|()| self.stdin.flush())
            .unwrap_or_else(|e| panic!("{PHASE}: writing {cmd:?} to the child failed: {e}"));
        self.line(cmd)
    }

    /// Close the child's stdin and require its exit with status 0.
    fn finish(mut self)
    {
        drop(self.stdin);
        let status = self.child.wait().expect("wait of the child");
        assert!(status.success(), "{PHASE}: the child exited {status:?}");
    }
}

/// A `Command` for a restore of `object` as `binary`.
fn restore_command(binary: &str, object: u64) -> Command
{
    let mut command = Command::new(binary);
    command
        .restore(object)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped());
    command
}

/// The phase; see the module documentation.
fn restore_phase(caps: &Caps)
{
    let authority = caps.debug_authority;
    assert_ne!(authority, 0, "{PHASE}: no debug authority");
    let before = listed_badges(authority);
    let mut child = Peer::new(
        Command::new(BINARY)
            .arg(CHILD_ROLE)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| panic!("{PHASE}: spawning the child failed: {e}")),
    );
    assert_eq!(child.line("ready"), "ready");
    let badge = spawned_badge(authority, &before, PHASE);
    held_refusals(&mut child);

    assert_eq!(child.ask("restore"), "quiescing");
    let checkpoint = take_at_point(child.child.process_handle());
    assert_eq!(child.line("quiesce outcome"), "captured");
    let first = restore(&checkpoint);
    let second = restore(&checkpoint);
    assert_ne!(
        first, second,
        "{PHASE}: two restores of one checkpoint took the same HashMap keys"
    );

    refused_restores(authority, badge, &checkpoint);
    drop(checkpoint);
    child.finish();
    std::os::seraph::log!("procmgr_restore phase passed");
}

/// Each value that holds a capability refuses the child's quiesce until it
/// is dropped.
fn held_refusals(child: &mut Peer)
{
    for what in [
        "thread",
        "readdir",
        "verified",
        "checkpoint",
        "argv-env",
        "session",
        "command",
    ]
    {
        assert_eq!(
            child.ask(what),
            "refused ResourceBusy not-captured",
            "{PHASE}: a quiesce with a {what} held, then dropped"
        );
    }
    assert_eq!(
        child.ask("detached"),
        "not-captured",
        "{PHASE}: a quiesce after a detached thread ended"
    );
}

/// A restore of `checkpoint`, its report checked, and its `HashMap` keys
/// answer.
fn restore(checkpoint: &Checkpoint) -> String
{
    let mut command = restore_command(BINARY, checkpoint.handle());
    let mut restored = Peer::new(
        command
            .spawn()
            .unwrap_or_else(|e| panic!("{PHASE}: the restore failed: {e}")),
    );
    let want = [
        "restored".to_owned(),
        format!("heap {HEAP_VALUE:x} static {STATIC_VALUE:x}"),
        format!("argv {CHILD_ROLE}"),
        "notice true".to_owned(),
        "time true".to_owned(),
        "fs true".to_owned(),
        "thread true".to_owned(),
        "park true".to_owned(),
    ];
    for want in want
    {
        assert_eq!(
            restored.line(&want),
            want,
            "{PHASE}: the restored child's report"
        );
    }
    let keys = restored.line("keys");
    assert!(
        keys.starts_with("keys "),
        "{PHASE}: the restored child printed {keys:?}"
    );
    restored.finish();
    // The restore covered that spawn alone: the same `Command` spawned
    // again creates a child of the binary, a restore-child by its argv.
    let mut fresh = Peer::new(
        command
            .arg(CHILD_ROLE)
            .spawn()
            .unwrap_or_else(|e| panic!("{PHASE}: the spawn after a restore failed: {e}")),
    );
    assert_eq!(
        fresh.line("ready"),
        "ready",
        "{PHASE}: a spawn of the `Command` after its restore"
    );
    fresh.finish();
    keys
}

/// The refused restores; none creates a process.
fn refused_restores(authority: u64, badge: u64, checkpoint: &Checkpoint)
{
    let before = listed_badges(authority);
    assert_eq!(
        argv_restore(checkpoint.handle()),
        procmgr_errors::INVALID_ARGUMENT,
        "{PHASE}: a restore request carrying argv and env"
    );
    let refused = |binary: &str, object: u64, pinned: bool| {
        restore_command(binary, object)
            .pinned(pinned)
            .spawn()
            .map(|_| ())
            .map_err(|e| e.kind())
    };
    assert_eq!(
        refused(BINARY, checkpoint.handle(), true),
        Err(std::io::ErrorKind::InvalidInput),
        "{PHASE}: a pinned restore"
    );
    assert_eq!(
        refused(
            "/tests/fixtures/programs/spawn-target",
            checkpoint.handle(),
            false
        ),
        Err(std::io::ErrorKind::Unsupported),
        "{PHASE}: a restore under another binary's name"
    );
    let reply = snapshot(authority, badge, Some(account()), PHASE);
    assert_eq!(
        reply.label,
        procmgr_errors::SUCCESS,
        "{PHASE}: SNAPSHOT of the child"
    );
    let debug = *reply.caps().first().expect("SNAPSHOT replied no handle");
    assert_eq!(
        refused(BINARY, debug, false),
        Err(std::io::ErrorKind::Unsupported),
        "{PHASE}: a restore of a debug snapshot"
    );
    let _ = call(
        debug,
        &IpcMessage::new(memmgr_labels::OBJECT_RELEASE),
        "OBJECT_RELEASE",
    );
    let _ = syscall::cap_delete(debug);
    let foreign = Foreign::new(PHASE);
    let send = foreign.send();
    assert_eq!(
        refused(BINARY, send, false),
        Err(std::io::ErrorKind::InvalidInput),
        "{PHASE}: a restore given a SEND on svctest's own endpoint as the object"
    );
    let _ = syscall::cap_delete(send);
    drop(foreign);
    assert_eq!(
        listed_badges(authority),
        before,
        "{PHASE}: a refused restore created a process"
    );
}

/// A `CREATE_FROM_FILE` restore of `object` that also flags argv and env
/// (`CREATE_ARGV_ENV`), each tail cap a copy of the object's handle: the
/// reply's label.
fn argv_restore(object: u64) -> u64
{
    let (file, size) = namespace_lookup_file(root_dir_cap(), BINARY)
        .unwrap_or_else(|e| panic!("{PHASE}: look up {BINARY}: {e}"));
    let copy = || syscall::cap_derive(object, syscall::RIGHTS_EP_SEND).expect("a handle copy");
    let label = procmgr_labels::CREATE_FROM_FILE
        | procmgr_labels::CREATE_RESTORE
        | procmgr_labels::CREATE_ARGV_ENV;
    let builder = IpcMessage::builder(label).word(0, size).cap(file);
    let builder = procmgr_labels::with_create_name(builder, label, BINARY.as_bytes())
        .expect("the binary's name fits");
    let msg = builder.cap(copy()).cap(copy()).build();
    call(startup_info().procmgr_endpoint, &msg, "CREATE_FROM_FILE").label
}
