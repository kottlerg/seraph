// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/fs_create_open.rs

//! A create that opens its file in the same request
//! (services/fs/docs/fs-driver-protocol.md § Label 13: `FS_CREATE`, the
//! `CREATE_OPEN` flag): fatfs records the open in the client's session before
//! it writes the directory entry, so an open the client's node refuses leaves
//! no entry.
//!
//! The phase drives the request raw: a create opens the new file in the
//! session its cap names, an existing name is `EXISTS` unless the request
//! asks to open it (`CREATE_OPEN_EXISTING`), and then opens it, a directory
//! of that name is `IS_A_DIRECTORY`, a request with no session cap or with
//! the second flag alone is `INVALID_ARGUMENT`, and in a session whose node is
//! at its max a create, and an open of an existing file, are `LIMIT` and make
//! no entry. Three children drive std's create: a `fs-create-open-full` child
//! ([`full_session_main`]) fills its node to its max and its session with the
//! `/data` driver to its pages, and its `File::create` and `create_new` fail
//! with no entry made; a `fs-create-open-cwd` child ([`cwd_at_max_main`]),
//! whose working directory procmgr installed from the `/data/svctest` cap
//! with its grant right kept, creates a file by a relative path at its max,
//! with no session with the `/data` driver, and the refused session start
//! fails the create with no entry made; and a `fs-create-open-send-only`
//! child ([`send_only_main`]), whose root is a `SEND`-only cap on
//! `/data/svctest`, has its create refused `PermissionDenied` with no entry
//! made, and finds the working directory std's spawn inherited with the grant
//! right svctest's own carries.

use std::os::seraph::{current_ipc_buf, startup_info};

use ipc::{IpcMessage, fs_errors, fs_labels, memmgr_errors, procmgr_errors, procmgr_labels};

use crate::bootstrap::Caps;
use crate::ipc_util::fs::{
    fs_close, fs_mkdir, fs_open_in, fs_read_bytes, fs_remove, fs_session, fs_write_inline,
    svctest_dir_cap,
};
use crate::ipc_util::ns::ns_lookup;
use crate::phases::budget;
use crate::phases::fs_sessions::{
    AT_MAX_NO_LIMIT, AT_MAX_PAGES, ESP_PROBE, NO_MAX, SESSION_MAX, at_max_fill, at_max_touch_stack,
    charge_handle, sub_node,
};
use crate::phases::node_handle::{node_usage, release_refused};
use crate::runner::Phase;

pub fn phases() -> &'static [Phase]
{
    &[Phase {
        name: "fs_create_open",
        run: fs_create_open_phase,
    }]
}

/// Child-mode dispatch for the argv tokens this module owns. A match
/// diverges; on a miss control returns to the caller.
pub fn reentry_main(role: &str)
{
    if role == FULL_ROLE
    {
        full_session_main();
    }
    if role == CWD_ROLE
    {
        cwd_at_max_main();
    }
    if role == SEND_ONLY_ROLE
    {
        send_only_main();
    }
}

/// The file the raw requests create and open.
const NEW: &str = "co-new.bin";
/// The name a create in a session at its max tries.
const LIMITED: &str = "co-limit.bin";
/// The name a create with no session cap tries.
const NO_SESSION: &str = "co-none.bin";
/// The name a create with `CREATE_OPEN_EXISTING` alone tries.
const EXISTING_ALONE: &str = "co-alone.bin";
/// A directory a create that opens an existing file meets.
const DIR: &str = "co-dir";
/// The bytes the phase writes through a new file's open cap.
const PAYLOAD: &[u8] = b"created and opened in one request";
/// Most opens the phase makes in a two-page session before it expects
/// `LIMIT`, far above what two pages of records hold. A test bound.
const OPEN_BOUND: usize = 4096;

/// argv[1] of the child whose session is full at its node's max.
const FULL_ROLE: &str = "fs-create-open-full";
/// The file the [`FULL_ROLE`] child opens to fill its session.
const FULL_PROBE: &str = "co-probe.bin";
/// The file the [`FULL_ROLE`] child creates with `create`.
const FULL_CREATE: &str = "co-full.bin";
/// The file the [`FULL_ROLE`] child creates with `create_new`.
const FULL_CREATE_NEW: &str = "co-full-new.bin";
/// Files the [`FULL_ROLE`] child opens, and drops, before its fill, and the
/// most it holds after: more than one session page's records, so the heap
/// and std's tables have grown for every open the fill makes before the node
/// is at its max.
const FULL_OPENS: usize = 64;
/// argv[1] of the child that creates in its working directory at its max.
const CWD_ROLE: &str = "fs-create-open-cwd";
/// The file the [`CWD_ROLE`] child creates, by a relative path.
const CWD_CREATE: &str = "co-cwd.bin";
/// argv[1] of the child whose root carries no grant right.
const SEND_ONLY_ROLE: &str = "fs-create-open-send-only";
/// The file the [`SEND_ONLY_ROLE`] child creates in its root.
const SEND_ONLY_CREATE: &str = "co-send-only.bin";
/// argv[2] of the [`SEND_ONLY_ROLE`] child when svctest's working directory
/// cap carries the grant right.
const CWD_GRANT: &str = "grant";

/// Child exit code: an open before the fill failed.
const NO_WARMUP: i32 = 10;
/// Child exit code: the session took more than [`FULL_OPENS`] opens at the
/// node's max.
const NO_SESSION_LIMIT: i32 = 11;
/// Child exit code: an open at the max failed with a kind other than
/// `QuotaExceeded`.
const WRONG_FILL_ERROR: i32 = 12;
/// Child exit code: a create that should have been refused succeeded.
const CREATED: i32 = 13;
/// Child exit code: a create was refused with another kind than the one
/// expected.
const WRONG_ERROR: i32 = 14;
/// Child exit code: the working directory cap procmgr installed carries no
/// grant right.
const CWD_NO_GRANT: i32 = 15;
/// Child exit code: the root cap carries the grant right, or there is none.
const ROOT_GRANT: i32 = 16;
/// Child exit code: the inherited working directory cap does not carry the
/// grant right exactly when svctest's does.
const CWD_RIGHTS: i32 = 17;

/// What a child's exit codes mean, for the assertion messages.
const EXIT_CODES: &str = "3=the fill to the max failed, 4=a grant past the max not refused \
                          with LIMIT, 10=an open before the fill failed, 11=the session took \
                          every open at the max, 12=an open at the max refused with another \
                          kind, 13=the create succeeded, 14=the create refused with another \
                          kind, 15=the cwd cap carries no grant right, 16=the root cap carries \
                          the grant right, 17=the inherited cwd cap's grant right differs from \
                          svctest's, a fault reason=the child was killed";

fn fs_create_open_phase(_: &Caps)
{
    let ipc_buf = current_ipc_buf();
    let svctest = svctest_dir_cap(ipc_buf);
    raw_requests(svctest, ipc_buf);
    full_session(svctest, ipc_buf);
    cwd_at_max(svctest, ipc_buf);
    send_only_root(svctest, ipc_buf);
    let _ = syscall::cap_delete(svctest);
    std::os::seraph::log!("fs_create_open phase passed");
}

/// A SEND-only copy of the session cap `session`, for a request to move.
fn session_copy(session: u64) -> u64
{
    syscall::cap_copy(session, startup_info().self_cspace, syscall::RIGHTS_EP_SEND)
        .expect("copying a session cap")
}

/// `FS_CREATE` of `name` in the directory `dir` with the flags `flags`,
/// carrying `caps` (moved to fatfs; deleted here when the kernel did not move
/// them). Returns the reply's open cap and size word, or the wire error code.
fn create_open(
    dir: u64,
    name: &str,
    flags: u64,
    caps: &[u64],
    ipc_buf: *mut u64,
) -> Result<(u64, u64), u64>
{
    let label = fs_labels::FS_CREATE | flags | ((name.len() as u64) << 16);
    let mut builder = IpcMessage::builder(label).bytes(0, name.as_bytes());
    for &cap in caps
    {
        builder = builder.cap(cap);
    }
    // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(dir, &builder.build(), ipc_buf) };
    for &cap in caps
    {
        let _ = syscall::cap_delete(cap);
    }
    let reply = reply.map_err(|_| u64::MAX)?;
    if reply.label != fs_errors::SUCCESS
    {
        assert!(
            reply.caps().is_empty(),
            "a refused create of {name} replied with caps"
        );
        return Err(reply.label);
    }
    match *reply.caps()
    {
        [open] => Ok((open, reply.word(1))),
        _ => panic!("a create of {name} that opens it replied without exactly one cap"),
    }
}

/// The flags of a create that opens a new file only.
const OPEN: u64 = fs_labels::CREATE_OPEN;
/// The flags of a create that opens an existing file of the name too.
const OPEN_EXISTING: u64 = fs_labels::CREATE_OPEN | fs_labels::CREATE_OPEN_EXISTING;

/// `FS_CREATE` with the flags `flags` ([`OPEN`] or [`OPEN_EXISTING`]) of
/// `name` in `dir`, in the session `session` names.
fn create_in(
    dir: u64,
    name: &str,
    flags: u64,
    session: u64,
    ipc_buf: *mut u64,
) -> Result<(u64, u64), u64>
{
    create_open(dir, name, flags, &[session_copy(session)], ipc_buf)
}

/// The size of the file `name` in `dir`, `None` when `dir` holds no such
/// entry.
fn entry_size(dir: u64, name: &str, ipc_buf: *mut u64) -> Option<u64>
{
    let (node, _kind, size) = ns_lookup(dir, name.as_bytes(), 0xFFFF, ipc_buf).ok()?;
    let _ = syscall::cap_delete(node);
    Some(size)
}

/// Remove each of `names` from `dir`, a run that failed having left it.
fn remove_all(dir: u64, names: &[&str], ipc_buf: *mut u64)
{
    for name in names
    {
        let _ = fs_remove(dir, name.as_bytes(), ipc_buf);
    }
}

/// Close `open`, which must name a live open, and delete it.
fn close(open: u64, ipc_buf: *mut u64)
{
    assert_eq!(fs_close(open, ipc_buf), fs_errors::SUCCESS, "FS_CLOSE");
    let _ = syscall::cap_delete(open);
}

/// The raw requests, in a session charged to a two-page node, on
/// `/data/svctest` (`svctest`).
fn raw_requests(svctest: u64, ipc_buf: *mut u64)
{
    let names = [NEW, LIMITED, NO_SESSION, EXISTING_ALONE, DIR];
    remove_all(svctest, &names, ipc_buf);
    let top = sub_node(startup_info().memmgr_endpoint, NO_MAX, "CREATE_SUB_NODE");
    let node = sub_node(top, SESSION_MAX, "NODE_CREATE of the session's node");
    let (session, liveness) =
        fs_session(svctest, charge_handle(node, "NODE_CHARGE_HANDLE"), ipc_buf)
            .expect("FS_SESSION on the /data/svctest directory cap");
    raw_creates(svctest, session, ipc_buf);
    let (file, opens) = raw_creates_at_max(svctest, session, ipc_buf);
    // The session ends at the close of its last open, its liveness cap gone.
    syscall::cap_delete(liveness).expect("deleting the session's liveness cap");
    for open in opens
    {
        close(open, ipc_buf);
    }
    assert_eq!(
        node_usage(node, "NODE_QUERY_USAGE after the session's last close").0,
        0,
        "the session's pages are still charged"
    );
    release_refused(node, "the session's node");
    release_refused(top, "the phase's node");
    for cap in [file, session]
    {
        let _ = syscall::cap_delete(cap);
    }
    fs_remove(svctest, NEW.as_bytes(), ipc_buf).expect("FS_REMOVE of the new file");
}

/// A create that opens a new file, an existing one, and a directory, and
/// the malformed requests, in the session `session` names.
fn raw_creates(svctest: u64, session: u64, ipc_buf: *mut u64)
{
    // A new file, opened in the session.
    let (open, size) = create_in(svctest, NEW, OPEN, session, ipc_buf)
        .unwrap_or_else(|e| panic!("a create that opens {NEW}: {e:#x}"));
    assert_eq!(size, 0, "a new file's size");
    assert_eq!(
        fs_write_inline(open, 0, PAYLOAD, ipc_buf),
        Ok(PAYLOAD.len() as u64),
        "FS_WRITE on a created file's open cap"
    );
    close(open, ipc_buf);
    assert_eq!(
        entry_size(svctest, NEW, ipc_buf),
        Some(PAYLOAD.len() as u64),
        "the created file's entry"
    );

    // An existing name: EXISTS, or opened when the request asks.
    assert_eq!(
        create_in(svctest, NEW, OPEN, session, ipc_buf).err(),
        Some(fs_errors::EXISTS),
        "a create that opens an existing name without CREATE_OPEN_EXISTING"
    );
    let (open, size) = create_in(svctest, NEW, OPEN_EXISTING, session, ipc_buf)
        .unwrap_or_else(|e| panic!("a create that opens the existing {NEW}: {e:#x}"));
    assert_eq!(size, PAYLOAD.len() as u64, "the existing file's size");
    assert_eq!(
        fs_read_bytes(open, 0, PAYLOAD.len() as u64, ipc_buf).as_deref(),
        Ok(PAYLOAD),
        "FS_READ on the existing file's open cap"
    );
    close(open, ipc_buf);
    let (dir, _kind) = fs_mkdir(svctest, DIR.as_bytes(), ipc_buf).expect("FS_MKDIR");
    let _ = syscall::cap_delete(dir);
    assert_eq!(
        create_in(svctest, DIR, OPEN_EXISTING, session, ipc_buf).err(),
        Some(fs_errors::IS_A_DIRECTORY),
        "a create that opens the existing directory {DIR}"
    );
    fs_remove(svctest, DIR.as_bytes(), ipc_buf).expect("FS_REMOVE of the directory");

    // Malformed requests make no entry.
    assert_eq!(
        create_open(svctest, NO_SESSION, fs_labels::CREATE_OPEN, &[], ipc_buf).err(),
        Some(fs_errors::INVALID_ARGUMENT),
        "a create that opens with no session cap"
    );
    assert_eq!(
        entry_size(svctest, NO_SESSION, ipc_buf),
        None,
        "{NO_SESSION} was created"
    );
    assert_eq!(
        create_open(
            svctest,
            EXISTING_ALONE,
            fs_labels::CREATE_OPEN_EXISTING,
            &[session_copy(session)],
            ipc_buf
        )
        .err(),
        Some(fs_errors::INVALID_ARGUMENT),
        "a create with CREATE_OPEN_EXISTING alone"
    );
    assert_eq!(
        entry_size(svctest, EXISTING_ALONE, ipc_buf),
        None,
        "{EXISTING_ALONE} was created"
    );
}

/// Opens of [`NEW`] that fill the session `session` names until its node's
/// max refuses the next page, and a create and an open of an existing file
/// then. Returns the file's node cap and the opens.
fn raw_creates_at_max(svctest: u64, session: u64, ipc_buf: *mut u64) -> (u64, Vec<u64>)
{
    // At the node's max: opens fill the session's two pages until LIMIT, and
    // then a create, and an open of an existing file, are LIMIT too.
    let (file, _kind, _size) =
        ns_lookup(svctest, NEW.as_bytes(), 0xFFFF, ipc_buf).expect("lookup of the new file");
    let mut opens = Vec::new();
    let refused = loop
    {
        assert!(
            opens.len() < OPEN_BOUND,
            "{OPEN_BOUND} opens in a two-page session"
        );
        match fs_open_in(file, session, 0, ipc_buf)
        {
            Ok(open) => opens.push(open),
            Err(e) => break e,
        }
    };
    assert_eq!(refused, fs_errors::LIMIT, "an open past the node's max");
    assert_eq!(
        create_in(svctest, LIMITED, OPEN, session, ipc_buf).err(),
        Some(fs_errors::LIMIT),
        "a create that opens, past the node's max"
    );
    assert_eq!(
        entry_size(svctest, LIMITED, ipc_buf),
        None,
        "a create whose open the node's max refused left {LIMITED} behind"
    );
    assert_eq!(
        create_in(svctest, NEW, OPEN_EXISTING, session, ipc_buf).err(),
        Some(fs_errors::LIMIT),
        "a create that opens an existing file, past the node's max"
    );
    assert_eq!(
        entry_size(svctest, NEW, ipc_buf),
        Some(PAYLOAD.len() as u64),
        "a refused open of the existing file changed it"
    );
    (file, opens)
}

/// Configure the namespace of the created child `handle` (`what`, for the
/// messages) to svctest's root and the working directory `cwd` (moved to
/// procmgr), start it, wait for its exit and destroy it; its exit reason.
fn run_with_cwd(handle: u64, cwd: u64, what: &str) -> u64
{
    let root = syscall::cap_copy(
        std::os::seraph::root_dir_cap(),
        startup_info().self_cspace,
        syscall::RIGHTS_EP_SEND,
    )
    .unwrap_or_else(|e| panic!("copying the root cap for {what} failed ({e})"));
    procmgr_call(
        handle,
        &IpcMessage::builder(procmgr_labels::CONFIGURE_NAMESPACE)
            .cap(root)
            .cap(cwd)
            .build(),
        "CONFIGURE_NAMESPACE",
        what,
    );
    procmgr_call(
        handle,
        &IpcMessage::new(procmgr_labels::START_PROCESS),
        "START_PROCESS",
        what,
    );
    budget::finish(handle, what)
}

/// Call the process handle `handle` of the child `what` with `msg`, the
/// step `step`, and assert procmgr accepts it.
fn procmgr_call(handle: u64, msg: &IpcMessage, step: &str, what: &str)
{
    // SAFETY: the IPC buffer is this thread's registered page.
    let reply = unsafe { ipc::ipc_call(handle, msg, current_ipc_buf()) }
        .unwrap_or_else(|e| panic!("{step} of {what} failed ({e})"));
    assert_eq!(
        reply.label,
        procmgr_errors::SUCCESS,
        "{step} of {what} refused"
    );
}

/// A `fs-create-open-full` child ([`full_session_main`]) fills its node and
/// its session with the `/data` driver; its creates fail, and no entry is
/// made.
fn full_session(svctest: u64, ipc_buf: *mut u64)
{
    let what = "the fs-create-open-full child";
    remove_all(svctest, &[FULL_CREATE, FULL_CREATE_NEW], ipc_buf);
    std::fs::write(format!("/data/svctest/{FULL_PROBE}"), PAYLOAD)
        .expect("fs_create_open: write the probe file");
    let (process, thread) = budget::create_with_max(FULL_ROLE, AT_MAX_PAGES, what);
    let reason = budget::run_to_exit(process, what);
    let _ = syscall::cap_delete(thread);
    let _ = syscall::cap_delete(process);
    let left = [FULL_CREATE, FULL_CREATE_NEW].map(|name| entry_size(svctest, name, ipc_buf));
    remove_all(
        svctest,
        &[FULL_CREATE, FULL_CREATE_NEW, FULL_PROBE],
        ipc_buf,
    );
    assert_eq!(reason, 0, "{what} exit reason {reason:#x}: {EXIT_CODES}");
    assert_eq!(
        left,
        [None, None],
        "a create whose open the node's max refused left its entry behind"
    );
}

/// Child role: open `/data/svctest/` [`FULL_PROBE`] [`FULL_OPENS`] times
/// and drop them, which starts std's session with the `/data` driver; touch
/// the stack; fill this process's node to its max; hold opens of the probe
/// until the session's next page is refused; and create [`FULL_CREATE`] with
/// `create` and [`FULL_CREATE_NEW`] with `create_new`, whose opens need that
/// page. Exit 0 when both fail with `QuotaExceeded`; else exit with the
/// step's code.
fn full_session_main() -> !
{
    use std::io::ErrorKind;
    use std::process::exit;

    let probe = format!("/data/svctest/{FULL_PROBE}");
    let mut files = Vec::with_capacity(FULL_OPENS);
    for _ in 0..FULL_OPENS
    {
        match std::fs::File::open(&probe)
        {
            Ok(file) => files.push(file),
            Err(_) => exit(NO_WARMUP),
        }
    }
    files.clear();
    at_max_touch_stack();
    at_max_fill();
    match crate::phases::memmgr::try_request_contiguous(1)
    {
        Err(label) if label == memmgr_errors::LIMIT =>
        {}
        _ => exit(AT_MAX_NO_LIMIT),
    }
    loop
    {
        if files.len() == FULL_OPENS
        {
            exit(NO_SESSION_LIMIT);
        }
        match std::fs::File::open(&probe)
        {
            Ok(file) => files.push(file),
            Err(e) if e.kind() == ErrorKind::QuotaExceeded => break,
            Err(_) => exit(WRONG_FILL_ERROR),
        }
    }
    for (name, create_new) in [(FULL_CREATE, false), (FULL_CREATE_NEW, true)]
    {
        match std::fs::OpenOptions::new()
            .write(true)
            .create(!create_new)
            .create_new(create_new)
            .open(format!("/data/svctest/{name}"))
        {
            Ok(_) => exit(CREATED),
            Err(e) if e.kind() == ErrorKind::QuotaExceeded =>
            {}
            Err(_) => exit(WRONG_ERROR),
        }
    }
    exit(0);
}

/// A `fs-create-open-cwd` child ([`cwd_at_max_main`]), whose working
/// directory is `/data/svctest` as a `SEND_GRANT` lookup minted it, creates a
/// file in it at its max; the create fails, and no entry is made.
fn cwd_at_max(svctest: u64, ipc_buf: *mut u64)
{
    let what = "the fs-create-open-cwd child";
    remove_all(svctest, &[CWD_CREATE], ipc_buf);
    let (process, thread) = budget::create_with_max(CWD_ROLE, AT_MAX_PAGES, what);
    let reason = run_with_cwd(process, svctest_dir_cap(ipc_buf), what);
    let _ = syscall::cap_delete(thread);
    let _ = syscall::cap_delete(process);
    let left = entry_size(svctest, CWD_CREATE, ipc_buf);
    remove_all(svctest, &[CWD_CREATE], ipc_buf);
    assert_eq!(reason, 0, "{what} exit reason {reason:#x}: {EXIT_CODES}");
    assert_eq!(
        left, None,
        "a create in the cwd whose session start the node's max refused left {CWD_CREATE} behind"
    );
}

/// Whether `cap` carries the endpoint grant right.
fn carries_grant(cap: u64) -> bool
{
    syscall::cap_info(cap, syscall::CAP_INFO_TAG_RIGHTS)
        .is_ok_and(|v| v & syscall::RIGHTS_EP_GRANT != 0)
}

/// Child role: check that the working directory cap carries the grant right
/// procmgr kept, open [`ESP_PROBE`] with std, which starts std's release
/// handler and a session with the `/esp` driver but none with `/data`'s,
/// touch the stack, fill this process's node to its max, and create
/// [`CWD_CREATE`] by a relative path: the session start the create takes
/// first is refused. Exit 0 when the create fails with `QuotaExceeded` or
/// `OutOfMemory`; else exit with the step's code.
fn cwd_at_max_main() -> !
{
    use std::io::ErrorKind;
    use std::process::exit;

    if !carries_grant(std::os::seraph::current_dir_cap())
    {
        exit(CWD_NO_GRANT);
    }
    match std::fs::File::open(ESP_PROBE)
    {
        Ok(file) => drop(file),
        Err(_) => exit(NO_WARMUP),
    }
    at_max_touch_stack();
    at_max_fill();
    match crate::phases::memmgr::try_request_contiguous(1)
    {
        Err(label) if label == memmgr_errors::LIMIT =>
        {}
        _ => exit(AT_MAX_NO_LIMIT),
    }
    match std::fs::File::create(CWD_CREATE)
    {
        Ok(_) => exit(CREATED),
        Err(e) if matches!(e.kind(), ErrorKind::QuotaExceeded | ErrorKind::OutOfMemory) => exit(0),
        Err(_) => exit(WRONG_ERROR),
    }
}

/// A `fs-create-open-send-only` child ([`send_only_main`]), spawned by std
/// with a `SEND`-only cap on `/data/svctest` as its root, has its create in
/// the root refused, and no entry is made.
fn send_only_root(svctest: u64, ipc_buf: *mut u64)
{
    remove_all(svctest, &[SEND_ONLY_CREATE], ipc_buf);
    let root = syscall::cap_derive(svctest, syscall::RIGHTS_EP_SEND)
        .expect("a SEND-only copy of the /data/svctest cap");
    let cwd_grant = if carries_grant(std::os::seraph::current_dir_cap())
    {
        CWD_GRANT
    }
    else
    {
        "no-grant"
    };
    let mut cmd = std::process::Command::new("/tests/svctest");
    cmd.arg(SEND_ONLY_ROLE).arg(cwd_grant);
    std::os::seraph::process::CommandExt::namespace_cap(&mut cmd, root);
    let status = cmd
        .status()
        .expect("fs_create_open: spawn the fs-create-open-send-only child");
    let left = entry_size(svctest, SEND_ONLY_CREATE, ipc_buf);
    remove_all(svctest, &[SEND_ONLY_CREATE], ipc_buf);
    assert!(
        status.success(),
        "the fs-create-open-send-only child exit status {status:?}: {EXIT_CODES}"
    );
    assert_eq!(
        left, None,
        "a create through a root cap with no grant right left {SEND_ONLY_CREATE} behind"
    );
}

/// Child role: check that the root cap carries no grant right and that the
/// working directory std's spawn inherited carries it exactly when svctest's
/// does (argv[2]), then create `/` [`SEND_ONLY_CREATE`]. Exit 0 when the
/// create fails with `PermissionDenied`; else exit with the step's code.
fn send_only_main() -> !
{
    use std::io::ErrorKind;
    use std::process::exit;

    let root = std::os::seraph::root_dir_cap();
    if root == 0 || carries_grant(root)
    {
        exit(ROOT_GRANT);
    }
    let parent_grant = std::env::args().nth(2).as_deref() == Some(CWD_GRANT);
    if carries_grant(std::os::seraph::current_dir_cap()) != parent_grant
    {
        exit(CWD_RIGHTS);
    }
    match std::fs::File::create(format!("/{SEND_ONLY_CREATE}"))
    {
        Ok(_) => exit(CREATED),
        Err(e) if e.kind() == ErrorKind::PermissionDenied => exit(0),
        Err(_) => exit(WRONG_ERROR),
    }
}
