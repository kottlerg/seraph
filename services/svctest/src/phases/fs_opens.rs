// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/fs_opens.rs

//! fatfs's per-open state (services/fs/docs/fs-driver-protocol.md § Label 18:
//! `FS_OPEN`): two opens of one file are told apart. One open's `FS_CLOSE`
//! releases only its own pages, a closed open's cap names no open, eviction
//! sends each page's cooperative release to the release endpoint of the open
//! that read it, and an open in a session whose client holds no copy of its
//! liveness cap any more, because the client died or deleted it, is released.

use std::os::seraph::{current_ipc_buf, startup_info};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use crate::bootstrap::Caps;
use crate::ipc_util::fs::{
    fs_close, fs_create, fs_open, fs_open_in, fs_read_bytes, fs_read_memory, fs_release_memory,
    fs_remove, fs_session, svctest_dir_cap,
};
use crate::ipc_util::ns::{ns_lookup, ns_stat};
use crate::phases::fs_sessions::{charge_handle, sub_node};
use crate::phases::node_handle::release_refused;
use crate::runner::Phase;

pub fn phases() -> &'static [Phase]
{
    &[
        Phase {
            name: "fs_reclaims_dead_opens",
            run: fs_reclaims_dead_opens_phase,
        },
        Phase {
            name: "fs_close_isolates_opens",
            run: fs_close_isolates_opens_phase,
        },
        Phase {
            name: "fs_eviction_routes_release_to_its_open",
            run: fs_eviction_routes_release_to_its_open_phase,
        },
    ]
}

const PAGE: usize = 4096;

/// Write a file of `pages` pages at `/data/svctest/<name>` through `std::fs`
/// and return the `/data/svctest` directory cap and the file's node cap.
fn scratch_file(name: &str, pages: usize, ipc_buf: *mut u64) -> (u64, u64)
{
    use std::io::Write;

    let path = format!("/data/svctest/{name}");
    let mut f = std::fs::File::create(&path).expect("fs_opens: create the scratch file");
    let page = vec![0x5Au8; PAGE];
    for _ in 0..pages
    {
        f.write_all(&page).expect("fs_opens: write a page");
    }
    drop(f);
    let svctest = svctest_dir_cap(ipc_buf);
    let (node, _kind, _size) =
        ns_lookup(svctest, name.as_bytes(), 0xFFFF, ipc_buf).expect("fs_opens: lookup");
    (svctest, node)
}

/// Whether `cap` still names a capability in this `CSpace`: a page cap the
/// driver revoked does not.
fn cap_live(cap: u64) -> bool
{
    syscall::cap_info(cap, syscall::CAP_INFO_TAG_RIGHTS).is_ok()
}

/// Two opens of one file each hold a page; one closes. Its page cap is
/// revoked and the other's is not, and the other can still release its own
/// page. The closed open's cap then names no open, even once a new open
/// reuses its table index. A node cap refuses the labels of an open, and an
/// open cap refuses `NS_*` and `FS_OPEN`.
pub fn fs_close_isolates_opens_phase(_: &Caps)
{
    const COOKIE_A: u64 = 0xA1;
    const COOKIE_B: u64 = 0xB1;

    let ipc_buf = std::os::seraph::current_ipc_buf();
    let name = "opens.bin";
    let (svctest, node) = scratch_file(name, 2, ipc_buf);

    let a = fs_open(node, 0, ipc_buf).expect("fs_close_isolates_opens: FS_OPEN a");
    let b = fs_open(node, 0, ipc_buf).expect("fs_close_isolates_opens: FS_OPEN b");
    let (page_a, _) = fs_read_memory(a, 0, COOKIE_A, ipc_buf).expect("FS_READ_MEMORY on a");
    let (page_b, _) =
        fs_read_memory(b, PAGE as u64, COOKIE_B, ipc_buf).expect("FS_READ_MEMORY on b");
    assert!(cap_live(page_a) && cap_live(page_b), "both pages held");

    assert_eq!(fs_close(a, ipc_buf), ipc::fs_errors::SUCCESS, "FS_CLOSE a");
    assert!(!cap_live(page_a), "a's FS_CLOSE left a's page cap live");
    assert!(cap_live(page_b), "a's FS_CLOSE revoked b's page");
    assert_eq!(
        fs_release_memory(b, COOKIE_B, ipc_buf),
        ipc::fs_errors::SUCCESS,
        "b releases its own page after a's close"
    );
    assert!(!cap_live(page_b), "b's release left its page cap live");

    // a's cap is stale: its open is gone, and the next open takes its index
    // under a new generation.
    assert_eq!(
        fs_read_memory(a, 0, 2, ipc_buf).err(),
        Some(ipc::fs_errors::INVALID_BADGE),
        "FS_READ_MEMORY on a closed open"
    );
    let c = fs_open(node, 0, ipc_buf).expect("fs_close_isolates_opens: FS_OPEN c");
    assert_eq!(
        fs_close(a, ipc_buf),
        ipc::fs_errors::INVALID_BADGE,
        "FS_CLOSE on a closed open whose index a new open reuses"
    );
    let (page_c, _) = fs_read_memory(c, 0, 3, ipc_buf).expect("FS_READ_MEMORY on c");
    assert!(cap_live(page_c), "a's stale close reached c");
    assert_eq!(fs_release_memory(c, 3, ipc_buf), ipc::fs_errors::SUCCESS);

    // The kind of cap decides which labels it takes.
    assert_eq!(
        fs_read_memory(node, 0, 4, ipc_buf).err(),
        Some(ipc::fs_errors::INVALID_BADGE),
        "FS_READ_MEMORY on a node cap"
    );
    assert_eq!(
        fs_close(node, ipc_buf),
        ipc::fs_errors::INVALID_BADGE,
        "FS_CLOSE on a node cap"
    );
    assert_eq!(
        fs_open(b, 0, ipc_buf).err(),
        Some(ipc::fs_errors::INVALID_BADGE),
        "FS_OPEN on an open cap"
    );
    assert_eq!(
        ns_stat(b, ipc_buf).err(),
        Some(namespace_protocol::NsError::NotSupported.as_label()),
        "NS_STAT on an open cap"
    );
    // The cap kind is checked before the rights: a wrong-kind request whose
    // badge also lacks the label's right is still INVALID_BADGE.
    let (stat_only, _kind, _size) = ns_lookup(
        svctest,
        name.as_bytes(),
        u64::from(namespace_protocol::rights::STAT),
        ipc_buf,
    )
    .expect("fs_close_isolates_opens: STAT-only lookup");
    assert_eq!(
        fs_read_memory(stat_only, 0, 5, ipc_buf).err(),
        Some(ipc::fs_errors::INVALID_BADGE),
        "FS_READ_MEMORY on a node cap without READ"
    );
    let _ = syscall::cap_delete(stat_only);
    assert_eq!(
        fs_create(b, b"x.bin", ipc_buf).err(),
        Some(ipc::fs_errors::INVALID_BADGE),
        "FS_CREATE on an open cap, which carries no MUTATE_DIR"
    );

    for cap in [page_a, page_b, page_c]
    {
        let _ = syscall::cap_delete(cap);
    }
    for open in [b, c]
    {
        assert_eq!(fs_close(open, ipc_buf), ipc::fs_errors::SUCCESS);
    }
    for cap in [a, b, c, node]
    {
        let _ = syscall::cap_delete(cap);
    }
    fs_remove(svctest, name.as_bytes(), ipc_buf).expect("cleanup opens.bin");
    let _ = syscall::cap_delete(svctest);
    std::os::seraph::log!("fs_close_isolates_opens phase passed");
}

/// Label of the message that stops a release handler thread.
const STOP_LABEL: u64 = 0x5709;

/// One open of the eviction phase: its open cap, the tag in the high byte
/// of every cookie it reads with, its release endpoint, and the page caps
/// it holds.
struct Opener
{
    open: u64,
    tag: u64,
    endpoint: u64,
    stop: u64,
    pages: Vec<u64>,
    /// The file page indices `pages` holds, in the same order.
    held: Vec<usize>,
}

/// The releases a handler thread received: the tag of the endpoint each
/// arrived on, and its cookie.
type ReleaseLog = Arc<Mutex<Vec<(u64, u64)>>>;

impl Opener
{
    /// A release endpoint with a handler thread that logs each
    /// `FS_RELEASE_MEMORY` under `tag` and acks it, and an `FS_OPEN` of
    /// `node` carrying a SEND on it.
    fn new(node: u64, tag: u64, log: &ReleaseLog, ipc_buf: *mut u64) -> Self
    {
        let endpoint =
            std::os::seraph::create_endpoint().expect("fs_eviction: endpoint creation failed");
        let send = syscall::cap_derive(endpoint, syscall::RIGHTS_EP_SEND).expect("release SEND");
        let stop = syscall::cap_derive(endpoint, syscall::RIGHTS_EP_SEND).expect("stop SEND");
        let log = log.clone();
        std::thread::Builder::new()
            .name("fs_eviction_release".into())
            .spawn(move || serve_releases(endpoint, tag, &log))
            .expect("fs_eviction: handler spawn failed");
        let open = fs_open(node, send, ipc_buf).expect("fs_eviction: FS_OPEN");
        Self {
            open,
            tag,
            endpoint,
            stop,
            pages: Vec::new(),
            held: Vec::new(),
        }
    }

    /// Read and hold page `index`; `false` when fatfs answers `IO_ERROR`,
    /// every cache slot being held.
    fn hold(&mut self, index: usize, ipc_buf: *mut u64) -> bool
    {
        let cookie = self.tag | index as u64;
        let offset = index
            .checked_mul(PAGE)
            .expect("fs_eviction: page offset overflowed");
        match fs_read_memory(self.open, offset as u64, cookie, ipc_buf)
        {
            Ok((page, _)) =>
            {
                self.pages.push(page);
                self.held.push(index);
                true
            }
            Err(ipc::fs_errors::IO_ERROR) => false,
            Err(e) => panic!("fs_eviction: FS_READ_MEMORY {index} status {e}"),
        }
    }

    /// Close the open, stop the handler, and drop every cap.
    fn finish(self, ipc_buf: *mut u64)
    {
        let _ = fs_close(self.open, ipc_buf);
        // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
        let _ = unsafe { ipc::ipc_call(self.stop, &ipc::IpcMessage::new(STOP_LABEL), ipc_buf) };
        for cap in self.pages
        {
            let _ = syscall::cap_delete(cap);
        }
        for cap in [self.open, self.stop, self.endpoint]
        {
            let _ = syscall::cap_delete(cap);
        }
    }
}

/// Receive on `endpoint` until a [`STOP_LABEL`] message, logging each
/// `FS_RELEASE_MEMORY` cookie under `tag` and acking it.
fn serve_releases(endpoint: u64, tag: u64, log: &ReleaseLog)
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    loop
    {
        // SAFETY: ipc_buf is this thread's registered IPC buffer page.
        let msg = unsafe { ipc::ipc_recv(endpoint, ipc_buf) }.expect("fs_eviction: ipc_recv");
        let stop = msg.label == STOP_LABEL;
        if msg.label == ipc::fs_labels::FS_RELEASE_MEMORY
        {
            log.lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push((tag, msg.word(0)));
        }
        let reply = ipc::IpcMessage::new(ipc::fs_labels::FS_RELEASE_ACK);
        // SAFETY: ipc_buf is this thread's registered IPC buffer page.
        let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
        if stop
        {
            return;
        }
    }
}

/// Wait up to five seconds for the release log to hold `count` entries.
fn wait_for_releases(log: &ReleaseLog, count: usize) -> Vec<(u64, u64)>
{
    let start = Instant::now();
    loop
    {
        let got = log.lock().unwrap_or_else(PoisonError::into_inner).clone();
        if got.len() >= count
        {
            return got;
        }
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "fs_eviction: {} of {count} cooperative releases arrived",
            got.len()
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// Opens of other files that each hold a release SEND in fatfs's `CSpace`,
/// kept across the
/// eviction phase's cache fill: more than the init funding's headroom beyond
/// a full cache's own caps (the quarantine's 32 and 64 more), so the fill
/// reaches the slots fatfs's `FS_OPEN` top-up keeps free.
const HELD_FILES: usize = 200;

/// Two opens of one file, each with its own release endpoint, read and hold
/// pages until every cache slot is held, so fatfs queues a held page for
/// eviction. Its cooperative `FS_RELEASE_MEMORY` must arrive on the release
/// endpoint of the open that read the page, naming that open's cookie. The
/// open it reached then closes, freeing its slots without touching the
/// other's pages, and the other reads until the cache is full again: the
/// next eviction must reach the other open's endpoint. fatfs once kept one
/// release SEND per node, the first a read of the node carried, and sent
/// every client's releases there.
///
/// The phase runs while fatfs's cache is still cold, and holds
/// [`HELD_FILES`] `std::fs::File`s open across the fill: each `FS_OPEN` left
/// a release SEND in fatfs's `CSpace`, so the fill's slot pages and per-read
/// caps need the slots `FS_OPEN`'s top-up keeps free for every slot not yet
/// provisioned. fatfs once kept only the per-read caps' worth free, and the
/// fill exhausted its `CSpace` before the cache filled.
pub fn fs_eviction_routes_release_to_its_open_phase(_: &Caps)
{
    const TAG_X: u64 = 0x58 << 56;
    const TAG_Y: u64 = 0x59 << 56;
    const TAG_MASK: u64 = 0xFF << 56;

    let ipc_buf = std::os::seraph::current_ipc_buf();
    // svctest holds an open cap per held File and a page cap per held page.
    assert!(
        std::os::seraph::fund_cspace_slot_budget(
            startup_info().self_cspace,
            HELD_FILES
                .checked_add(crate::phases::fs_ipc::fatfs_slot_ceiling(ipc_buf))
                .and_then(|n| n.checked_add(64))
                .expect("fs_eviction: CSpace slot budget overflowed") as u64,
        ),
        "fs_eviction: funding svctest's CSpace failed"
    );
    let held_files: Vec<std::fs::File> = (0..HELD_FILES)
        .map(|i| {
            std::fs::File::open("/data/svctest/bench.bin")
                .unwrap_or_else(|e| panic!("fs_eviction: holding open File {i}: {e}"))
        })
        .collect();
    // The slot-reuse phase's file, more pages than the cache has slots,
    // written here while the cache is cold; that phase reads it next and
    // removes it.
    let file_pages = crate::phases::fs_ipc::slot_reuse_file(ipc_buf);
    let name = crate::phases::fs_ipc::SLOT_REUSE_NAME;
    let svctest = svctest_dir_cap(ipc_buf);
    let (node, _kind, _size) =
        ns_lookup(svctest, name, 0xFFFF, ipc_buf).expect("fs_eviction: lookup");

    let log: ReleaseLog = Arc::new(Mutex::new(Vec::new()));
    let mut x = Opener::new(node, TAG_X, &log, ipc_buf);
    let mut y = Opener::new(node, TAG_Y, &log, ipc_buf);

    // y holds page 0; x holds pages from 1 on until the cache is full.
    assert!(y.hold(0, ipc_buf), "fs_eviction: y's first page");
    let mut next = 1;
    while next < file_pages && x.hold(next, ipc_buf)
    {
        next = next
            .checked_add(1)
            .expect("fs_eviction: page counter overflow");
    }
    assert!(
        next < file_pages,
        "fs_eviction: {next} pages held, cache never filled"
    );
    let first = *wait_for_releases(&log, 1)
        .first()
        .expect("fs_eviction: release log empty after wait");
    assert_eq!(
        first.0,
        first.1 & TAG_MASK,
        "fs_eviction: a release of cookie {:#x} arrived on another open's endpoint",
        first.1
    );

    // Close the open the first release reached; the other keeps its pages.
    let (mut other, closed) = if first.0 == TAG_X { (y, x) } else { (x, y) };
    closed.finish(ipc_buf);
    assert!(
        other.pages.iter().all(|&p| cap_live(p)),
        "fs_eviction: closing one open revoked a page of the other"
    );
    // Pages the closed open held are cached but unreferenced, so reading
    // them takes slots again; a page `other` holds itself takes none.
    let own: Vec<usize> = other.held.clone();
    let filled = (0..file_pages)
        .filter(|i| !own.contains(i))
        .any(|i| !other.hold(i, ipc_buf));
    assert!(filled, "fs_eviction: cache never filled again");
    let releases = wait_for_releases(&log, 2);
    for &(tag, cookie) in &releases
    {
        assert_eq!(
            tag,
            cookie & TAG_MASK,
            "fs_eviction: a release of cookie {cookie:#x} arrived on another open's endpoint"
        );
    }
    assert_eq!(
        releases
            .get(1)
            .expect("fs_eviction: fewer than two releases logged")
            .0,
        other.tag,
        "fs_eviction: the second eviction did not reach the open still holding pages"
    );

    other.finish(ipc_buf);
    drop(held_files);
    let _ = syscall::cap_delete(node);
    let _ = syscall::cap_delete(svctest);
    std::os::seraph::log!(
        "fs_eviction_routes_release_to_its_open phase passed ({} releases)",
        releases.len()
    );
}

// ── Reclaim of an open whose client is gone ────────────────────────────────

/// Role token for [`open_reclaim_child_main`].
const OPEN_RECLAIM_CHILD_ROLE: &str = "open-reclaim-child";

/// Role token for [`session_undeliverable_child_main`].
const SESSION_UNDELIVERABLE_CHILD_ROLE: &str = "session-undeliverable-child";

/// Role token for [`read_undeliverable_child_main`].
const READ_UNDELIVERABLE_CHILD_ROLE: &str = "read-undeliverable-child";

/// How long the reclaim phase and its children wait for fatfs to end a
/// session whose client is gone. A test wait bound.
const RECLAIM_WAIT: Duration = Duration::from_secs(60);

/// The scratch file the reclaim phase and its children open.
const RECLAIM_NAME: &str = "reclaim.bin";

/// Label of the call an `open-reclaim-child` makes on its namespace cap,
/// which carries SEND only (procmgr installs it so), to fetch its caps.
const RECLAIM_FETCH_LABEL: u64 = 0x6F70_6631;

/// Label of the call an `open-reclaim-child` makes on the fetched hand-off
/// SEND, carrying a copy of its open cap.
const RECLAIM_HAND_LABEL: u64 = 0x6F70_6632;

/// Badge of the hand-off SEND (with GRANT) an `open-reclaim-child` fetches.
const RECLAIM_HAND_BADGE: u64 = 0x5703;

/// Badge of the SEND that stops [`serve_reclaim_child`].
const RECLAIM_STOP_BADGE: u64 = 0x5704;

/// Child-mode dispatch for argv tokens this module owns. An
/// `open-reclaim-child` parks until its spawner kills it, and a
/// `session-undeliverable-child` and a `read-undeliverable-child` exit with
/// their result; on a miss control returns to the caller.
pub fn reentry_main(role: &str)
{
    if role == OPEN_RECLAIM_CHILD_ROLE
    {
        open_reclaim_child_main();
    }
    if role == SESSION_UNDELIVERABLE_CHILD_ROLE
    {
        session_undeliverable_child_main();
    }
    if role == READ_UNDELIVERABLE_CHILD_ROLE
    {
        read_undeliverable_child_main();
    }
}

/// An `open-reclaim-child`: fetch a file node cap, a release SEND, and a
/// hand-off SEND from the spawner (whose endpoint arrives as this process's
/// namespace cap), open the file in this process's session carrying the
/// release SEND, read a page, hand the spawner a copy of the open cap, and
/// park until killed. Exit codes: 2 = the fetch failed, 3 = `FS_OPEN`
/// failed, 4 = `FS_READ_MEMORY` failed, 5 = the open cap's copy failed, 6 =
/// the hand-off call failed.
fn open_reclaim_child_main() -> !
{
    let ipc_buf = current_ipc_buf();
    let fetch = ipc::IpcMessage::new(RECLAIM_FETCH_LABEL);
    // SAFETY: `ipc_buf` is this thread's registered IPC buffer page.
    let fetched = unsafe { ipc::ipc_call(std::os::seraph::root_dir_cap(), &fetch, ipc_buf) };
    let Some(&[node, release, hand]) = fetched.as_ref().ok().map(ipc::IpcMessage::caps)
    else
    {
        std::process::exit(2)
    };
    let Ok(open) = fs_open(node, release, ipc_buf)
    else
    {
        std::process::exit(3)
    };
    if fs_read_memory(open, 0, 1, ipc_buf).is_err()
    {
        std::process::exit(4);
    }
    let Ok(copy) = syscall::cap_derive(open, syscall::RIGHTS_EP_SEND)
    else
    {
        std::process::exit(5)
    };
    let msg = ipc::IpcMessage::builder(RECLAIM_HAND_LABEL)
        .cap(copy)
        .build();
    // SAFETY: as above.
    if unsafe { ipc::ipc_call(hand, &msg, ipc_buf) }.is_err()
    {
        std::process::exit(6);
    }
    loop
    {
        std::thread::park();
    }
}

/// Serve `ep` for an `open-reclaim-child`: answer its fetch with `node`,
/// `release`, and a hand-off SEND badged [`RECLAIM_HAND_BADGE`], and return
/// the open cap copy its hand-off carries, or `None` once the stop badge
/// arrives. Any other call is refused and its caps deleted.
fn serve_reclaim_child(ep: u64, node: u64, release: u64) -> Option<u64>
{
    let ipc_buf = current_ipc_buf();
    let mut grant = Some((node, release));
    loop
    {
        // SAFETY: `ipc_buf` is this thread's registered IPC buffer page.
        let msg = unsafe { ipc::ipc_recv(ep, ipc_buf) }.expect("fs_reclaim server: ipc_recv");
        let handed = (msg.badge == RECLAIM_HAND_BADGE && msg.label == RECLAIM_HAND_LABEL)
            .then(|| msg.caps().first().copied())
            .flatten();
        for &cap in msg.caps().iter().skip(usize::from(handed.is_some()))
        {
            let _ = syscall::cap_delete(cap);
        }
        let done = msg.badge == RECLAIM_STOP_BADGE || handed.is_some();
        let reply = match grant
        {
            Some((node, release)) if !done && msg.label == RECLAIM_FETCH_LABEL =>
            {
                grant = None;
                let hand = syscall::cap_derive_badge(
                    ep,
                    syscall::RIGHTS_EP_SEND_GRANT,
                    RECLAIM_HAND_BADGE,
                )
                .expect("fs_reclaim server: hand-off SEND derive");
                ipc::IpcMessage::builder(0)
                    .cap(node)
                    .cap(release)
                    .cap(hand)
                    .build()
            }
            _ if done => ipc::IpcMessage::new(0),
            _ => ipc::IpcMessage::new(u64::MAX),
        };
        // SAFETY: as above.
        let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
        if done
        {
            return handed;
        }
    }
}

/// Spawn an `open-reclaim-child` on `node`, its release SEND on `release`,
/// and return it with the copy of its open cap it hands back.
fn spawn_reclaim_child(node: u64, release: u64) -> (std::process::Child, u64)
{
    use std::os::seraph::process::CommandExt;

    let ep =
        std::os::seraph::create_endpoint().expect("fs_reclaim: server endpoint creation failed");
    let root = syscall::cap_derive(ep, syscall::RIGHTS_EP_SEND).expect("fs_reclaim: root SEND");
    let stop = syscall::cap_derive_badge(ep, syscall::RIGHTS_EP_SEND, RECLAIM_STOP_BADGE)
        .expect("fs_reclaim: stop SEND");
    let server = std::thread::Builder::new()
        .name("fs_reclaim_server".into())
        .spawn(move || serve_reclaim_child(ep, node, release))
        .expect("fs_reclaim: server thread spawn failed");
    let mut child = std::process::Command::new("/tests/svctest")
        .arg(OPEN_RECLAIM_CHILD_ROLE)
        .namespace_cap(root)
        .spawn()
        .expect("fs_reclaim: spawning open-reclaim-child failed");
    while !server.is_finished()
    {
        if let Some(status) = child.try_wait().expect("fs_reclaim: try_wait failed")
        {
            // SAFETY: `current_ipc_buf` is this thread's registered IPC buffer.
            let _ = unsafe { ipc::ipc_call(stop, &ipc::IpcMessage::new(0), current_ipc_buf()) };
            let _ = server.join();
            panic!(
                "fs_reclaim: open-reclaim-child exited {status} before handing its open (2 = \
                 fetch, 3 = FS_OPEN, 4 = FS_READ_MEMORY, 5 = copy, 6 = hand-off failed)"
            );
        }
        let _ = syscall::thread_yield();
    }
    let copy = server
        .join()
        .expect("fs_reclaim: server thread panicked")
        .expect("fs_reclaim: no open cap handed over");
    let _ = syscall::cap_delete(stop);
    let _ = syscall::cap_delete(ep);
    (child, copy)
}

/// Whether `open` still names an open of an 8-byte-or-longer file: an
/// `FS_READ` through it reads 8 bytes. `false` when fatfs answers
/// `INVALID_BADGE`, its open having been released; any other answer panics.
fn open_live(open: u64, ipc_buf: *mut u64) -> bool
{
    match fs_read_bytes(open, 0, 8, ipc_buf)
    {
        Ok(bytes) => bytes.len() == 8,
        Err(ipc::fs_errors::INVALID_BADGE) => false,
        Err(e) => panic!("fs_reclaim: FS_READ on an open cap status {e}"),
    }
}

/// Whether `cap` is the only reference to its object
/// (`CAP_INFO_SOLE_REFERENCE`).
fn sole(cap: u64) -> bool
{
    syscall::cap_info(cap, syscall::CAP_INFO_SOLE_REFERENCE)
        .expect("fs_reclaim: CAP_INFO_SOLE_REFERENCE failed")
        == 1
}

/// fatfs ends a session, with every open made in it, once its client holds
/// no copy of the session's liveness cap (services/fs/docs/fs-driver-protocol.md
/// § Label 23), and keeps every session whose liveness cap someone holds. An
/// `open-reclaim-child` opens a file in its own session carrying a release
/// SEND on a svctest endpoint, reads a page, hands svctest a copy of its open
/// cap, and is killed, sending no `FS_CLOSE`: its death releases its node,
/// which signals fatfs. The child's open must then be gone (its cap copy
/// answers `INVALID_BADGE`), and so must its release SEND (svctest's endpoint
/// cap is the endpoint's only reference). A session whose liveness cap svctest
/// deleted, its node kept, must end at a scheduled sweep, which svctest brings
/// on by starting sessions, while an open in svctest's own session still
/// reads. A `session-undeliverable-child`, whose `CSpace` cannot take the
/// `FS_SESSION` reply, sees fatfs end the session it started before it serves
/// the child's next request, its page leaving the child's node. A
/// `read-undeliverable-child`, whose `CSpace` cannot take an `FS_READ_MEMORY`
/// reply's page, sees fatfs give each such page back, so more reads than an
/// open may hold pages all fail their transfer and none is refused. fatfs once
/// kept a dead client's open, and its release SEND, until the open's node was
/// removed.
pub fn fs_reclaims_dead_opens_phase(_: &Caps)
{
    let ipc_buf = current_ipc_buf();
    let (svctest, node) = scratch_file(RECLAIM_NAME, 1, ipc_buf);

    let kept = fs_open(node, 0, ipc_buf).expect("fs_reclaim: FS_OPEN kept");
    let (orphan, release_ep) = killed_childs_open(node, ipc_buf);
    let start = Instant::now();
    while open_live(orphan, ipc_buf)
    {
        assert!(
            start.elapsed() < RECLAIM_WAIT,
            "fs_reclaim: the dead child's open outlived its death"
        );
        std::thread::yield_now();
    }
    assert!(
        sole(release_ep),
        "fs_reclaim: fatfs ended the dead child's open but kept its release SEND"
    );

    let sessions = dropped_session_swept(node, ipc_buf);
    assert!(
        open_live(kept, ipc_buf),
        "fs_reclaim: a sweep ended svctest's own session"
    );

    let status = std::process::Command::new("/tests/svctest")
        .arg(SESSION_UNDELIVERABLE_CHILD_ROLE)
        .status()
        .expect("fs_reclaim: spawning session-undeliverable-child failed");
    assert!(
        status.success(),
        "fs_reclaim: session-undeliverable-child exited {status} (2 = lookup, 3 = node or \
         handle, 4 = CSpace exhaustion, 5 = the FS_SESSION reply landed, 6 = the call failed, \
         7 = fatfs kept the session's page)"
    );
    let status = std::process::Command::new("/tests/svctest")
        .arg(READ_UNDELIVERABLE_CHILD_ROLE)
        .status()
        .expect("fs_reclaim: spawning read-undeliverable-child failed");
    assert!(
        status.success(),
        "fs_reclaim: read-undeliverable-child exited {status} (2 = lookup, 3 = FS_OPEN or the \
         first read, 4 = CSpace exhaustion, 5 = fatfs kept the pages of undelivered reads: a \
         read's reply landed or was refused, 6 = the call failed)"
    );

    assert_eq!(fs_close(kept, ipc_buf), ipc::fs_errors::SUCCESS);
    for cap in [kept, orphan, release_ep, node]
    {
        let _ = syscall::cap_delete(cap);
    }
    fs_remove(svctest, RECLAIM_NAME.as_bytes(), ipc_buf).expect("cleanup reclaim.bin");
    let _ = syscall::cap_delete(svctest);
    std::os::seraph::log!("fs_reclaims_dead_opens phase passed (swept within {sessions} sessions)");
}

/// Spawn an `open-reclaim-child` on `node` with a release SEND on a new
/// svctest endpoint, check that its open reads and that fatfs holds its
/// release SEND, and kill it. Returns the copy of the child's open cap and
/// the release endpoint.
fn killed_childs_open(node: u64, ipc_buf: *mut u64) -> (u64, u64)
{
    let release_ep =
        std::os::seraph::create_endpoint().expect("fs_reclaim: release endpoint creation failed");
    let release = syscall::cap_derive(release_ep, syscall::RIGHTS_EP_SEND)
        .expect("fs_reclaim: release SEND derive");
    let child_node = syscall::cap_derive(node, syscall::RIGHTS_EP_SEND_GRANT)
        .expect("fs_reclaim: node cap copy");
    let (mut child, orphan) = spawn_reclaim_child(child_node, release);
    assert!(
        open_live(orphan, ipc_buf),
        "fs_reclaim: the live child's open does not read"
    );
    assert!(
        !sole(release_ep),
        "fs_reclaim: fatfs holds no release SEND for the live child's open"
    );
    child
        .kill()
        .expect("fs_reclaim: killing open-reclaim-child failed");
    let _ = child.wait();
    (orphan, release_ep)
}

/// Open `node` in a session on a sub-node of svctest's, delete the session's
/// liveness cap and keep the node, so only a scheduled sweep can end it, and
/// start sessions, each dropped the same way, until the open names no open.
/// Returns the sessions it took; the nodes are released after.
fn dropped_session_swept(node: u64, ipc_buf: *mut u64) -> usize
{
    // A test bound: the sessions svctest starts before the sweep must have
    // come. fatfs sweeps within the larger of `fat_parse::sweep::SWEEP_FLOOR`
    // (64) and the live sessions of its last sweep, far below this in a
    // svctest boot.
    const SWEEP_BOUND: usize = 1 << 12;

    let top = sub_node(
        startup_info().memmgr_endpoint,
        u64::MAX,
        "fs_reclaim: CREATE_SUB_NODE",
    );
    let mut nodes = Vec::new();
    let mut dropped_session = |what: &str| {
        let held = sub_node(top, u64::MAX, what);
        nodes.push(held);
        let (session, liveness) = fs_session(node, charge_handle(held, what), ipc_buf)
            .unwrap_or_else(|e| panic!("{what}: FS_SESSION status {e:#x}"));
        syscall::cap_delete(liveness).expect("fs_reclaim: deleting a liveness cap");
        session
    };
    let session = dropped_session("fs_reclaim: the dropped session's node");
    let dropped = fs_open_in(node, session, 0, ipc_buf).expect("fs_reclaim: FS_OPEN dropped");
    let sessions = (1..=SWEEP_BOUND).find(|_| {
        let other = dropped_session("fs_reclaim: a sweep-bringing session's node");
        let _ = syscall::cap_delete(other);
        !open_live(dropped, ipc_buf)
    });
    let sessions = sessions.unwrap_or_else(|| {
        panic!("fs_reclaim: a session with no liveness cap outlived {SWEEP_BOUND} sessions")
    });
    for held in nodes
    {
        release_refused(held, "fs_reclaim: a session's node");
    }
    release_refused(top, "fs_reclaim: the sessions' parent node");
    for cap in [dropped, session]
    {
        let _ = syscall::cap_delete(cap);
    }
    sessions
}

/// A `session-undeliverable-child`: make a sub-node of its own node and a
/// charge-only handle to it, exhaust this process's `CSpace`, its IPC receive
/// reserve included, and ask for a session on [`RECLAIM_NAME`]'s node
/// carrying the handle: moving the handle out frees one slot, so the reply's
/// session cap and liveness cap cannot both land. Check that the reply
/// transfer fails and that fatfs, once it has received another request (an
/// `NS_STAT` of the child's), has ended the session it started, its page
/// leaving the sub-node. Allocates nothing on the heap after the exhaustion,
/// since a heap refill needs a free slot. Exit codes: 0 = the page went, 2 =
/// the lookup failed, 3 = the sub-node or its handle could not be made, 4 = a
/// grant spending the receive reserve neither landed nor failed its transfer,
/// 5 = the reply landed or fatfs refused the session, 6 = the call failed, 7 =
/// the page stayed charged past the wait bound.
fn session_undeliverable_child_main() -> !
{
    let info = startup_info();
    let ipc_buf = current_ipc_buf();
    let svctest = svctest_dir_cap(ipc_buf);
    let Ok((node, _, _)) = ns_lookup(svctest, RECLAIM_NAME.as_bytes(), 0xFFFF, ipc_buf)
    else
    {
        std::process::exit(2)
    };
    let one_cap = |reply: Option<SmallReply>| match reply
    {
        Some(r) if r.label == ipc::memmgr_errors::SUCCESS && r.caps == 1 => Some(r.cap),
        _ => None,
    };
    let Some(own) = one_cap(small_call(
        info.memmgr_endpoint,
        ipc::memmgr_labels::CREATE_SUB_NODE,
        Some(u64::MAX),
    ))
    else
    {
        std::process::exit(3)
    };
    let Some(charge) = one_cap(small_call(
        own,
        ipc::memmgr_labels::NODE_CHARGE_HANDLE,
        None,
    ))
    else
    {
        std::process::exit(3)
    };

    // Fill every general slot with copies of the directory cap, then spend
    // the IPC receive reserve, which general allocations leave free, on
    // one-page memmgr grants: each lands until the reserve is gone.
    while syscall::cap_derive(svctest, syscall::RIGHTS_EP_SEND).is_ok()
    {}
    for _ in 0..=syscall_abi::CSPACE_IPC_RECV_RESERVE
    {
        match small_call(
            info.memmgr_endpoint,
            ipc::memmgr_labels::REQUEST_MEMORY_CAPS,
            Some(1),
        )
        {
            Some(reply) if reply.label == syscall::IPC_REPLY_TRANSFER_FAILED => break,
            Some(reply) if reply.label == ipc::memmgr_errors::SUCCESS && reply.caps != 0 =>
            {}
            _ => std::process::exit(4),
        }
    }

    match small_call_carrying(node, ipc::fs_labels::FS_SESSION, charge)
    {
        Some(reply) if reply.label == syscall::IPC_REPLY_TRANSFER_FAILED =>
        {}
        Some(_) => std::process::exit(5),
        None => std::process::exit(6),
    }
    // fatfs undoes a reply that was not delivered once its loop's next
    // receive returns, before it serves the request that receive brings: a
    // request of this child's own brings it, whatever else fatfs serves.
    let _ = ns_stat(node, ipc_buf);
    let start = Instant::now();
    while start.elapsed() < RECLAIM_WAIT
    {
        // A recheck of memmgr's deferred list pools a page fatfs has let go.
        let _ = small_call(
            info.memmgr_endpoint,
            ipc::memmgr_labels::RELEASE_MEMORY_CAPS,
            Some(0),
        );
        if small_call(own, ipc::memmgr_labels::NODE_QUERY_USAGE, None)
            .is_some_and(|r| r.label == ipc::memmgr_errors::SUCCESS && r.word2 == 0)
        {
            std::process::exit(0);
        }
        let _ = syscall::thread_yield();
    }
    std::process::exit(7);
}

/// A `read-undeliverable-child`: open [`RECLAIM_NAME`] and check that a
/// memory-cap read of it lands, then exhaust this process's `CSpace`, its IPC
/// receive reserve included, and make one more `FS_READ_MEMORY` than an open
/// may hold pages (fatfs's cache slot ceiling), each under a new cookie. Every
/// reply's page cap finds no slot, so each must arrive as
/// `IPC_REPLY_TRANSFER_FAILED`: a fatfs that kept the page of a reply that did
/// not arrive holds the open's limit before the last read and refuses it.
/// Allocates nothing on the heap after the exhaustion. Exit codes: 0 = every
/// read failed its transfer, 2 = the lookup failed, 3 = `FS_OPEN` or the
/// first read failed, 4 = a grant spending the receive reserve neither landed
/// nor failed its transfer, 5 = a read's reply landed or was refused, 6 = a
/// call failed.
fn read_undeliverable_child_main() -> !
{
    let info = startup_info();
    let ipc_buf = current_ipc_buf();
    let svctest = svctest_dir_cap(ipc_buf);
    let Ok((node, _, _)) = ns_lookup(svctest, RECLAIM_NAME.as_bytes(), 0xFFFF, ipc_buf)
    else
    {
        std::process::exit(2)
    };
    let Ok(open) = fs_open(node, 0, ipc_buf)
    else
    {
        std::process::exit(3)
    };
    let Ok((page, _)) = fs_read_memory(open, 0, 1, ipc_buf)
    else
    {
        std::process::exit(3)
    };
    let _ = syscall::cap_delete(page);
    if page == 0 || fs_release_memory(open, 1, ipc_buf) != ipc::fs_errors::SUCCESS
    {
        std::process::exit(3);
    }
    let reads = crate::phases::fs_ipc::fatfs_slot_ceiling(ipc_buf).saturating_add(1);

    // Fill every general slot, then spend the IPC receive reserve on one-page
    // memmgr grants, as `session-undeliverable-child` does.
    while syscall::cap_derive(svctest, syscall::RIGHTS_EP_SEND).is_ok()
    {}
    for _ in 0..=syscall_abi::CSPACE_IPC_RECV_RESERVE
    {
        match small_call(
            info.memmgr_endpoint,
            ipc::memmgr_labels::REQUEST_MEMORY_CAPS,
            Some(1),
        )
        {
            Some(reply) if reply.label == syscall::IPC_REPLY_TRANSFER_FAILED => break,
            Some(reply) if reply.label == ipc::memmgr_errors::SUCCESS && reply.caps != 0 =>
            {}
            _ => std::process::exit(4),
        }
    }

    for cookie in 2..=u64::try_from(reads).unwrap_or(u64::MAX).saturating_add(1)
    {
        let read = ipc::IpcMessage::builder(ipc::fs_labels::FS_READ_MEMORY)
            .word(0, 0)
            .word(1, cookie)
            .build();
        match small_reply(open, &read)
        {
            Some(reply) if reply.label == syscall::IPC_REPLY_TRANSFER_FAILED =>
            {}
            Some(_) => std::process::exit(5),
            None => std::process::exit(6),
        }
    }
    std::process::exit(0);
}

/// What a [`small_call`] keeps of its reply: the label, the cap count, the
/// first cap (0 for none) and `data[2]`.
#[derive(Clone, Copy)]
struct SmallReply
{
    label: u64,
    caps: usize,
    cap: u64,
    word2: u64,
}

/// Call `target` with `label` and, when given, `data[0]` = `word`, on this
/// thread's IPC buffer; the reply as [`SmallReply`] keeps it, `None` when
/// the call fails. Keeps the message off the caller's frame.
fn small_call(target: u64, label: u64, word: Option<u64>) -> Option<SmallReply>
{
    let mut msg = ipc::IpcMessage::builder(label);
    if let Some(word) = word
    {
        msg = msg.word(0, word);
    }
    small_reply(target, &msg.build())
}

/// [`small_call`] of the bare `label` carrying `cap`.
fn small_call_carrying(target: u64, label: u64, cap: u64) -> Option<SmallReply>
{
    small_reply(target, &ipc::IpcMessage::builder(label).cap(cap).build())
}

/// Send `msg` on `target` and keep the reply as [`SmallReply`].
fn small_reply(target: u64, msg: &ipc::IpcMessage) -> Option<SmallReply>
{
    // SAFETY: `current_ipc_buf` is this thread's registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(target, msg, current_ipc_buf()) }.ok()?;
    Some(SmallReply {
        label: reply.label,
        caps: reply.caps().len(),
        cap: reply.caps().first().copied().unwrap_or(0),
        word2: reply.word(2),
    })
}
