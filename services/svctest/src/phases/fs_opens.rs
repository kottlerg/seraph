// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/fs_opens.rs

//! fatfs's per-open state (services/fs/docs/fs-driver-protocol.md § Label 18:
//! `FS_OPEN`): two opens of one file are told apart. One open's `FS_CLOSE`
//! releases only its own pages, a closed open's cap names no open, eviction
//! sends each page's cooperative release to the release endpoint of the open
//! that read it, and an open whose client holds no copy of its liveness cap
//! any more, because the client died or deleted it, is released.

use std::os::seraph::{current_ipc_buf, startup_info};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use crate::bootstrap::Caps;
use crate::ipc_util::fs::{
    fs_close, fs_create, fs_open, fs_open_live, fs_read_bytes, fs_read_memory, fs_release_memory,
    fs_remove, svctest_dir_cap,
};
use crate::ipc_util::ns::{ns_lookup, ns_stat};
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
            std::os::seraph::object_slab_retype(std::os::seraph::ENDPOINT_RETYPE_BYTES, |slab| {
                syscall::cap_create_endpoint(slab).ok()
            })
            .expect("fs_eviction: endpoint creation failed");
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
        match fs_read_memory(self.open, (index * PAGE) as u64, cookie, ipc_buf)
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

/// Opens of other files that each hold a release SEND and a liveness
/// Notification in fatfs's `CSpace`, kept across the
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
/// a release SEND and a liveness parent in fatfs's `CSpace`, so the fill's slot pages and per-read
/// caps need the slots `FS_OPEN`'s top-up keeps free for every slot not yet
/// provisioned. fatfs once kept only the per-read caps' worth free, and the
/// fill exhausted its `CSpace` before the cache filled.
pub fn fs_eviction_routes_release_to_its_open_phase(_: &Caps)
{
    const TAG_X: u64 = 0x58 << 56;
    const TAG_Y: u64 = 0x59 << 56;
    const TAG_MASK: u64 = 0xFF << 56;

    let ipc_buf = std::os::seraph::current_ipc_buf();
    // svctest holds an open cap and a liveness cap per held File and a page
    // cap per held page.
    assert!(
        std::os::seraph::fund_cspace_slot_budget(
            startup_info().self_cspace,
            (2 * HELD_FILES + crate::phases::fs_ipc::fatfs_slot_ceiling(ipc_buf) + 64) as u64,
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
        next += 1;
    }
    assert!(
        next < file_pages,
        "fs_eviction: {next} pages held, cache never filled"
    );
    let first = wait_for_releases(&log, 1)[0];
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
        releases[1].0, other.tag,
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

/// Role token for [`open_undeliverable_child_main`].
const OPEN_UNDELIVERABLE_CHILD_ROLE: &str = "open-undeliverable-child";

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
/// `open-reclaim-child` parks until its spawner kills it, and an
/// `open-undeliverable-child` exits with its result; on a miss control
/// returns to the caller.
pub fn reentry_main(role: &str)
{
    if role == OPEN_RECLAIM_CHILD_ROLE
    {
        open_reclaim_child_main();
    }
    if role == OPEN_UNDELIVERABLE_CHILD_ROLE
    {
        open_undeliverable_child_main();
    }
}

/// An `open-reclaim-child`: fetch a file node cap, a release SEND, and a
/// hand-off SEND from the spawner (whose endpoint arrives as this process's
/// namespace cap), open the file carrying the release SEND, read a page, hand
/// the spawner a copy of the open cap, and park until killed, keeping the
/// open's liveness cap. Exit codes: 2 = the fetch failed, 3 = `FS_OPEN`
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
    let Ok((open, _liveness)) = fs_open_live(node, release, ipc_buf)
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

    let ep = std::os::seraph::object_slab_retype(std::os::seraph::ENDPOINT_RETYPE_BYTES, |slab| {
        syscall::cap_create_endpoint(slab).ok()
    })
    .expect("fs_reclaim: server endpoint creation failed");
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

/// fatfs releases an open once no copy of its liveness cap is left outside it
/// (services/fs/docs/fs-driver-protocol.md § Label 18), and keeps every open
/// whose liveness cap someone holds. An `open-reclaim-child` opens a file
/// carrying a release SEND on a svctest endpoint, reads a page, hands svctest
/// a copy of its open cap, and is killed, sending no `FS_CLOSE`; svctest
/// opens and closes the file until a sweep falls due. The child's open must
/// then be gone (its cap copy answers `INVALID_BADGE`), and so must its
/// release SEND (svctest's endpoint cap is the endpoint's only reference),
/// as must an open whose liveness cap svctest deleted, while an open whose
/// liveness cap svctest keeps still reads. An `FS_CLOSE` revokes the open's
/// liveness cap, and an `open-undeliverable-child`, whose `CSpace` cannot
/// take the `FS_OPEN` reply, sees fatfs drop the release SEND that open
/// carried. fatfs once kept a dead client's open, and its release SEND, until
/// the open's node was removed.
pub fn fs_reclaims_dead_opens_phase(_: &Caps)
{
    let ipc_buf = current_ipc_buf();
    let (svctest, node) = scratch_file(RECLAIM_NAME, 1, ipc_buf);

    let (kept, _kept_liveness) = fs_open_live(node, 0, ipc_buf).expect("fs_reclaim: FS_OPEN kept");
    let (dropped, dropped_liveness) =
        fs_open_live(node, 0, ipc_buf).expect("fs_reclaim: FS_OPEN dropped");
    syscall::cap_delete(dropped_liveness).expect("fs_reclaim: deleting a liveness cap");
    close_revokes_liveness(node, ipc_buf);

    let (orphan, release_ep) = killed_childs_open(node, ipc_buf);
    let opens = open_until_released(node, orphan, ipc_buf);
    assert!(
        sole(release_ep),
        "fs_reclaim: the sweep released the dead child's open but kept its release SEND"
    );
    assert!(
        !open_live(dropped, ipc_buf),
        "fs_reclaim: an open whose liveness cap was deleted outlived a sweep"
    );
    assert!(
        open_live(kept, ipc_buf),
        "fs_reclaim: a sweep released an open whose liveness cap is held"
    );

    let status = std::process::Command::new("/tests/svctest")
        .arg(OPEN_UNDELIVERABLE_CHILD_ROLE)
        .status()
        .expect("fs_reclaim: spawning open-undeliverable-child failed");
    assert!(
        status.success(),
        "fs_reclaim: open-undeliverable-child exited {status} (2 = lookup, 3 = release \
         endpoint, 4 = CSpace exhaustion, 5 = the FS_OPEN reply landed, 6 = the call failed, \
         7 = fatfs kept the release SEND)"
    );

    assert_eq!(fs_close(kept, ipc_buf), ipc::fs_errors::SUCCESS);
    for cap in [kept, dropped, orphan, release_ep, node]
    {
        let _ = syscall::cap_delete(cap);
    }
    fs_remove(svctest, RECLAIM_NAME.as_bytes(), ipc_buf).expect("cleanup reclaim.bin");
    let _ = syscall::cap_delete(svctest);
    std::os::seraph::log!("fs_reclaims_dead_opens phase passed (swept within {opens} opens)");
}

/// Open `node` and close the open: its `FS_CLOSE` must revoke the liveness
/// cap the open's reply carried.
fn close_revokes_liveness(node: u64, ipc_buf: *mut u64)
{
    let (closed, liveness) = fs_open_live(node, 0, ipc_buf).expect("fs_reclaim: FS_OPEN closed");
    assert_eq!(fs_close(closed, ipc_buf), ipc::fs_errors::SUCCESS);
    assert!(
        !cap_live(liveness),
        "fs_reclaim: FS_CLOSE left the open's liveness cap live"
    );
    let _ = syscall::cap_delete(closed);
}

/// Spawn an `open-reclaim-child` on `node` with a release SEND on a new
/// svctest endpoint, check that its open reads and that fatfs holds its
/// release SEND, and kill it. Returns the copy of the child's open cap and
/// the release endpoint.
fn killed_childs_open(node: u64, ipc_buf: *mut u64) -> (u64, u64)
{
    let release_ep =
        std::os::seraph::object_slab_retype(std::os::seraph::ENDPOINT_RETYPE_BYTES, |slab| {
            syscall::cap_create_endpoint(slab).ok()
        })
        .expect("fs_reclaim: release endpoint creation failed");
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

/// Open and close `node` until `orphan` names no open, a sweep having
/// released it, and return the opens it took.
fn open_until_released(node: u64, orphan: u64, ipc_buf: *mut u64) -> usize
{
    // A test wait bound: the opens svctest makes before the sweep must have
    // come. fatfs sweeps within the larger of 64 and the live opens of its
    // last sweep, far below this in a svctest boot.
    const SWEEP_BOUND: usize = 1 << 14;

    let opens = (1..=SWEEP_BOUND).find(|_| {
        let (open, liveness) = fs_open_live(node, 0, ipc_buf).expect("fs_reclaim: FS_OPEN");
        assert_eq!(fs_close(open, ipc_buf), ipc::fs_errors::SUCCESS);
        let _ = syscall::cap_delete(open);
        let _ = syscall::cap_delete(liveness);
        !open_live(orphan, ipc_buf)
    });
    opens
        .unwrap_or_else(|| panic!("fs_reclaim: the dead child's open outlived {SWEEP_BOUND} opens"))
}

/// An `open-undeliverable-child`: exhaust this process's `CSpace`, its IPC
/// receive reserve included, so the two-cap `FS_OPEN` reply cannot land,
/// open [`RECLAIM_NAME`] carrying a release SEND on an endpoint of its own,
/// and check that the reply transfer fails and that fatfs then deletes the
/// SEND, leaving this process's endpoint cap the endpoint's only reference.
/// Allocates nothing on the heap after the exhaustion, since a heap refill
/// needs a free slot. Exit codes: 0 = the SEND went, 2 = the lookup failed,
/// 3 = the release endpoint or its SEND could not be made, 4 = a grant
/// spending the receive reserve neither landed nor failed its transfer, 5 =
/// the reply landed or fatfs refused the open, 6 = the call failed, 7 =
/// fatfs kept the SEND past the wait bound.
fn open_undeliverable_child_main() -> !
{
    // A test wait bound: how long fatfs may take to release the open after
    // its reply failed.
    const RELEASE_WAIT: Duration = Duration::from_secs(5);

    let info = startup_info();
    let ipc_buf = current_ipc_buf();
    let svctest = svctest_dir_cap(ipc_buf);
    let Ok((node, _, _)) = ns_lookup(svctest, RECLAIM_NAME.as_bytes(), 0xFFFF, ipc_buf)
    else
    {
        std::process::exit(2)
    };
    let ep = std::os::seraph::object_slab_retype(std::os::seraph::ENDPOINT_RETYPE_BYTES, |slab| {
        syscall::cap_create_endpoint(slab).ok()
    });
    let Some(release) = ep.and_then(|ep| syscall::cap_derive(ep, syscall::RIGHTS_EP_SEND).ok())
    else
    {
        std::process::exit(3)
    };
    let ep = ep.unwrap_or_default();

    // Fill every general slot with copies of the directory cap, then spend
    // the IPC receive reserve, which general allocations leave free, on
    // one-page memmgr grants: each lands until the reserve is gone.
    while syscall::cap_derive(svctest, syscall::RIGHTS_EP_SEND).is_ok()
    {}
    for _ in 0..=syscall_abi::CSPACE_IPC_RECV_RESERVE
    {
        let grant = ipc::IpcMessage::builder(ipc::memmgr_labels::REQUEST_MEMORY_CAPS)
            .word(0, 1)
            .build();
        // SAFETY: `ipc_buf` is the kernel-registered IPC buffer page.
        match unsafe { ipc::ipc_call(info.memmgr_endpoint, &grant, ipc_buf) }
        {
            Ok(reply) if reply.label == syscall::IPC_REPLY_TRANSFER_FAILED => break,
            Ok(reply) if reply.label == ipc::memmgr_errors::SUCCESS && !reply.caps().is_empty() =>
            {
            }
            _ => std::process::exit(4),
        }
    }

    // The open moves the SEND out, freeing one slot; the reply's open cap
    // and liveness cap cannot both land.
    let open = ipc::IpcMessage::builder(ipc::fs_labels::FS_OPEN)
        .cap(release)
        .build();
    // SAFETY: `ipc_buf` is the kernel-registered IPC buffer page.
    match unsafe { ipc::ipc_call(node, &open, ipc_buf) }
    {
        Ok(reply) if reply.label == syscall::IPC_REPLY_TRANSFER_FAILED =>
        {}
        Ok(_) => std::process::exit(5),
        Err(_) => std::process::exit(6),
    }
    let start = Instant::now();
    while start.elapsed() < RELEASE_WAIT
    {
        if syscall::cap_info(ep, syscall::CAP_INFO_SOLE_REFERENCE) == Ok(1)
        {
            std::process::exit(0);
        }
        let _ = syscall::thread_yield();
    }
    std::process::exit(7);
}
