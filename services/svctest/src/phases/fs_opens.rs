// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/fs_opens.rs

//! fatfs's per-open state (services/fs/docs/fs-driver-protocol.md § Label 18:
//! `FS_OPEN`): two opens of one file are told apart. One open's `FS_CLOSE`
//! releases only its own pages, a closed open's cap names no open, and
//! eviction sends each page's cooperative release to the release endpoint of
//! the open that read it.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use crate::bootstrap::Caps;
use crate::ipc_util::fs::{
    fs_close, fs_open, fs_read_memory, fs_release_memory, fs_remove, svctest_dir_cap,
};
use crate::ipc_util::ns::{ns_lookup, ns_stat};
use crate::runner::Phase;

pub fn phases() -> &'static [Phase]
{
    &[
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
/// and return its node cap.
fn scratch_file(name: &str, pages: usize, ipc_buf: *mut u64) -> (u32, u32)
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
fn cap_live(cap: u32) -> bool
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
    open: u32,
    tag: u64,
    endpoint: u32,
    stop: u32,
    pages: Vec<u32>,
}

/// The releases a handler thread received: the tag of the endpoint each
/// arrived on, and its cookie.
type ReleaseLog = Arc<Mutex<Vec<(u64, u64)>>>;

impl Opener
{
    /// A release endpoint with a handler thread that logs each
    /// `FS_RELEASE_MEMORY` under `tag` and acks it, and an `FS_OPEN` of
    /// `node` carrying a SEND on it.
    fn new(node: u32, tag: u64, log: &ReleaseLog, ipc_buf: *mut u64) -> Self
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
fn serve_releases(endpoint: u32, tag: u64, log: &ReleaseLog)
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

/// Two opens of one file, each with its own release endpoint, read and hold
/// pages until every cache slot is held, so fatfs queues a held page for
/// eviction. Its cooperative `FS_RELEASE_MEMORY` must arrive on the release
/// endpoint of the open that read the page, naming that open's cookie. The
/// open it reached then closes, freeing its slots without touching the
/// other's pages, and the other reads until the cache is full again: the
/// next eviction must reach the other open's endpoint. fatfs once kept one
/// release SEND per node, the first a read of the node carried, and sent
/// every client's releases there.
pub fn fs_eviction_routes_release_to_its_open_phase(_: &Caps)
{
    const TAG_X: u64 = 0x58 << 56;
    const TAG_Y: u64 = 0x59 << 56;
    const TAG_MASK: u64 = 0xFF << 56;

    let ipc_buf = std::os::seraph::current_ipc_buf();
    let slots = crate::phases::fs_ipc::fatfs_slot_ceiling(ipc_buf);
    let file_pages = slots + 64;
    let name = "evict.bin";
    let (svctest, node) = scratch_file(name, file_pages, ipc_buf);

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
    while next < file_pages && other.hold(next, ipc_buf)
    {
        next += 1;
    }
    assert!(next < file_pages, "fs_eviction: cache never filled again");
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
    let _ = syscall::cap_delete(node);
    fs_remove(svctest, name.as_bytes(), ipc_buf).expect("cleanup evict.bin");
    let _ = syscall::cap_delete(svctest);
    std::os::seraph::log!(
        "fs_eviction_routes_release_to_its_open phase passed ({} releases)",
        releases.len()
    );
}
