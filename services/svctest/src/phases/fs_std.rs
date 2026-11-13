// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/fs_std.rs

//! `std::fs` surface (PAL layer over the FS-IPC contract).

use crate::bootstrap::Caps;
use crate::runner::Phase;

const STD_BULK_LEN: usize = 16 * 1024;

pub fn phases() -> &'static [Phase]
{
    &[
        Phase {
            name: "std_write",
            run: std_write_phase,
        },
        Phase {
            name: "std_create",
            run: std_create_phase,
        },
        Phase {
            name: "std_truncate",
            run: std_truncate_phase,
        },
        Phase {
            name: "std_append",
            run: std_append_phase,
        },
        Phase {
            name: "std_mkdir_remove",
            run: std_mkdir_remove_phase,
        },
        Phase {
            name: "std_rename",
            run: std_rename_phase,
        },
        Phase {
            name: "std_rename_names_too_long",
            run: std_rename_names_too_long_phase,
        },
        Phase {
            name: "std_remove_dir_all",
            run: std_remove_dir_all_phase,
        },
        Phase {
            name: "std_bulk_write",
            run: std_bulk_write_phase,
        },
        Phase {
            name: "std_frame_write_pool",
            run: std_frame_write_pool_phase,
        },
        Phase {
            name: "std_read_dir",
            run: std_read_dir_phase,
        },
        Phase {
            name: "std_metadata",
            run: std_metadata_phase,
        },
        Phase {
            name: "std_open_options_invalid",
            run: std_open_options_invalid_phase,
        },
        Phase {
            name: "std_release_matched_by_open",
            run: std_release_matched_by_open_phase,
        },
    ]
}

/// Role token for [`release_child_main`].
const RELEASE_CHILD_ROLE: &str = "release-child";

/// Child-mode dispatch for argv tokens this module owns. The matching arm
/// exits through `std::process::exit`; on a miss control returns to the
/// caller.
pub fn reentry_main(role: &str)
{
    if role == RELEASE_CHILD_ROLE
    {
        release_child_main();
    }
}

pub fn std_write_phase(_: &Caps)
{
    let path = "/data/svctest/std_w.bin";
    let _ = std::fs::remove_file(path);
    std::fs::write(path, b"hello std::fs").expect("std::fs::write");
    let got = std::fs::read(path).expect("std::fs::read");
    assert_eq!(&got[..], b"hello std::fs");
    std::fs::remove_file(path).expect("cleanup");
    std::os::seraph::log!("std_write phase passed");
}

pub fn std_create_phase(_: &Caps)
{
    use std::io::Write;
    let path = "/data/svctest/std_c.bin";
    let _ = std::fs::remove_file(path);
    {
        let mut f = std::fs::File::create(path).expect("File::create");
        f.write_all(b"create-data").expect("write_all");
        f.sync_all().expect("sync_all");
    }
    let got = std::fs::read(path).expect("readback");
    assert_eq!(&got[..], b"create-data");
    std::fs::remove_file(path).expect("cleanup");
    std::os::seraph::log!("std_create phase passed");
}

pub fn std_truncate_phase(_: &Caps)
{
    use std::io::Write;
    let path = "/data/svctest/std_t.bin";
    let _ = std::fs::remove_file(path);
    std::fs::write(path, vec![0xAAu8; 1024]).expect("seed 1 KiB");
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(path)
            .expect("reopen with truncate");
        f.write_all(b"short").expect("write short");
    }
    let got = std::fs::read(path).expect("readback");
    assert_eq!(got.len(), 5, "size must reflect post-truncate length");
    assert_eq!(&got[..], b"short");
    std::fs::remove_file(path).expect("cleanup");
    std::os::seraph::log!("std_truncate phase passed");
}

pub fn std_append_phase(_: &Caps)
{
    use std::io::Write;
    let path = "/data/svctest/std_a.bin";
    let _ = std::fs::remove_file(path);
    std::fs::write(path, b"head ").expect("seed");
    {
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(path)
            .expect("open append");
        f.write_all(b"tail").expect("append");
    }
    let got = std::fs::read(path).expect("readback");
    assert_eq!(&got[..], b"head tail");
    std::fs::remove_file(path).expect("cleanup");
    std::os::seraph::log!("std_append phase passed");
}

pub fn std_mkdir_remove_phase(_: &Caps)
{
    let d = "/data/svctest/std_d";
    let f = "/data/svctest/std_d/inner.bin";
    let _ = std::fs::remove_file(f);
    let _ = std::fs::remove_dir(d);

    std::fs::create_dir(d).expect("create_dir");
    std::fs::write(f, b"x").expect("write inside dir");
    let err = std::fs::remove_dir(d).expect_err("remove_dir non-empty must fail");
    assert_eq!(err.kind(), std::io::ErrorKind::DirectoryNotEmpty);
    std::fs::remove_file(f).expect("remove inner");
    std::fs::remove_dir(d).expect("remove now-empty dir");
    std::os::seraph::log!("std_mkdir_remove phase passed");
}

pub fn std_rename_phase(_: &Caps)
{
    let a = "/data/svctest/std_r_a.bin";
    let b = "/data/svctest/std_r_b.bin";
    let _ = std::fs::remove_file(a);
    let _ = std::fs::remove_file(b);
    std::fs::write(a, b"renameme").expect("seed");
    std::fs::rename(a, b).expect("rename");
    assert!(
        std::fs::read(a).is_err(),
        "old name must be gone after rename"
    );
    let got = std::fs::read(b).expect("read new name");
    assert_eq!(&got[..], b"renameme");
    std::fs::remove_file(b).expect("cleanup");
    std::os::seraph::log!("std_rename phase passed");
}

/// Leaf length that passes `validate_name` on its own while two such names
/// overflow the `FS_RENAME` data area left after its two length words.
const RENAME_LONG_NAME_LEN: usize = (syscall_abi::MSG_DATA_WORDS_MAX - 2) * 8 / 2 + 2;
const _: () = assert!(RENAME_LONG_NAME_LEN <= namespace_protocol::MAX_NAME_LEN);

/// Two root-anchored names of [`RENAME_LONG_NAME_LEN`] bytes: the combined
/// leaf-length check in `std::fs::rename` fires before any `FS_RENAME` is
/// sent, so neither name needs to exist for the refusal to be observable.
pub fn std_rename_names_too_long_phase(_: &Caps)
{
    let from = format!("/{}", "a".repeat(RENAME_LONG_NAME_LEN));
    let to = format!("/{}", "b".repeat(RENAME_LONG_NAME_LEN));
    let err = std::fs::rename(&from, &to).expect_err("oversize rename pair must be refused");
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::InvalidFilename,
        "oversize rename pair must surface as InvalidFilename, got {err:?}"
    );
    std::os::seraph::log!("std_rename_names_too_long phase passed");
}

pub fn std_remove_dir_all_phase(_: &Caps)
{
    let top = "/data/svctest/std_tree";
    let sub = "/data/svctest/std_tree/sub";
    let f1 = "/data/svctest/std_tree/file.bin";
    let f2 = "/data/svctest/std_tree/sub/leaf.bin";
    let _ = std::fs::remove_dir_all(top);

    std::fs::create_dir(top).expect("create top");
    std::fs::create_dir(sub).expect("create sub");
    std::fs::write(f1, b"a").expect("seed file.bin");
    std::fs::write(f2, b"b").expect("seed leaf.bin");

    std::fs::remove_dir_all(top).expect("remove_dir_all");

    assert!(
        std::fs::read(f1).is_err(),
        "file.bin must be gone after remove_dir_all"
    );
    assert!(
        std::fs::read(f2).is_err(),
        "leaf.bin must be gone after remove_dir_all"
    );
    std::os::seraph::log!("std_remove_dir_all phase passed");
}

pub fn std_bulk_write_phase(_: &Caps)
{
    use std::io::{Read, Write};
    let path = "/data/svctest/std_bulk.bin";
    let _ = std::fs::remove_file(path);
    let mut buf = vec![0u8; STD_BULK_LEN];
    for (i, b) in buf.iter_mut().enumerate()
    {
        *b = u8::try_from(i & 0xFF).unwrap_or(0);
    }
    {
        let mut f = std::fs::File::create(path).expect("create bulk");
        f.write_all(&buf).expect("write_all 16 KiB");
    }
    let mut got = Vec::with_capacity(STD_BULK_LEN);
    {
        let mut f = std::fs::File::open(path).expect("reopen bulk");
        f.read_to_end(&mut got).expect("read_to_end");
    }
    assert_eq!(got.len(), STD_BULK_LEN, "bulk round-trip length");
    for (i, &b) in got.iter().enumerate()
    {
        assert_eq!(b, u8::try_from(i & 0xFF).unwrap_or(0), "byte {i} mismatch");
    }
    std::fs::remove_file(path).expect("cleanup");
    std::os::seraph::log!("std_bulk_write phase passed");
}

/// Each frame-path write (over 504 bytes) returns its source page to memmgr
/// when it ends, so repeated writes leave memmgr's free pool where it was.
/// The writes go to one offset, so the fs driver's cache does not grow, and a
/// first write before the baseline settles this process's heap and the
/// driver's cache page. A leak of one page per write drops the pool by
/// `FRAME_WRITES` pages, four times the slack, on every attempt; the pool
/// is system-wide, so another process's allocation can perturb one
/// attempt, and the phase passes when any of `ATTEMPTS` stays in slack.
pub fn std_frame_write_pool_phase(_: &Caps)
{
    use std::io::{Seek, SeekFrom, Write};
    const FRAME_WRITES: u64 = 64;
    const SLACK_BYTES: u64 = (FRAME_WRITES / 4) * 4096;
    const ATTEMPTS: usize = 3;

    let path = "/data/svctest/std_frame_pool.bin";
    let _ = std::fs::remove_file(path);
    let chunk = vec![0x5Au8; 2048];
    let mut f = std::fs::File::create(path).expect("create frame-pool file");
    f.write_all(&chunk).expect("warm-up frame write");
    let mut drops = Vec::with_capacity(ATTEMPTS);
    for _ in 0..ATTEMPTS
    {
        let before = std::os::seraph::memmgr_pool_free_bytes().expect("memmgr pool query");
        for _ in 0..FRAME_WRITES
        {
            f.seek(SeekFrom::Start(0)).expect("seek to start");
            f.write_all(&chunk).expect("frame write");
        }
        let after = std::os::seraph::memmgr_pool_free_bytes().expect("memmgr pool query");
        drops.push(before.saturating_sub(after));
        if drops.last().is_some_and(|&d| d <= SLACK_BYTES)
        {
            break;
        }
    }
    drop(f);
    std::fs::remove_file(path).expect("cleanup");
    assert!(
        drops.iter().any(|&d| d <= SLACK_BYTES),
        "frame writes dropped memmgr's free pool past {SLACK_BYTES} bytes on every attempt: \
         {drops:?}"
    );
    std::os::seraph::log!("std_frame_write_pool phase passed (pool drops {drops:?})");
}

pub fn std_read_dir_phase(_: &Caps)
{
    let d = "/data/svctest/STD_RD";
    let _ = std::fs::remove_dir_all(d);
    std::fs::create_dir(d).expect("create_dir");
    std::fs::write("/data/svctest/STD_RD/A.BIN", b"a").expect("A.BIN");
    std::fs::write("/data/svctest/STD_RD/B.BIN", b"bb").expect("B.BIN");
    std::fs::create_dir("/data/svctest/STD_RD/SUB").expect("create SUB");

    let mut saw_a = false;
    let mut saw_b = false;
    let mut saw_sub = false;
    for entry in std::fs::read_dir(d).expect("read_dir")
    {
        let entry = entry.expect("dir entry");
        let name = entry.file_name();
        let name_str = name.to_str().expect("utf-8 name");
        assert_ne!(name_str, ".", "`.` must be filtered");
        assert_ne!(name_str, "..", "`..` must be filtered");
        let ft = entry.file_type().expect("file_type");
        match name_str
        {
            "A.BIN" =>
            {
                assert!(ft.is_file());
                let md = entry.metadata().expect("metadata A.BIN");
                assert_eq!(md.len(), 1);
                saw_a = true;
            }
            "B.BIN" =>
            {
                assert!(ft.is_file());
                let md = entry.metadata().expect("metadata B.BIN");
                assert_eq!(md.len(), 2);
                saw_b = true;
            }
            "SUB" =>
            {
                assert!(ft.is_dir());
                saw_sub = true;
            }
            other => panic!("unexpected entry {other:?}"),
        }
    }
    assert!(saw_a && saw_b && saw_sub, "missing entries");

    std::fs::remove_dir_all(d).expect("cleanup");
    std::os::seraph::log!("std_read_dir phase passed");
}

pub fn std_metadata_phase(_: &Caps)
{
    let f = "/data/svctest/std_md.bin";
    let _ = std::fs::remove_file(f);
    std::fs::write(f, b"meta").expect("seed");
    let md = std::fs::metadata(f).expect("metadata file");
    assert!(md.is_file());
    assert!(!md.is_dir());
    assert_eq!(md.len(), 4);

    let d = "/data/svctest";
    let md_d = std::fs::metadata(d).expect("metadata dir");
    assert!(md_d.is_dir());
    assert!(!md_d.is_file());

    assert!(std::fs::exists(f).expect("exists present"));
    assert!(!std::fs::exists("/data/svctest/__definitely_not_here__").expect("exists missing"));

    std::fs::remove_file(f).expect("cleanup");
    std::os::seraph::log!("std_metadata phase passed");
}

#[expect(
    clippy::suspicious_open_options,
    clippy::nonsensical_open_options,
    clippy::ineffective_open_options,
    reason = "the phase builds the invalid `OpenOptions` combinations these lints catch, to assert \
              std rejects each with `InvalidInput`"
)]
pub fn std_open_options_invalid_phase(_: &Caps)
{
    let path = "/data/svctest/__ooopt.bin";

    let no_mode = std::fs::OpenOptions::new().open(path);
    assert!(no_mode.is_err(), "open with no access mode must reject");
    assert_eq!(
        no_mode.unwrap_err().kind(),
        std::io::ErrorKind::InvalidInput
    );

    let append_truncate = std::fs::OpenOptions::new()
        .write(true)
        .append(true)
        .truncate(true)
        .open(path);
    assert!(append_truncate.is_err());
    assert_eq!(
        append_truncate.unwrap_err().kind(),
        std::io::ErrorKind::InvalidInput
    );

    let truncate_no_write = std::fs::OpenOptions::new()
        .read(true)
        .truncate(true)
        .open(path);
    assert!(truncate_no_write.is_err());
    assert_eq!(
        truncate_no_write.unwrap_err().kind(),
        std::io::ErrorKind::InvalidInput
    );

    let create_no_write = std::fs::OpenOptions::new()
        .read(true)
        .create(true)
        .open(path);
    assert!(create_no_write.is_err());
    assert_eq!(
        create_no_write.unwrap_err().kind(),
        std::io::ErrorKind::InvalidInput
    );

    let create_new_no_write = std::fs::OpenOptions::new()
        .read(true)
        .create_new(true)
        .open(path);
    assert!(create_new_no_write.is_err());
    assert_eq!(
        create_new_no_write.unwrap_err().kind(),
        std::io::ErrorKind::InvalidInput
    );

    std::os::seraph::log!("std_open_options_invalid phase passed");
}

/// Badge of the spawner's stop SEND on the fake fs endpoint.
const FAKE_FS_STOP_BADGE: u64 = 0x5709;

/// Size the fake fs reports for `/a` and `/b`: two pages, so a one-page
/// read at offset 0 takes the frame path.
const FAKE_FS_FILE_SIZE: u64 = 8192;

/// The std release handler's longest wait for a read of a released page:
/// the driver's cooperative-release window (fs-driver-protocol.md § Label 8).
const RELEASE_WINDOW: std::time::Duration = std::time::Duration::from_millis(100);

/// A driver release's reply label and round-trip time.
type ReleaseReply = (u64, std::time::Duration);

/// Badge offset of the fake fs's open caps: node `n`'s open is badged
/// `FAKE_FS_OPEN_BASE + n`.
const FAKE_FS_OPEN_BASE: u64 = 0x100;

/// What the fake fs saw of the `release-child`'s requests, and the replies
/// to the releases it sent while `/b`'s read was unanswered.
#[derive(Default)]
struct FakeFsReport
{
    /// Caps each node's `FS_OPEN` carried, by node (1 = `/a`, 2 = `/b`).
    open_caps: [Option<usize>; 2],
    /// Caps `/b`'s `FS_READ_MEMORY` carried.
    read_caps: Option<usize>,
    /// A release of `/b`'s mid-read cookie on `/a`'s release SEND.
    cross: Option<ReleaseReply>,
    /// Two releases of it on `/b`'s own release SEND.
    own: Option<(ReleaseReply, ReleaseReply)>,
    /// `FS_CLOSE`s each open received, by node: the child's exit hook sends
    /// one for each `File` it never drops.
    closes: [usize; 2],
}

/// The std client hands each `File`'s release SEND to the driver on its
/// `FS_OPEN` and none on `FS_READ_MEMORY`, and its release handler matches a
/// driver `FS_RELEASE_MEMORY` against the pages of the `File` whose SEND it
/// arrived on: it waits out a read of the cookie's page for at most the
/// driver's release window, waits once per cookie, and discards a read whose
/// copy that wait outlasted. The phase serves a fake fs root to a
/// `release-child`, which opens `/a` and `/b` and reads a page of `/b`.
/// While that `FS_READ_MEMORY` is still unanswered, so its cookie is
/// mid-read, the fake sends a release of the cookie on `/a`'s SEND, which
/// names a `File` that holds no such page and is acked at once, and then
/// two on `/b`'s. The child exits through `std::process::exit` holding both
/// `File`s, so its exit hook must send one `FS_CLOSE` on each open.
pub fn std_release_matched_by_open_phase(_: &Caps)
{
    use std::os::seraph::process::CommandExt;

    let ep = std::os::seraph::object_slab_retype(std::os::seraph::ENDPOINT_RETYPE_BYTES, |slab| {
        syscall::cap_create_endpoint(slab).ok()
    })
    .expect("std_release_matched_by_open: endpoint creation failed");
    let root = syscall::cap_derive(ep, syscall::RIGHTS_EP_SEND)
        .expect("std_release_matched_by_open: root SEND derive failed");
    let stop = syscall::cap_derive_badge(ep, syscall::RIGHTS_EP_SEND, FAKE_FS_STOP_BADGE)
        .expect("std_release_matched_by_open: stop SEND derive failed");

    let server = std::thread::Builder::new()
        .name("fake_fs".into())
        .spawn(move || fake_fs_serve(ep))
        .expect("std_release_matched_by_open: fake fs thread spawn failed");
    let status = std::process::Command::new("/tests/svctest")
        .arg(RELEASE_CHILD_ROLE)
        .namespace_cap(root)
        .status()
        .expect("std_release_matched_by_open: spawning release-child failed");

    let ipc_buf = std::os::seraph::current_ipc_buf();
    // SAFETY: `ipc_buf` is this thread's registered IPC buffer page.
    unsafe { ipc::ipc_call(stop, &ipc::IpcMessage::new(0), ipc_buf) }
        .expect("std_release_matched_by_open: stopping the fake fs failed");
    let report = server
        .join()
        .expect("std_release_matched_by_open: fake fs thread panicked");
    let _ = syscall::cap_delete(stop);
    let _ = syscall::cap_delete(ep);

    assert!(
        status.success(),
        "std_release_matched_by_open: release-child exited {status}; 2 = an open failed, \
         3 = /b's stalled read did not return Interrupted, 4 = /b's position moved"
    );
    assert_eq!(
        report.open_caps,
        [Some(1), Some(1)],
        "each File's FS_OPEN must carry its release SEND, and only it"
    );
    assert_eq!(
        report.read_caps,
        Some(0),
        "FS_READ_MEMORY must carry no cap (None: the fake saw no read of /b)"
    );
    let (cross, cross_rtt) = report
        .cross
        .expect("std_release_matched_by_open: the fake fs saw no read of /b");
    assert_eq!(
        cross,
        ipc::fs_labels::FS_RELEASE_ACK,
        "a release on /a's SEND names a File that holds no such page and must be acked"
    );
    assert!(
        cross_rtt < RELEASE_WINDOW,
        "a release on another File's SEND waited ({cross_rtt:?}) for /b's read"
    );
    assert_eq!(
        report.closes,
        [1, 1],
        "the exit hook must send one FS_CLOSE on each open File (counts for /a, /b)"
    );
    let ((first, first_rtt), (repeat, repeat_rtt)) = report
        .own
        .expect("std_release_matched_by_open: the fake fs sent no release on /b's SEND");
    assert_eq!(
        first,
        ipc::fs_errors::IO_ERROR,
        "a release of /b's mid-read cookie on /b's SEND must wait out the read and be \
         refused, not acked"
    );
    assert!(
        first_rtt >= RELEASE_WINDOW,
        "the release of a mid-read cookie returned after {first_rtt:?}, before the release \
         window"
    );
    assert_eq!(
        repeat,
        ipc::fs_errors::IO_ERROR,
        "a repeated release of a stalled cookie must be refused"
    );
    assert!(
        repeat_rtt < RELEASE_WINDOW,
        "a repeated release of a stalled cookie waited again ({repeat_rtt:?} after \
         {first_rtt:?})"
    );
    std::os::seraph::log!("std_release_matched_by_open phase passed");
}

/// `release-child`: open `/a` and `/b` from the fake fs root its spawner
/// delivered, then read a page of `/b`. The fake answers the read with a
/// frame only after a release of its cookie on `/b`'s SEND has waited out the
/// window, so the copy is stalled and must be discarded: the read returns
/// `Interrupted` and the position stays at 0. Exits through
/// `std::process::exit` before the `File`s drop, so the exit hook closes them.
/// Exit codes: 0 as expected, 2 an open failed, 3 `/b`'s read did not return
/// `Interrupted`, 4 `/b`'s position moved.
fn release_child_main() -> !
{
    use std::io::{ErrorKind, Read, Seek};

    let open = |path| std::fs::File::open(path).unwrap_or_else(|_| std::process::exit(2));
    let _a = open("/a");
    let mut b = open("/b");
    let mut buf = vec![0u8; 4096];
    if !matches!(b.read(&mut buf), Err(e) if e.kind() == ErrorKind::Interrupted)
    {
        std::process::exit(3);
    }
    if !matches!(b.stream_position(), Ok(0))
    {
        std::process::exit(4);
    }
    std::process::exit(0);
}

/// Serve the fake fs on `ep` until the spawner's stop message: each
/// `NS_LOOKUP` gets a file node SEND badged 1, 2, ... in order, and each
/// node's `FS_OPEN` an open SEND badged [`FAKE_FS_OPEN_BASE`] plus the node
/// and a liveness cap (a zero-rights copy of the endpoint, which nothing
/// sweeps), keeping the release SEND it carries. `/b`'s `FS_READ_MEMORY` is answered,
/// after one release of its cookie on `/a`'s release SEND and two on
/// `/b`'s, with a one-page frame (a read-only derivation of a page from
/// memmgr). Each open's `FS_CLOSE` is counted and answered. Anything else is
/// refused.
fn fake_fs_serve(ep: u64) -> FakeFsReport
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let mut next_badge = 1;
    let mut releases = [0u64; 2];
    let mut frame_page = 0;
    let mut report = FakeFsReport::default();
    loop
    {
        // SAFETY: `ipc_buf` is this thread's registered IPC buffer page.
        let msg = unsafe { ipc::ipc_recv(ep, ipc_buf) }.expect("fake fs: ipc_recv failed");
        let opcode = msg.label & 0xFFFF;
        let reply = if msg.badge == FAKE_FS_STOP_BADGE
        {
            ipc::IpcMessage::new(0)
        }
        else if opcode == ipc::ns_labels::NS_LOOKUP
        {
            // GRANT: the client's FS_OPEN on a node carries its release SEND
            // in caps[0].
            let node = syscall::cap_derive_badge(ep, syscall::RIGHTS_EP_SEND_GRANT, next_badge)
                .expect("fake fs: node SEND derive failed");
            next_badge = next_badge.checked_add(1).expect("fake fs: node badge");
            ipc::IpcMessage::builder(0)
                .word(0, namespace_protocol::NodeKind::File as u64)
                .word(1, FAKE_FS_FILE_SIZE)
                .cap(node)
                .build()
        }
        else if opcode == ipc::fs_labels::FS_OPEN && matches!(msg.badge, 1 | 2)
        {
            // The badge is 1 or 2, so the node's index is 0 or 1.
            let idx = usize::from(msg.badge == 2);
            *report.open_caps.get_mut(idx).expect("fake fs: node index") = Some(msg.caps().len());
            if let Some((&send, rest)) = msg.caps().split_first()
            {
                *releases.get_mut(idx).expect("fake fs: node index") = send;
                for &cap in rest
                {
                    let _ = syscall::cap_delete(cap);
                }
            }
            // The badge (1 or 2) lies below the base's bit, so the OR adds it.
            let open_badge = FAKE_FS_OPEN_BASE | msg.badge;
            let open = syscall::cap_derive_badge(ep, syscall::RIGHTS_EP_SEND, open_badge)
                .expect("fake fs: open SEND derive failed");
            let liveness = syscall::cap_derive(ep, 0).expect("fake fs: liveness cap derive failed");
            ipc::IpcMessage::builder(ipc::fs_errors::SUCCESS)
                .cap(open)
                .cap(liveness)
                .build()
        }
        else if opcode == ipc::fs_labels::FS_CLOSE
            && (msg.badge == FAKE_FS_OPEN_BASE + 1 || msg.badge == FAKE_FS_OPEN_BASE + 2)
        {
            // The badge is one of the two open badges, so its index is 0 or 1.
            let idx = usize::from(msg.badge == FAKE_FS_OPEN_BASE + 2);
            let closes = report.closes.get_mut(idx).expect("fake fs: open index");
            *closes = closes
                .checked_add(1)
                .expect("fake fs: close counter overflow");
            ipc::IpcMessage::new(ipc::fs_errors::SUCCESS)
        }
        else if opcode == ipc::fs_labels::FS_READ_MEMORY && msg.badge == FAKE_FS_OPEN_BASE + 2
        {
            report.read_caps = Some(msg.caps().len());
            for &cap in msg.caps()
            {
                let _ = syscall::cap_delete(cap);
            }
            let cookie = msg.word(1);
            report.cross = Some(release_once(releases[0], cookie));
            report.own = Some((
                release_once(releases[1], cookie),
                release_once(releases[1], cookie),
            ));
            frame_page = fake_fs_page();
            let frame = syscall::cap_derive(frame_page, syscall::RIGHTS_MEM_MAP)
                .expect("fake fs: frame derive failed");
            ipc::IpcMessage::builder(ipc::fs_errors::SUCCESS)
                .word(0, FAKE_FS_FRAME_BYTES)
                .word(1, cookie)
                .word(2, 0)
                .cap(frame)
                .build()
        }
        else
        {
            for &cap in msg.caps()
            {
                let _ = syscall::cap_delete(cap);
            }
            ipc::IpcMessage::new(ipc::fs_errors::IO_ERROR)
        };
        // SAFETY: `ipc_buf` is this thread's registered IPC buffer page.
        let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
        if msg.badge == FAKE_FS_STOP_BADGE
        {
            for cap in releases
            {
                let _ = syscall::cap_delete(cap);
            }
            let _ = syscall::cap_delete(frame_page);
            return report;
        }
    }
}

/// Bytes of the fake fs's frame for `/b`.
const FAKE_FS_FRAME_BYTES: u64 = 64;

/// One page from memmgr for the fake fs's frame.
fn fake_fs_page() -> u64
{
    let req = ipc::IpcMessage::builder(ipc::memmgr_labels::REQUEST_MEMORY_CAPS)
        .word(0, 1)
        .build();
    let ipc_buf = std::os::seraph::current_ipc_buf();
    // SAFETY: `ipc_buf` is this thread's registered IPC buffer page.
    let grant = unsafe {
        ipc::ipc_call(
            std::os::seraph::startup_info().memmgr_endpoint,
            &req,
            ipc_buf,
        )
    }
    .expect("fake fs: memmgr REQUEST_MEMORY_CAPS failed");
    *grant
        .caps()
        .first()
        .expect("fake fs: REQUEST_MEMORY_CAPS returned no cap")
}

/// Send `FS_RELEASE_MEMORY` for `cookie` on `release` once, from a helper
/// thread so the caller's unanswered `FS_READ_MEMORY` stays pending, and
/// return the reply's label (`u64::MAX` when the call fails) and round-trip
/// time.
fn release_once(release: u64, cookie: u64) -> ReleaseReply
{
    std::thread::spawn(move || {
        let ipc_buf = std::os::seraph::current_ipc_buf();
        let msg = ipc::IpcMessage::builder(ipc::fs_labels::FS_RELEASE_MEMORY)
            .word(0, cookie)
            .build();
        let start = std::time::Instant::now();
        // SAFETY: `ipc_buf` is this thread's registered IPC buffer page.
        let label = unsafe { ipc::ipc_call(release, &msg, ipc_buf) }.map_or(u64::MAX, |r| r.label);
        (label, start.elapsed())
    })
    .join()
    .expect("fake fs: release thread panicked")
}
