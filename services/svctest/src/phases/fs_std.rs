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
            name: "std_release_matched_by_cookie",
            run: std_release_matched_by_cookie_phase,
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

#[allow(
    clippy::suspicious_open_options,
    clippy::nonsensical_open_options,
    clippy::ineffective_open_options,
    clippy::needless_update
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

/// The std release handler matches a driver `FS_RELEASE_MEMORY` by cookie
/// across every open `File`, waits out a read of the cookie's page for at
/// most the driver's release window, waits once per cookie, and discards a
/// read whose copy that wait outlasted. The phase
/// serves a fake fs root to a `release-child`, which opens `/a` and `/b` and
/// reads a page of each. While `/b`'s `FS_READ_MEMORY` is still unanswered,
/// so its cookie is mid-read, the fake sends a release of that cookie on the
/// release SEND `/a`'s first read delivered, and then sends it again. Two
/// distinct nodes stand in for the driver's per-node SEND sharing, under
/// which a release can arrive on another `File`'s badge. The fake refuses
/// `/a`'s first read, which a driver may do before it records the SEND, so
/// `/a`'s second read must carry a release SEND again.
pub fn std_release_matched_by_cookie_phase(_: &Caps)
{
    use std::os::seraph::process::CommandExt;

    let ep =
        std::os::seraph::object_slab_retype(88, |slab| syscall::cap_create_endpoint(slab).ok())
            .expect("std_release_matched_by_cookie: endpoint creation failed");
    let root = syscall::cap_derive(ep, syscall::RIGHTS_EP_SEND)
        .expect("std_release_matched_by_cookie: root SEND derive failed");
    let stop = syscall::cap_derive_badge(ep, syscall::RIGHTS_EP_SEND, FAKE_FS_STOP_BADGE)
        .expect("std_release_matched_by_cookie: stop SEND derive failed");

    let server = std::thread::Builder::new()
        .name("fake_fs".into())
        .spawn(move || fake_fs_serve(ep))
        .expect("std_release_matched_by_cookie: fake fs thread spawn failed");
    let status = std::process::Command::new("/tests/svctest")
        .arg(RELEASE_CHILD_ROLE)
        .namespace_cap(root)
        .status()
        .expect("std_release_matched_by_cookie: spawning release-child failed");

    let ipc_buf = std::os::seraph::current_ipc_buf();
    // SAFETY: `ipc_buf` is this thread's registered IPC buffer page.
    unsafe { ipc::ipc_call(stop, &ipc::IpcMessage::new(0), ipc_buf) }
        .expect("std_release_matched_by_cookie: stopping the fake fs failed");
    let (probe, a_retry_send) = server
        .join()
        .expect("std_release_matched_by_cookie: fake fs thread panicked");
    let _ = syscall::cap_delete(stop);
    let _ = syscall::cap_delete(ep);

    assert!(
        status.success(),
        "std_release_matched_by_cookie: release-child exited {status}; 1 = /a's read \
         succeeded, 2 = an open failed, 3 = /b's stalled read did not return Interrupted, \
         4 = /b's position moved"
    );
    assert_eq!(
        a_retry_send,
        Some(true),
        "/a's read after a refused first read must carry a release SEND again (None: the \
         fake saw no second read of /a)"
    );
    let ((first, first_rtt), (repeat, repeat_rtt)) =
        probe.expect("std_release_matched_by_cookie: the fake fs saw no read of /b");
    assert_eq!(
        first,
        ipc::fs_errors::IO_ERROR,
        "a release of /b's mid-read cookie on /a's SEND must wait out the read and be \
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
    std::os::seraph::log!("std_release_matched_by_cookie phase passed");
}

/// `release-child`: open `/a` and `/b` from the fake fs root its spawner
/// delivered, then read a page of `/a` twice and of `/b` once. The fake
/// refuses both of `/a`'s reads and answers `/b`'s with a frame only after a
/// release of its cookie has waited out the window, so `/b`'s copy is
/// stalled and must be discarded:
/// the read returns `Interrupted` and the position stays at 0. Exits before
/// the `File`s drop. Exit codes: 0 as expected, 1 a read of `/a` succeeded,
/// 2 an open failed, 3 `/b`'s read did not return `Interrupted`, 4 `/b`'s
/// position moved.
fn release_child_main() -> !
{
    use std::io::{ErrorKind, Read, Seek};

    let open = |path| std::fs::File::open(path).unwrap_or_else(|_| std::process::exit(2));
    let mut a = open("/a");
    let mut b = open("/b");
    let mut buf = vec![0u8; 4096];
    if a.read(&mut buf).is_ok() || a.read(&mut buf).is_ok()
    {
        std::process::exit(1);
    }
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
/// `NS_LOOKUP` gets a file node SEND badged 1, 2, ... in order. Node 1's
/// first `FS_READ_MEMORY` hands over its release SEND and is refused with
/// `IO_ERROR`, as is its second, whose release SEND, if any, is deleted.
/// Node 2's is answered, after two releases of its cookie on node 1's
/// release SEND, with a one-page frame (a read-only derivation of a page
/// from memmgr). Anything else is refused. Returns the two releases'
/// replies, and whether node 1's second read carried a release SEND (`None`
/// when there was no second read).
fn fake_fs_serve(ep: u32) -> (Option<(ReleaseReply, ReleaseReply)>, Option<bool>)
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let mut next_badge = 1;
    let mut a_release = 0;
    let mut a_retry_send = None;
    let mut frame_page = 0;
    let mut probe = None;
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
            // GRANT: the client's FS_READ_MEMORY on a node carries a copy of
            // its release SEND in caps[0] until a request carrying one
            // succeeds; the fake keeps node 1's first copy and deletes the
            // others.
            let node = syscall::cap_derive_badge(ep, syscall::RIGHTS_EP_SEND_GRANT, next_badge)
                .expect("fake fs: node SEND derive failed");
            next_badge += 1;
            ipc::IpcMessage::builder(0)
                .word(0, namespace_protocol::NodeKind::File as u64)
                .word(1, FAKE_FS_FILE_SIZE)
                .cap(node)
                .build()
        }
        else if opcode == ipc::fs_labels::FS_READ_MEMORY
        {
            let release = msg.caps().first().copied().unwrap_or(0);
            match msg.badge
            {
                1 if a_release == 0 =>
                {
                    a_release = release;
                    ipc::IpcMessage::new(ipc::fs_errors::IO_ERROR)
                }
                1 =>
                {
                    if a_retry_send.is_none()
                    {
                        a_retry_send = Some(release != 0);
                    }
                    let _ = syscall::cap_delete(release);
                    ipc::IpcMessage::new(ipc::fs_errors::IO_ERROR)
                }
                2 =>
                {
                    let _ = syscall::cap_delete(release);
                    let cookie = msg.word(1);
                    probe = Some(release_twice(a_release, cookie));
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
                _ => ipc::IpcMessage::new(ipc::fs_errors::IO_ERROR),
            }
        }
        else
        {
            ipc::IpcMessage::new(ipc::fs_errors::IO_ERROR)
        };
        // SAFETY: `ipc_buf` is this thread's registered IPC buffer page.
        let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
        if msg.badge == FAKE_FS_STOP_BADGE
        {
            let _ = syscall::cap_delete(a_release);
            let _ = syscall::cap_delete(frame_page);
            return (probe, a_retry_send);
        }
    }
}

/// Bytes of the fake fs's frame for `/b`.
const FAKE_FS_FRAME_BYTES: u64 = 64;

/// One page from memmgr for the fake fs's frame.
fn fake_fs_page() -> u32
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

/// Send `FS_RELEASE_MEMORY` for `cookie` on `release` twice, from a helper
/// thread so the caller's unanswered `FS_READ_MEMORY` stays pending, and
/// return each reply's label and round-trip time.
fn release_twice(release: u32, cookie: u64) -> (ReleaseReply, ReleaseReply)
{
    std::thread::spawn(move || {
        let ipc_buf = std::os::seraph::current_ipc_buf();
        let msg = ipc::IpcMessage::builder(ipc::fs_labels::FS_RELEASE_MEMORY)
            .word(0, cookie)
            .build();
        let send = || {
            let start = std::time::Instant::now();
            // SAFETY: `ipc_buf` is this thread's registered IPC buffer page.
            let reply = unsafe { ipc::ipc_call(release, &msg, ipc_buf) }
                .expect("fake fs: FS_RELEASE_MEMORY ipc_call failed");
            (reply.label, start.elapsed())
        };
        let first = send();
        (first, send())
    })
    .join()
    .expect("fake fs: release thread panicked")
}
