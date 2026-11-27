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
            name: "std_frame_write_past_deadline",
            run: std_frame_write_past_deadline_phase,
        },
        Phase {
            name: "std_frame_write_interrupted",
            run: std_frame_write_interrupted_phase,
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

/// Role token for [`write_child_main`].
const WRITE_CHILD_ROLE: &str = "write-child";

/// Child-mode dispatch for argv tokens this module owns. The matching arm
/// exits through `std::process::exit`; on a miss control returns to the
/// caller.
pub fn reentry_main(role: &str)
{
    if role == RELEASE_CHILD_ROLE
    {
        release_child_main();
    }
    if role == WRITE_CHILD_ROLE
    {
        write_child_main();
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

/// Frame-path writes (over 504 bytes) [`std_frame_write_pool_phase`] and
/// [`std_frame_write_past_deadline_phase`] make.
const FRAME_WRITES: u64 = 64;

/// Recheck rounds [`measure_frame_writes`] gives the charge to return to
/// its baseline, or below it, after the `File` dropped.
const FRAME_POOL_RECHECKS: u32 = 16;

/// Bytes of one frame-path write: past the inline `FS_WRITE` threshold, within
/// one page.
const FRAME_CHUNK_LEN: usize = 2048;

/// What a file [`measure_frame_writes`] wrote must hold once its `File`
/// dropped.
#[derive(Clone, Copy)]
enum ReadBack
{
    /// The last measured write's bytes: every write reached the file.
    LastWrite,
    /// The warm-up's bytes: no measured write was sent.
    WarmUp,
}

/// svctest's charge, in pages, and its write-frame memmgr calls
/// (`std::os::seraph::fs::write_frame_memmgr_calls`) around
/// [`FRAME_WRITES`] frame-path writes on one `File`.
struct FrameCharge
{
    /// The charge before the `File` opened.
    base: u64,
    /// The charge right after the writes, with the `File` still open.
    written: u64,
    /// The charge after the `File` dropped and the rechecks.
    now: u64,
    /// The recheck rounds taken.
    rechecks: u32,
    /// The memmgr calls made for write frames by the writes.
    calls_written: u64,
    /// The memmgr calls made for write frames by the writes and the drop.
    calls_dropped: u64,
}

/// Make [`FRAME_WRITES`] frame-path writes of one [`FRAME_CHUNK_LEN`] chunk
/// to the start of a file at `path` with `write`, through one `File` opened
/// after a warm-up `File` wrote the file once and dropped, and measure
/// svctest's charge and write-frame memmgr calls around them as
/// [`std_frame_write_pool_phase`] describes; the file is removed again.
/// After the drop the file must hold the last measured write's bytes when
/// `read_back` is [`ReadBack::LastWrite`], else the warm-up's.
fn measure_frame_writes(
    path: &str,
    read_back: ReadBack,
    mut write: impl FnMut(&mut std::fs::File, &[u8]),
) -> FrameCharge
{
    use std::io::{Seek, SeekFrom, Write};

    let calls = std::os::seraph::fs::write_frame_memmgr_calls;
    let _ = std::fs::remove_file(path);
    let chunk = vec![0x5Au8; FRAME_CHUNK_LEN];
    {
        let mut warm = std::fs::File::create(path).expect("create frame-pool file");
        warm.write_all(&chunk).expect("warm-up frame write");
    }
    let recheck = || {
        let (grant, region_id) = super::memmgr::try_request_contiguous(1)
            .unwrap_or_else(|label| panic!("REQUEST_MEMORY_CAPS status {label:#x}"));
        super::memmgr::release_grant(grant, region_id);
    };
    recheck();
    let (base, _, _) = super::memmgr::memory_usage();
    let start = calls();
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .expect("reopen frame-pool file");
    // Each write's bytes differ from the one before, so a reused frame that
    // still lent an earlier write's bytes leaves the file other than the last.
    let mut last = chunk.clone();
    for i in 0..FRAME_WRITES
    {
        last.fill(0x60u8.wrapping_add(u8::try_from(i & 0xF).unwrap_or(0)));
        f.seek(SeekFrom::Start(0)).expect("seek to start");
        write(&mut f, &last);
    }
    let (written, _, _) = super::memmgr::memory_usage();
    let calls_written = calls().wrapping_sub(start);
    drop(f);
    let calls_dropped = calls().wrapping_sub(start);
    let (mut now, _, _) = super::memmgr::memory_usage();
    let mut rechecks = 0;
    for round in 1..=FRAME_POOL_RECHECKS
    {
        if now <= base
        {
            break;
        }
        recheck();
        rechecks = round;
        (now, _, _) = super::memmgr::memory_usage();
    }
    assert_eq!(
        std::fs::read(path).expect("read back frame-pool file"),
        match read_back
        {
            ReadBack::LastWrite => last,
            ReadBack::WarmUp => chunk,
        },
        "the file must hold the last frame-path write's bytes, or the warm-up's when no write \
         was sent"
    );
    std::fs::remove_file(path).expect("cleanup");
    FrameCharge {
        base,
        written,
        now,
        rechecks,
        calls_written,
        calls_dropped,
    }
}

/// A `File` takes one write frame from memmgr at its first frame-path write,
/// keeps it across the later ones, and returns it when it drops: the
/// [`FRAME_WRITES`] writes make one write-frame memmgr call
/// (`REQUEST_MEMORY_CAPS`), the drop one more (`RELEASE_MEMORY_CAPS`), and
/// the drop leaves svctest's own charge where it was before the `File` opened.
///
/// The measure is svctest's own budget charge (`QUERY_MEMORY_USAGE`
/// `data[0]`), which no other process's allocation raises: memmgr charges the
/// source page to svctest when it grants it and uncharges the run only when
/// the run rejoins the free pool (services/memmgr/docs/ipc-interface.md
/// § Label 10).
/// The writes go to one offset, so the fs driver's cache does not grow, and a
/// warm-up `File` that writes once and drops, and a first recheck (below),
/// before the baseline settle this process's heap, stack and `CSpace` slots,
/// the page tables the frame's mapping funds, and the driver's cache page. A
/// frame the drop failed to return leaves the charge a page up.
///
/// A released run that some mapping or capability still reaches waits on
/// memmgr's deferred list, charged, until a recheck pools it, and memmgr
/// rechecks before each `RELEASE_MEMORY_CAPS`
/// (services/memmgr/docs/memory-pool.md § Reclamation). After the drop the
/// phase takes and releases a one-page grant of its own, which pools at once,
/// up to [`FRAME_POOL_RECHECKS`] times, until the charge is back at its
/// baseline. The check fails only a charge above the baseline: an earlier
/// released run of svctest's that a recheck pools during the measure (the
/// warm-up's frame among them) lowers the charge below the baseline, which no
/// leak does.
pub fn std_frame_write_pool_phase(_: &Caps)
{
    use std::io::Write;

    let FrameCharge {
        base,
        written,
        now,
        rechecks,
        calls_written,
        calls_dropped,
    } = measure_frame_writes(
        "/data/svctest/std_frame_pool.bin",
        ReadBack::LastWrite,
        |f, chunk| {
            f.write_all(chunk).expect("frame write");
        },
    );
    assert_eq!(
        (calls_written, calls_dropped),
        (1, 2),
        "std_frame_write_pool: {FRAME_WRITES} frame writes on one File made {calls_written} \
         write-frame memmgr calls and its drop {} more; one frame must serve them all",
        calls_dropped.wrapping_sub(calls_written)
    );
    assert!(
        now <= base,
        "std_frame_write_pool: charge {now} pages after {FRAME_WRITES} frame writes, the \
         File's drop and {rechecks} rechecks, above the baseline {base} (right after the \
         writes: {written} pages)"
    );
    std::os::seraph::log!(
        "std_frame_write_pool phase passed (charge {base} pages, {written} after the writes, \
         {rechecks} rechecks; write-frame memmgr calls {calls_written} for the writes, \
         {calls_dropped} with the drop)"
    );
}

/// A frame-path write under a call deadline that has passed
/// (`std::os::seraph::with_call_deadline`) fails `TimedOut` without sending
/// `FS_WRITE_MEMORY`, and leaves its frame idle and the `File`'s: the
/// [`FRAME_WRITES`] refused writes make one write-frame memmgr call, the drop
/// returns the frame, and the charge returns to its baseline as in
/// [`std_frame_write_pool_phase`]. A frame kept as though the driver might
/// still copy from it would leave the File without one, and each later write
/// would take another.
pub fn std_frame_write_past_deadline_phase(_: &Caps)
{
    use std::io::Write;

    let FrameCharge {
        base,
        written,
        now,
        rechecks,
        calls_written,
        calls_dropped,
    } = measure_frame_writes(
        "/data/svctest/std_frame_deadline.bin",
        ReadBack::WarmUp,
        |f, chunk| {
            let wrote =
                std::os::seraph::with_call_deadline(std::time::Instant::now(), || f.write(chunk));
            let err = wrote.expect_err("a frame write under a passed call deadline was sent");
            assert_eq!(
                err.kind(),
                std::io::ErrorKind::TimedOut,
                "std_frame_write_past_deadline: the write failed {err}"
            );
        },
    );
    assert_eq!(
        (calls_written, calls_dropped),
        (1, 2),
        "std_frame_write_past_deadline: {FRAME_WRITES} writes past the deadline made \
         {calls_written} write-frame memmgr calls, and with the drop {calls_dropped}"
    );
    assert!(
        now <= base,
        "std_frame_write_past_deadline: charge {now} pages after {FRAME_WRITES} writes past the \
         deadline, the File's drop and {rechecks} rechecks, above the baseline {base} (right \
         after the writes: {written} pages)"
    );
    std::os::seraph::log!(
        "std_frame_write_past_deadline phase passed (charge {base} pages, {written} after the \
         writes, {rechecks} rechecks)"
    );
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

/// Badge of the session cap the fake fs mints for the `release-child`'s
/// `FS_SESSION`.
const FAKE_FS_SESSION_BADGE: u64 = 0x200;

/// What the fake fs saw of the `release-child`'s requests, and the replies
/// to the releases it sent while `/b`'s read was unanswered.
#[derive(Default)]
struct FakeFsReport
{
    /// `FS_SESSION`s the fake fs answered.
    sessions: usize,
    /// Caps each node's `FS_OPEN` carried, by node (1 = `/a`, 2 = `/b`).
    open_caps: [Option<usize>; 2],
    /// Whether each node's `FS_OPEN` carried in `caps[0]` a copy of the
    /// session cap with `SEND` alone, by node.
    open_sessions: [Option<bool>; 2],
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

/// The std client starts one session with a driver and opens each `File`
/// in it, handing a `SEND`-only copy of the session cap and the `File`'s
/// release SEND to the driver on its `FS_OPEN` and none on
/// `FS_READ_MEMORY`, and its release handler matches a
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

    let ep = std::os::seraph::create_endpoint()
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
        report.sessions, 1,
        "std must start one session with the fake fs and open both Files in it"
    );
    assert_eq!(
        report.open_caps,
        [Some(2), Some(2)],
        "each File's FS_OPEN must carry its session cap and its release SEND, and only them"
    );
    assert_eq!(
        report.open_sessions,
        [Some(true), Some(true)],
        "each File's FS_OPEN must carry a SEND-only copy of the session cap"
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

/// The fake fs's `FS_SESSION` on a node: count it, delete the carried
/// handle, and reply with a session cap badged [`FAKE_FS_SESSION_BADGE`]
/// with `IDENTIFY` and a zero-rights liveness cap.
fn fake_fs_session(ep: u64, msg: &ipc::IpcMessage, report: &mut FakeFsReport) -> ipc::IpcMessage
{
    report.sessions = report
        .sessions
        .checked_add(1)
        .expect("fake fs: session counter overflow");
    for &cap in msg.caps()
    {
        let _ = syscall::cap_delete(cap);
    }
    let session = syscall::cap_derive_badge(
        ep,
        syscall::RIGHTS_EP_SEND | syscall::RIGHTS_EP_IDENTIFY,
        FAKE_FS_SESSION_BADGE,
    )
    .expect("fake fs: session cap derive failed");
    let liveness = syscall::cap_derive(ep, 0).expect("fake fs: liveness cap derive failed");
    ipc::IpcMessage::builder(ipc::fs_errors::SUCCESS)
        .cap(session)
        .cap(liveness)
        .build()
}

/// The fake fs's `FS_OPEN` on node 1 or 2 (the badge): record what it
/// carried, keep its release SEND (`caps[1]`) in `releases`, delete the
/// rest, and reply with the node's open cap.
fn fake_fs_open(
    ep: u64,
    msg: &ipc::IpcMessage,
    report: &mut FakeFsReport,
    releases: &mut [u64; 2],
) -> ipc::IpcMessage
{
    // The badge is 1 or 2, so the node's index is 0 or 1.
    let idx = usize::from(msg.badge == 2);
    let carried = msg.caps();
    *report.open_caps.get_mut(idx).expect("fake fs: node index") = Some(carried.len());
    let in_session = carried.first().is_some_and(|&cap| {
        syscall::endpoint_badge(ep, cap) == Ok(FAKE_FS_SESSION_BADGE)
            && syscall::cap_info(cap, syscall::CAP_INFO_TAG_RIGHTS)
                .is_ok_and(|tag| tag & 0xFFFF_FFFF == syscall::RIGHTS_EP_SEND)
    });
    *report
        .open_sessions
        .get_mut(idx)
        .expect("fake fs: node index") = Some(in_session);
    for (i, &cap) in carried.iter().enumerate()
    {
        if i == 1
        {
            *releases.get_mut(idx).expect("fake fs: node index") = cap;
        }
        else
        {
            let _ = syscall::cap_delete(cap);
        }
    }
    // The badge (1 or 2) lies below the base's bit, so the OR adds it.
    let open_badge = FAKE_FS_OPEN_BASE | msg.badge;
    // SEND_GRANT, as fs-driver-protocol.md § Label 18 mints it: a request on
    // the open that carries a cap (`FS_WRITE_MEMORY`) needs GRANT.
    let open = syscall::cap_derive_badge(ep, syscall::RIGHTS_EP_SEND_GRANT, open_badge)
        .expect("fake fs: open SEND derive failed");
    ipc::IpcMessage::builder(ipc::fs_errors::SUCCESS)
        .cap(open)
        .build()
}

/// Serve the fake fs on `ep` until the spawner's stop message: each
/// `NS_LOOKUP` gets a file node SEND badged 1, 2, ... in order, each node's
/// `FS_SESSION` a session cap badged [`FAKE_FS_SESSION_BADGE`] with
/// `IDENTIFY` and a liveness cap (a zero-rights copy of the endpoint, which
/// nothing sweeps), and each node's `FS_OPEN` an open `SEND_GRANT` badged
/// [`FAKE_FS_OPEN_BASE`] plus the node, keeping the release SEND it carries
/// in `caps[1]`. `/b`'s `FS_READ_MEMORY` is answered,
/// after one release of its cookie on `/a`'s release SEND and two on
/// `/b`'s, with a one-page frame (a read-only derivation of a page from
/// memmgr). Each open's `FS_CLOSE` is counted and answered. Anything else is
/// refused.
#[expect(
    clippy::large_stack_frames,
    reason = "the `reply` and the builder temporaries of its seven reply arms (`IpcMessage`s, 568 B \
              each); on the stack of the `fake_fs` thread, 64 KiB at the least"
)]
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
            // GRANT: the client's FS_SESSION on a node carries its charge
            // handle, and its FS_OPEN its session cap and release SEND.
            let node = syscall::cap_derive_badge(ep, syscall::RIGHTS_EP_SEND_GRANT, next_badge)
                .expect("fake fs: node SEND derive failed");
            next_badge = next_badge.checked_add(1).expect("fake fs: node badge");
            ipc::IpcMessage::builder(0)
                .word(0, namespace_protocol::NodeKind::File as u64)
                .word(1, FAKE_FS_FILE_SIZE)
                // Every path opened here (`/a`, `/b`) has one component.
                .word(2, 1)
                .cap(node)
                .build()
        }
        else if opcode == ipc::fs_labels::FS_SESSION && matches!(msg.badge, 1 | 2)
        {
            fake_fs_session(ep, &msg, &mut report)
        }
        else if opcode == ipc::fs_labels::FS_OPEN && matches!(msg.badge, 1 | 2)
        {
            fake_fs_open(ep, &msg, &mut report, &mut releases)
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

/// The index, from 0, of the `write-child`'s `FS_WRITE_MEMORY` the fake fs
/// leaves unanswered.
const STALLED_WRITE: usize = 2;

/// What the fake fs of [`std_frame_write_interrupted_phase`] saw of the
/// `write-child`'s writes.
#[derive(Default)]
struct FakeWriteReport
{
    /// Caps each `FS_WRITE_MEMORY` carried, in order.
    write_caps: Vec<usize>,
    /// Whether the derivation the first write lent, which the fake kept, was
    /// gone by the second write.
    first_revoked: Option<bool>,
    /// `FS_CLOSE`s the open received.
    closes: usize,
    /// Whether each `FS_WRITE_MEMORY`'s page held that write's bytes
    /// ([`write_fill`]) and zeros after them, in order.
    contents: Vec<bool>,
}

/// The byte the `write-child`'s `index`-th write (from 0) fills its chunk
/// with: a different one per write, so a page that still held an earlier
/// write's bytes is told apart.
fn write_fill(index: usize) -> u8
{
    0xA0u8.wrapping_add(u8::try_from(index & 0xF).unwrap_or(0))
}

/// Map the page `cap` names read-only into svctest's own address space and
/// report whether it holds [`FRAME_CHUNK_LEN`] bytes of `fill` and zeros
/// after them, as the fs driver would read a write's chunk from it.
fn lent_page_holds(cap: u64, fill: u8) -> bool
{
    let aspace = std::os::seraph::startup_info().self_aspace;
    let range = std::os::seraph::reserve_pages(1).expect("fake fs: reserve_pages failed");
    let va = range.va_start();
    // SAFETY: `range` is a fresh page reservation from the per-process arena,
    // owned here: VA no Rust object or IPC page occupies.
    let mapped =
        unsafe { std::os::seraph::mem_map_funded(cap, aspace, va, 0, 1, syscall::MAP_READ) }
            .is_ok();
    let holds = mapped && {
        // SAFETY: `va` was just mapped readable for one page, which nothing
        // writes while this shared view of it lives: its owner is blocked in
        // the call this fake has not answered.
        let page = unsafe {
            core::slice::from_raw_parts(
                va as *const u8,
                usize::try_from(syscall_abi::PAGE_SIZE).unwrap_or(0),
            )
        };
        let (chunk, tail) = page.split_at(FRAME_CHUNK_LEN);
        chunk.iter().all(|&b| b == fill) && tail.iter().all(|&b| b == 0)
    };
    if mapped
    {
        // SAFETY: `va` is the page mapped above; the slice into it is dead.
        let _ = unsafe { syscall::mem_unmap(aspace, va, 1) };
    }
    std::os::seraph::unreserve_pages(range);
    holds
}

/// A `File` keeps its write frame across writes, lends each write a fresh
/// derivation revoked once the reply settles it, and abandons the frame when
/// a call ends after the driver received it, since the driver may still copy
/// from it. The phase serves a fake fs root to a `write-child`, which writes
/// `/a` four times through the frame path. The fake keeps the first write's
/// derivation and finds it revoked at the second; it leaves the third
/// unanswered and receives again, which releases the caller with
/// `Interrupted` (core/kernel/docs/ipc-internals.md,
/// `release_unreplied_caller`), after the driver received it; the
/// child checks its write-frame memmgr calls after each step
/// ([`write_child_main`]). The fake also maps each write's page and checks
/// that it holds that write's bytes, the reused frame's and the fresh one's.
pub fn std_frame_write_interrupted_phase(_: &Caps)
{
    use std::os::seraph::process::CommandExt;

    let ep = std::os::seraph::create_endpoint()
        .expect("std_frame_write_interrupted: endpoint creation failed");
    let root = syscall::cap_derive(ep, syscall::RIGHTS_EP_SEND)
        .expect("std_frame_write_interrupted: root SEND derive failed");
    let stop = syscall::cap_derive_badge(ep, syscall::RIGHTS_EP_SEND, FAKE_FS_STOP_BADGE)
        .expect("std_frame_write_interrupted: stop SEND derive failed");

    let server = std::thread::Builder::new()
        .name("fake_write_fs".into())
        .spawn(move || fake_write_fs_serve(ep))
        .expect("std_frame_write_interrupted: fake fs thread spawn failed");
    let status = std::process::Command::new("/tests/svctest")
        .arg(WRITE_CHILD_ROLE)
        .namespace_cap(root)
        .status()
        .expect("std_frame_write_interrupted: spawning write-child failed");

    let ipc_buf = std::os::seraph::current_ipc_buf();
    // SAFETY: `ipc_buf` is this thread's registered IPC buffer page.
    unsafe { ipc::ipc_call(stop, &ipc::IpcMessage::new(0), ipc_buf) }
        .expect("std_frame_write_interrupted: stopping the fake fs failed");
    let report = server
        .join()
        .expect("std_frame_write_interrupted: fake fs thread panicked");
    let _ = syscall::cap_delete(stop);
    let _ = syscall::cap_delete(ep);

    assert!(
        status.success(),
        "std_frame_write_interrupted: write-child exited {status}; 2 = the open failed, \
         3/5/9 = a write the fake answered failed, 7 = the unanswered write succeeded, \
         4/6/8/10/11 = its write-frame memmgr calls after the 1st, 2nd, 3rd and 4th write and \
         the drop were not 1, 1, 1, 2, 3"
    );
    assert_eq!(
        report.write_caps,
        [1, 1, 1, 1],
        "each FS_WRITE_MEMORY must carry one derivation of the frame"
    );
    assert_eq!(
        report.first_revoked,
        Some(true),
        "the derivation a write lent must be revoked once its reply settles it"
    );
    assert_eq!(
        report.contents,
        [true, true, true, true],
        "each FS_WRITE_MEMORY's page must hold that write's bytes and zeros after them"
    );
    assert_eq!(report.closes, 1, "the File's drop must send one FS_CLOSE");
    std::os::seraph::log!("std_frame_write_interrupted phase passed");
}

/// `write-child`: open `/a` for writing from the fake fs root its spawner
/// delivered and make four frame-path writes, checking its write-frame
/// memmgr calls (`std::os::seraph::fs::write_frame_memmgr_calls`) after each:
/// the first takes a frame (1), the second reuses it (1), the third, which the
/// fake leaves unanswered, fails and abandons it (1), the fourth takes a fresh
/// one (2), and the drop returns only that one (3). Exit codes: 0 as expected,
/// 2 the open failed, 3, 5 and 9 an answered write failed, 7 the unanswered
/// write succeeded, 4, 6, 8, 10 and 11 a count after the 1st, 2nd, 3rd and
/// 4th write and the drop was wrong.
fn write_child_main() -> !
{
    use std::io::Write;

    let calls = std::os::seraph::fs::write_frame_memmgr_calls;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .open("/a")
        .unwrap_or_else(|_| std::process::exit(2));
    let start = calls();
    let made = || calls().wrapping_sub(start);
    let wrote = |f: &mut std::fs::File, index: usize| {
        let chunk = vec![write_fill(index); FRAME_CHUNK_LEN];
        matches!(f.write(&chunk), Ok(n) if n == FRAME_CHUNK_LEN)
    };
    // Per write: whether the fake answers it, the exit code of a write that
    // went otherwise, the calls wanted after it, and the exit code of a count
    // that differs.
    let steps: [(bool, i32, u64, i32); 4] = [
        (true, 3, 1, 4),
        (true, 5, 1, 6),
        (false, 7, 1, 8),
        (true, 9, 2, 10),
    ];
    for (index, (answered, write_code, want, count_code)) in steps.into_iter().enumerate()
    {
        if wrote(&mut f, index) != answered
        {
            std::process::exit(write_code);
        }
        if made() != want
        {
            std::process::exit(count_code);
        }
    }
    drop(f);
    if made() != 3
    {
        std::process::exit(11);
    }
    std::process::exit(0);
}

/// The fake fs's `FS_WRITE_MEMORY` on `/a`'s open, the `index`-th from 0:
/// record the caps it carried, keep the first write's derivation in `kept`
/// and, at the second, record whether it is gone. Returns the reply, or
/// `None` for the write at [`STALLED_WRITE`], which is left unanswered.
fn fake_write_memory(
    msg: &ipc::IpcMessage,
    report: &mut FakeWriteReport,
    kept: &mut u64,
) -> Option<ipc::IpcMessage>
{
    let index = report.write_caps.len();
    report.write_caps.push(msg.caps().len());
    report.contents.push(
        msg.caps()
            .first()
            .is_some_and(|&cap| lent_page_holds(cap, write_fill(index))),
    );
    for (i, &cap) in msg.caps().iter().enumerate()
    {
        if index == 0 && i == 0
        {
            *kept = cap;
        }
        else
        {
            let _ = syscall::cap_delete(cap);
        }
    }
    if index == 1
    {
        report.first_revoked =
            Some(syscall::cap_info(*kept, syscall::CAP_INFO_TAG_RIGHTS).is_err());
        let _ = syscall::cap_delete(*kept);
        *kept = 0;
    }
    (index != STALLED_WRITE).then(|| {
        ipc::IpcMessage::builder(ipc::fs_errors::SUCCESS)
            .word(0, msg.word(1))
            .build()
    })
}

/// Serve the fake fs of [`std_frame_write_interrupted_phase`] on `ep` until
/// the spawner's stop message: `/a`'s lookup, session and open as
/// [`fake_fs_serve`] answers them, each `FS_WRITE_MEMORY` on its open as
/// [`fake_write_memory`] says, and its `FS_CLOSE`, counted. An unanswered
/// write's caller is released by the next receive. Anything else is refused.
fn fake_write_fs_serve(ep: u64) -> FakeWriteReport
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let mut releases = [0u64; 2];
    let mut opens = FakeFsReport::default();
    let mut kept = 0;
    let mut report = FakeWriteReport::default();
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
            let node = syscall::cap_derive_badge(ep, syscall::RIGHTS_EP_SEND_GRANT, 1)
                .expect("fake fs: node SEND derive failed");
            ipc::IpcMessage::builder(0)
                .word(0, namespace_protocol::NodeKind::File as u64)
                .word(1, FAKE_FS_FILE_SIZE)
                // The one path opened here, `/a`, has one component.
                .word(2, 1)
                .cap(node)
                .build()
        }
        else if opcode == ipc::fs_labels::FS_SESSION && msg.badge == 1
        {
            fake_fs_session(ep, &msg, &mut opens)
        }
        else if opcode == ipc::fs_labels::FS_OPEN && msg.badge == 1
        {
            fake_fs_open(ep, &msg, &mut opens, &mut releases)
        }
        else if opcode == ipc::fs_labels::FS_CLOSE && msg.badge == FAKE_FS_OPEN_BASE + 1
        {
            report.closes = report
                .closes
                .checked_add(1)
                .expect("fake fs: close counter overflow");
            ipc::IpcMessage::new(ipc::fs_errors::SUCCESS)
        }
        else if opcode == ipc::fs_labels::FS_WRITE_MEMORY && msg.badge == FAKE_FS_OPEN_BASE + 1
        {
            match fake_write_memory(&msg, &mut report, &mut kept)
            {
                Some(reply) => reply,
                None => continue,
            }
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
            let _ = syscall::cap_delete(kept);
            return report;
        }
    }
}
