// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

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
            name: "std_remove_dir_all",
            run: std_remove_dir_all_phase,
        },
        Phase {
            name: "std_bulk_write",
            run: std_bulk_write_phase,
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
    ]
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
