// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! fatfs / vfsd FS IPC surface (raw `FS_*` labels).

use std::os::seraph::startup_info;

use crate::bootstrap::Caps;
use crate::ipc_util::fs::{
    fs_create, fs_mkdir, fs_read_bytes, fs_remove, fs_rename, fs_write_inline, svctest_dir_cap,
};
use crate::ipc_util::ns::ns_lookup;
use crate::runner::Phase;

/// All FS-IPC phases EXCEPT `fs_open_relative_phase` (which installs
/// a process-global `current_dir_cap` and must therefore run after
/// every other phase that exercises the same fs).
pub fn phases_pre_relative() -> &'static [Phase]
{
    &[
        Phase {
            name: "fs_open",
            run: fs_open_phase,
        },
        Phase {
            name: "fs_release_on_close",
            run: fs_release_on_close_phase,
        },
        Phase {
            name: "fs_crossover_bench",
            run: fs_crossover_bench_phase,
        },
        Phase {
            name: "fs_rights_attenuation",
            run: fs_rights_attenuation_phase,
        },
        Phase {
            name: "fs_write",
            run: fs_write_phase,
        },
        Phase {
            name: "fs_create_remove",
            run: fs_create_remove_phase,
        },
        Phase {
            name: "fs_mkdir",
            run: fs_mkdir_phase,
        },
        Phase {
            name: "fs_rename",
            run: fs_rename_phase,
        },
        Phase {
            name: "fs_write_memory",
            run: fs_write_memory_phase,
        },
        Phase {
            name: "fs_write_cache_coherence",
            run: fs_write_cache_coherence_phase,
        },
        Phase {
            name: "fs_write_invariants",
            run: fs_write_invariants_phase,
        },
    ]
}

/// Singleton terminal entry: `fs_open_relative_phase` installs a
/// process-global `current_dir_cap` whose cap-derivation pressure on
/// TCG-emulated arches affects subsequent phases.
pub fn relative_only() -> &'static [Phase]
{
    &[Phase {
        name: "fs_open_relative",
        run: fs_open_relative_phase,
    }]
}

pub fn fs_open_phase(_: &Caps)
{
    use std::io::Read;

    // Read the bootstrap bundle header (the first 16 bytes carry
    // `SRPHBNDL` magic + u32 version + u32 entry count) to exercise the
    // vfsd/fatfs std::fs path on a small read without pulling tens of MiB
    // into a userspace Vec.
    let mut file = match std::fs::File::open("/esp/EFI/seraph/bootstrap.bundle")
    {
        Ok(f) => f,
        Err(e) => panic!("fs_open: open /esp/EFI/seraph/bootstrap.bundle failed: {e}"),
    };
    let mut header = [0u8; 16];
    let n = file
        .read(&mut header)
        .expect("fs_open: read(bundle header) failed");
    assert_eq!(n, 16, "fs_open: short read on bundle header (got {n})");
    assert_eq!(
        &header[0..8],
        b"SRPHBNDL",
        "fs_open: bootstrap.bundle magic mismatch (got {:?})",
        &header[0..8]
    );
    std::os::seraph::log!("fs_open: read bundle header magic+version+entry_count");

    match std::fs::File::open("/esp/no_such_directory/missing.txt")
    {
        Ok(_) => panic!("fs_open: nonexistent path unexpectedly opened"),
        Err(e) => assert_eq!(
            e.kind(),
            std::io::ErrorKind::NotFound,
            "fs_open: nonexistent path expected NotFound, got {e:?}"
        ),
    }
    std::os::seraph::log!("fs_open: nonexistent path → NotFound");
    std::os::seraph::log!("fs_open phase passed");
}

pub fn fs_release_on_close_phase(_: &Caps)
{
    use std::io::Read;

    let path = "/data/svctest/large.bin";

    for iter in 0..8u32
    {
        let mut f = std::fs::File::open(path)
            .unwrap_or_else(|e| panic!("fs_release_on_close: open #{iter} failed: {e}"));

        let mut buf = vec![0u8; 4096];
        let n = f
            .read(&mut buf)
            .unwrap_or_else(|e| panic!("fs_release_on_close: read #{iter} failed: {e}"));
        assert!(
            n > 0,
            "fs_release_on_close: iter #{iter} read returned 0 bytes"
        );

        if iter == 0
        {
            let prefix: &[u8] = b"PAGE_00_";
            assert!(
                buf.starts_with(prefix),
                "fs_release_on_close: first-page content mismatch (got {:?})",
                core::str::from_utf8(&buf[..prefix.len()]).unwrap_or("<non-utf8>"),
            );
        }
    }

    std::os::seraph::log!("fs_release_on_close phase passed (8 cycles)");
}

pub fn fs_crossover_bench_phase(_: &Caps)
{
    use std::process::Command;

    let mut child = Command::new("/programs/fsbench")
        .spawn()
        .expect("spawn /programs/fsbench failed");
    let status = child.wait().expect("fsbench wait failed");
    assert!(status.success(), "fsbench did not exit cleanly: {status}");
    std::os::seraph::log!("fs_crossover_bench phase passed");
}

pub fn fs_rights_attenuation_phase(_: &Caps)
{
    use namespace_protocol::rights;

    let system_root_cap = std::os::seraph::root_dir_cap();
    assert!(
        system_root_cap != 0,
        "fs_rights_attenuation: root_dir_cap() returned 0"
    );

    let info = startup_info();
    #[allow(clippy::cast_ptr_alignment)]
    let ipc_buf = info.ipc_buffer.cast::<u64>();

    let (data_cap, _kind, _) = ns_lookup(system_root_cap, b"data", 0xFFFF, ipc_buf)
        .expect("fs_rights_attenuation: NS_LOOKUP /data failed");

    let stat_only = u64::from(rights::STAT);
    let (stat_cap, _kind, _) = ns_lookup(data_cap, b"test.txt", stat_only, ipc_buf)
        .expect("fs_rights_attenuation: NS_LOOKUP /data/test.txt (STAT) failed");

    let read_msg = ipc::IpcMessage::builder(ipc::fs_labels::FS_READ)
        .word(0, 0)
        .word(1, 4)
        .build();
    // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
    let read_reply = unsafe { ipc::ipc_call(stat_cap, &read_msg, ipc_buf) }
        .expect("fs_rights_attenuation: FS_READ ipc_call failed");
    assert_eq!(
        read_reply.label,
        ipc::fs_errors::PERMISSION_DENIED,
        "fs_rights_attenuation: FS_READ on STAT-only cap returned {} (expected PERMISSION_DENIED={})",
        read_reply.label,
        ipc::fs_errors::PERMISSION_DENIED,
    );
    std::os::seraph::log!("fs_rights_attenuation: FS_READ rejected on STAT-only cap");

    let memory_msg = ipc::IpcMessage::builder(ipc::fs_labels::FS_READ_MEMORY)
        .word(0, 0)
        .word(1, 1)
        .build();
    // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
    let memory_reply = unsafe { ipc::ipc_call(stat_cap, &memory_msg, ipc_buf) }
        .expect("fs_rights_attenuation: FS_READ_MEMORY ipc_call failed");
    assert_eq!(
        memory_reply.label,
        ipc::fs_errors::PERMISSION_DENIED,
        "fs_rights_attenuation: FS_READ_MEMORY on STAT-only cap returned {} (expected PERMISSION_DENIED={})",
        memory_reply.label,
        ipc::fs_errors::PERMISSION_DENIED,
    );
    std::os::seraph::log!("fs_rights_attenuation: FS_READ_MEMORY rejected on STAT-only cap");

    let unknown_msg = ipc::IpcMessage::new(0x9999);
    // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
    let unknown_reply = unsafe { ipc::ipc_call(stat_cap, &unknown_msg, ipc_buf) }
        .expect("fs_rights_attenuation: unknown-opcode ipc_call failed");
    assert_eq!(
        unknown_reply.label,
        ipc::fs_errors::UNKNOWN_OPCODE,
        "fs_rights_attenuation: unknown opcode 0x9999 returned {} (expected UNKNOWN_OPCODE={})",
        unknown_reply.label,
        ipc::fs_errors::UNKNOWN_OPCODE,
    );
    std::os::seraph::log!("fs_rights_attenuation: unknown badged label rejected");

    let _ = syscall::cap_delete(stat_cap);

    let (empty_cap, _kind, _) = ns_lookup(data_cap, b"test.txt", 0, ipc_buf)
        .expect("fs_rights_attenuation: NS_LOOKUP /data/test.txt (empty) failed");
    let release_msg = ipc::IpcMessage::builder(ipc::fs_labels::FS_RELEASE_MEMORY)
        .word(0, 1)
        .build();
    // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
    let release_reply = unsafe { ipc::ipc_call(empty_cap, &release_msg, ipc_buf) }
        .expect("fs_rights_attenuation: FS_RELEASE_MEMORY ipc_call failed");
    assert_eq!(
        release_reply.label,
        ipc::fs_errors::PERMISSION_DENIED,
        "fs_rights_attenuation: FS_RELEASE_MEMORY on empty-rights cap returned {} (expected \
         PERMISSION_DENIED={})",
        release_reply.label,
        ipc::fs_errors::PERMISSION_DENIED,
    );
    std::os::seraph::log!("fs_rights_attenuation: FS_RELEASE_MEMORY rejected on empty-rights cap");
    let _ = syscall::cap_delete(empty_cap);

    let (full_cap, _kind, _) = ns_lookup(data_cap, b"test.txt", 0xFFFF, ipc_buf)
        .expect("fs_rights_attenuation: NS_LOOKUP /data/test.txt (full) failed");

    let read_msg = ipc::IpcMessage::builder(ipc::fs_labels::FS_READ)
        .word(0, 0)
        .word(1, 8)
        .build();
    // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
    let read_reply = unsafe { ipc::ipc_call(full_cap, &read_msg, ipc_buf) }
        .expect("fs_rights_attenuation: FS_READ (full) ipc_call failed");
    assert_eq!(
        read_reply.label,
        ipc::fs_errors::SUCCESS,
        "fs_rights_attenuation: FS_READ on full-rights cap returned {}",
        read_reply.label,
    );
    let bytes_read = read_reply.word(0);
    assert!(
        bytes_read > 0,
        "fs_rights_attenuation: FS_READ returned 0 bytes on full-rights cap"
    );

    let _ = syscall::cap_delete(full_cap);
    let _ = syscall::cap_delete(data_cap);
    std::os::seraph::log!("fs_rights_attenuation phase passed");
}

pub fn fs_write_phase(_: &Caps)
{
    let info = startup_info();
    #[allow(clippy::cast_ptr_alignment)]
    let ipc_buf = info.ipc_buffer.cast::<u64>();
    let svctest = svctest_dir_cap(ipc_buf);

    let name: &[u8] = b"wrt.bin";
    let _ = fs_remove(svctest, name, ipc_buf);

    let (file_cap, kind) = fs_create(svctest, name, ipc_buf).expect("FS_CREATE wrt.bin failed");
    assert_eq!(kind, namespace_protocol::NodeKind::File as u64);

    let payload: &[u8] = b"hello write path\n";
    let n = fs_write_inline(file_cap, 0, payload, ipc_buf).expect("FS_WRITE wrt.bin failed");
    assert_eq!(n, payload.len() as u64, "FS_WRITE short");

    let _ = syscall::cap_delete(file_cap);
    let (rd_cap, _kind, size_hint) =
        ns_lookup(svctest, name, 0xFFFF, ipc_buf).expect("NS_LOOKUP wrt.bin failed");
    assert_eq!(size_hint, payload.len() as u64, "post-write size hint");

    let got =
        fs_read_bytes(rd_cap, 0, payload.len() as u64, ipc_buf).expect("FS_READ wrt.bin failed");
    assert_eq!(&got[..], payload, "round-trip bytes mismatch");

    let _ = syscall::cap_delete(rd_cap);
    let _ = fs_remove(svctest, name, ipc_buf);
    let _ = syscall::cap_delete(svctest);
    std::os::seraph::log!("fs_write phase passed");
}

pub fn fs_create_remove_phase(_: &Caps)
{
    let info = startup_info();
    #[allow(clippy::cast_ptr_alignment)]
    let ipc_buf = info.ipc_buffer.cast::<u64>();
    let svctest = svctest_dir_cap(ipc_buf);

    let name: &[u8] = b"crt.bin";
    let _ = fs_remove(svctest, name, ipc_buf);

    let (cap, _) = fs_create(svctest, name, ipc_buf).expect("FS_CREATE first failed");
    let _ = syscall::cap_delete(cap);

    let dup = fs_create(svctest, name, ipc_buf);
    assert!(
        dup.is_err(),
        "duplicate FS_CREATE on existing name should fail"
    );

    fs_remove(svctest, name, ipc_buf).expect("FS_REMOVE crt.bin failed");

    let gone = ns_lookup(svctest, name, 0xFFFF, ipc_buf);
    assert!(
        gone.is_err(),
        "NS_LOOKUP after FS_REMOVE should fail; got {gone:?}"
    );

    let _ = syscall::cap_delete(svctest);
    std::os::seraph::log!("fs_create_remove phase passed");
}

pub fn fs_mkdir_phase(_: &Caps)
{
    let info = startup_info();
    #[allow(clippy::cast_ptr_alignment)]
    let ipc_buf = info.ipc_buffer.cast::<u64>();
    let svctest = svctest_dir_cap(ipc_buf);

    let dname: &[u8] = b"mkd";
    let _ = fs_remove(svctest, dname, ipc_buf);

    let (dir_cap, kind) = fs_mkdir(svctest, dname, ipc_buf).expect("FS_MKDIR mkd failed");
    assert_eq!(kind, namespace_protocol::NodeKind::Dir as u64);

    let entry0 = crate::ipc_util::ns::ns_readdir(dir_cap, 0, ipc_buf).expect("NS_READDIR 0");
    assert!(entry0.is_some(), "newly-mkdir'd directory must have ./..");

    let _ = syscall::cap_delete(dir_cap);
    fs_remove(svctest, dname, ipc_buf).expect("FS_REMOVE mkd (empty) failed");

    let (dir_cap2, _) = fs_mkdir(svctest, dname, ipc_buf).expect("FS_MKDIR mkd retry");
    let (inner, _) = fs_create(dir_cap2, b"in.bin", ipc_buf).expect("FS_CREATE inside dir failed");
    let _ = syscall::cap_delete(inner);
    let err = fs_remove(svctest, dname, ipc_buf).expect_err("FS_REMOVE non-empty should fail");
    assert_eq!(
        err,
        ipc::fs_errors::NOT_EMPTY,
        "FS_REMOVE non-empty dir code"
    );
    fs_remove(dir_cap2, b"in.bin", ipc_buf).expect("cleanup file in mkd");
    fs_remove(svctest, dname, ipc_buf).expect("FS_REMOVE mkd (now empty)");
    let _ = syscall::cap_delete(dir_cap2);
    let _ = syscall::cap_delete(svctest);
    std::os::seraph::log!("fs_mkdir phase passed");
}

pub fn fs_rename_phase(_: &Caps)
{
    let info = startup_info();
    #[allow(clippy::cast_ptr_alignment)]
    let ipc_buf = info.ipc_buffer.cast::<u64>();
    let svctest = svctest_dir_cap(ipc_buf);

    let src: &[u8] = b"ren_a.bin";
    let dst: &[u8] = b"ren_b.bin";
    let _ = fs_remove(svctest, src, ipc_buf);
    let _ = fs_remove(svctest, dst, ipc_buf);

    let (cap, _) = fs_create(svctest, src, ipc_buf).expect("FS_CREATE ren_a failed");
    let payload: &[u8] = b"renaming";
    fs_write_inline(cap, 0, payload, ipc_buf).expect("FS_WRITE ren_a failed");
    let _ = syscall::cap_delete(cap);

    fs_rename(svctest, src, dst, ipc_buf).expect("FS_RENAME failed");

    assert!(
        ns_lookup(svctest, src, 0xFFFF, ipc_buf).is_err(),
        "src must be gone after rename"
    );
    let (dst_cap, _kind, dst_size) =
        ns_lookup(svctest, dst, 0xFFFF, ipc_buf).expect("NS_LOOKUP dst after rename");
    assert_eq!(dst_size, payload.len() as u64);
    let got = fs_read_bytes(dst_cap, 0, payload.len() as u64, ipc_buf).expect("read dst");
    assert_eq!(&got[..], payload, "rename preserved contents");

    let _ = syscall::cap_delete(dst_cap);
    fs_remove(svctest, dst, ipc_buf).expect("cleanup dst");
    let _ = syscall::cap_delete(svctest);
    std::os::seraph::log!("fs_rename phase passed");
}

#[allow(clippy::too_many_lines, clippy::items_after_statements)]
pub fn fs_write_memory_phase(_: &Caps)
{
    use std::io::Read;

    use syscall::MAP_WRITABLE;

    const WRITE_LEN: usize = 2048;

    let info = startup_info();
    #[allow(clippy::cast_ptr_alignment)]
    let ipc_buf = info.ipc_buffer.cast::<u64>();
    let svctest = svctest_dir_cap(ipc_buf);

    let name: &[u8] = b"wrtf.bin";
    let _ = fs_remove(svctest, name, ipc_buf);

    let (file_cap, _) = fs_create(svctest, name, ipc_buf).expect("FS_CREATE wrtf failed");

    let req = ipc::IpcMessage::builder(ipc::memmgr_labels::REQUEST_MEMORY_CAPS)
        .word(0, 1)
        .build();
    // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(info.memmgr_endpoint, &req, ipc_buf) }
        .expect("memmgr REQUEST_MEMORY_CAPS ipc_call failed");
    assert_eq!(
        reply.label,
        ipc::memmgr_errors::SUCCESS,
        "REQUEST_MEMORY_CAPS status"
    );
    assert_eq!(reply.word(0), 1);
    let memory_cap = *reply
        .caps()
        .first()
        .expect("REQUEST_MEMORY_CAPS returned no cap");

    let range = std::os::seraph::reserve_pages(1).expect("reserve_pages");
    let va = range.va_start();
    syscall::mem_map(memory_cap, info.self_aspace, va, 0, 1, MAP_WRITABLE)
        .expect("mem_map memory cap failed");

    // SAFETY: va just mapped MAP_WRITABLE for one page; WRITE_LEN ≤ PAGE_SIZE.
    unsafe {
        for i in 0..WRITE_LEN
        {
            *((va + i as u64) as *mut u8) = u8::try_from(i & 0xFF).unwrap_or(0);
        }
    }

    let msg = ipc::IpcMessage::builder(ipc::fs_labels::FS_WRITE_MEMORY)
        .word(0, 0)
        .word(1, WRITE_LEN as u64)
        .word(2, 0)
        .cap(memory_cap)
        .build();
    // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
    let reply =
        unsafe { ipc::ipc_call(file_cap, &msg, ipc_buf) }.expect("FS_WRITE_MEMORY ipc_call failed");
    assert_eq!(
        reply.label,
        ipc::fs_errors::SUCCESS,
        "FS_WRITE_MEMORY status {} (expected SUCCESS={})",
        reply.label,
        ipc::fs_errors::SUCCESS
    );
    assert_eq!(reply.word(0), WRITE_LEN as u64);
    let returned = *reply
        .caps()
        .first()
        .expect("FS_WRITE_MEMORY returned no cap");
    let _ = syscall::cap_delete(returned);

    let _ = syscall::mem_unmap(info.self_aspace, va, 1);
    let _ = syscall::cap_delete(file_cap);

    let mut f = std::fs::File::open("/data/svctest/wrtf.bin").expect("open wrtf.bin");
    let mut buf = vec![0u8; WRITE_LEN];
    let mut total = 0;
    while total < WRITE_LEN
    {
        let n = f.read(&mut buf[total..]).expect("read wrtf.bin");
        assert!(n > 0, "short read at offset {total}");
        total += n;
    }
    for (i, &b) in buf.iter().enumerate()
    {
        assert_eq!(b, u8::try_from(i & 0xFF).unwrap_or(0), "byte {i} mismatch");
    }
    drop(f);

    fs_remove(svctest, name, ipc_buf).expect("cleanup wrtf");
    let _ = syscall::cap_delete(svctest);
    std::os::seraph::log!("fs_write_memory phase passed");
}

pub fn fs_write_cache_coherence_phase(_: &Caps)
{
    let info = startup_info();
    #[allow(clippy::cast_ptr_alignment)]
    let ipc_buf = info.ipc_buffer.cast::<u64>();
    let svctest = svctest_dir_cap(ipc_buf);

    let name: &[u8] = b"coh.bin";
    let _ = fs_remove(svctest, name, ipc_buf);

    let (cap, _) = fs_create(svctest, name, ipc_buf).expect("create coh");
    fs_write_inline(cap, 0, b"AAAAAAAA", ipc_buf).expect("write 1");
    let r1 = fs_read_bytes(cap, 0, 8, ipc_buf).expect("read 1");
    assert_eq!(&r1[..], b"AAAAAAAA");
    fs_write_inline(cap, 0, b"BBBBBBBB", ipc_buf).expect("write 2");
    let r2 = fs_read_bytes(cap, 0, 8, ipc_buf).expect("read 2");
    assert_eq!(
        &r2[..],
        b"BBBBBBBB",
        "read after write returned stale bytes"
    );

    let _ = syscall::cap_delete(cap);
    fs_remove(svctest, name, ipc_buf).expect("cleanup coh");
    let _ = syscall::cap_delete(svctest);
    std::os::seraph::log!("fs_write_cache_coherence phase passed");
}

#[allow(clippy::too_many_lines)]
pub fn fs_write_invariants_phase(_: &Caps)
{
    use namespace_protocol::rights;

    const CLUSTER: usize = 4096;
    const INLINE_CHUNK: usize = 504;

    let info = startup_info();
    #[allow(clippy::cast_ptr_alignment)]
    let ipc_buf = info.ipc_buffer.cast::<u64>();

    // ── (1) rights attenuation on FS_CREATE child cap ──────────────
    {
        let svctest_full = svctest_dir_cap(ipc_buf);
        let scratch_name: &[u8] = b"inv_rights.bin";
        let _ = fs_remove(svctest_full, scratch_name, ipc_buf);

        let root = std::os::seraph::root_dir_cap();
        let restricted_rights = u64::from(rights::LOOKUP | rights::MUTATE_DIR);
        let (data_cap, _, _) =
            ns_lookup(root, b"data", 0xFFFF, ipc_buf).expect("ns_lookup /data for attenuated walk");
        let (parent_attenuated, _, _) = ns_lookup(data_cap, b"svctest", restricted_rights, ipc_buf)
            .expect("ns_lookup /data/svctest attenuated");
        let _ = syscall::cap_delete(data_cap);

        let (child_cap, _) = fs_create(parent_attenuated, scratch_name, ipc_buf)
            .expect("FS_CREATE through attenuated parent should succeed");

        let write_err = fs_write_inline(child_cap, 0, b"x", ipc_buf)
            .expect_err("FS_WRITE on rights-attenuated child cap must reject");
        assert_eq!(
            write_err,
            ipc::fs_errors::PERMISSION_DENIED,
            "expected PERMISSION_DENIED; got {write_err}"
        );

        let _ = syscall::cap_delete(child_cap);
        let _ = syscall::cap_delete(parent_attenuated);
        let _ = fs_remove(svctest_full, scratch_name, ipc_buf);
        let _ = syscall::cap_delete(svctest_full);
        std::os::seraph::log!("fs_write_invariants: rights attenuation ok");
    }

    // ── (2) NodeTable dedupe must not alias distinct empty files ───
    {
        let svctest = svctest_dir_cap(ipc_buf);
        let a: &[u8] = b"inv_aa.bin";
        let b: &[u8] = b"inv_bb.bin";
        let _ = fs_remove(svctest, a, ipc_buf);
        let _ = fs_remove(svctest, b, ipc_buf);

        let (cap_a, _) = fs_create(svctest, a, ipc_buf).expect("create inv_aa");
        let (cap_b, _) = fs_create(svctest, b, ipc_buf).expect("create inv_bb");

        fs_write_inline(cap_a, 0, b"AAAA", ipc_buf).expect("write to inv_aa");

        let r_b = fs_read_bytes(cap_b, 0, 8, ipc_buf).unwrap_or_default();
        assert!(
            r_b.is_empty() || r_b.iter().all(|&x| x == 0),
            "inv_bb returned non-zero bytes through held cap after sibling write: {r_b:?}"
        );

        let (cap_b_fresh, _, b_size) =
            ns_lookup(svctest, b, 0xFFFF, ipc_buf).expect("lookup inv_bb");
        assert_eq!(
            b_size, 0,
            "inv_bb on-disk size hint was perturbed by inv_aa write"
        );

        let _ = syscall::cap_delete(cap_a);
        let _ = syscall::cap_delete(cap_b);
        let _ = syscall::cap_delete(cap_b_fresh);
        let _ = fs_remove(svctest, a, ipc_buf);
        let _ = fs_remove(svctest, b, ipc_buf);
        let _ = syscall::cap_delete(svctest);
        std::os::seraph::log!("fs_write_invariants: empty-file dedupe ok");
    }

    // ── (3) FAT chain past EOC must not corrupt prior cluster ──────
    {
        let svctest = svctest_dir_cap(ipc_buf);
        let name: &[u8] = b"inv_chain.bin";
        let _ = fs_remove(svctest, name, ipc_buf);

        let (cap, _) = fs_create(svctest, name, ipc_buf).expect("create inv_chain");

        let pattern_a = vec![0xA5u8; CLUSTER];
        let pattern_b = vec![0x5Au8; CLUSTER];
        let write_pattern = |cap: u32, base: usize, src: &[u8]| {
            let mut written = 0usize;
            while written < src.len()
            {
                let n = (src.len() - written).min(INLINE_CHUNK);
                fs_write_inline(
                    cap,
                    (base + written) as u64,
                    &src[written..written + n],
                    ipc_buf,
                )
                .expect("inline write chunk");
                written += n;
            }
        };
        write_pattern(cap, 0, &pattern_a);
        write_pattern(cap, CLUSTER, &pattern_b);

        let _ = syscall::cap_delete(cap);
        let (cap, _, size) = ns_lookup(svctest, name, 0xFFFF, ipc_buf).expect("lookup inv_chain");
        assert_eq!(size, 2 * CLUSTER as u64, "expected 8 KiB after AB writes");

        fs_write_inline(cap, (4 * CLUSTER) as u64, b"Z", ipc_buf).expect("write Z past EOC");

        let _ = syscall::cap_delete(cap);
        let (cap, _, _) = ns_lookup(svctest, name, 0xFFFF, ipc_buf).expect("lookup inv_chain 2");

        let got_b = fs_read_bytes(cap, CLUSTER as u64, INLINE_CHUNK as u64, ipc_buf)
            .expect("read pattern B");
        assert_eq!(
            got_b.len(),
            INLINE_CHUNK,
            "short read at offset {CLUSTER} (chain corruption?)"
        );
        assert!(
            got_b.iter().all(|&b| b == 0x5A),
            "pattern B corrupted at offset {CLUSTER} — FAT chain rewritten"
        );

        let got_a = fs_read_bytes(cap, 0, INLINE_CHUNK as u64, ipc_buf).expect("read pattern A");
        assert!(got_a.iter().all(|&b| b == 0xA5), "pattern A corrupted");
        let got_z = fs_read_bytes(cap, (4 * CLUSTER) as u64, 1, ipc_buf).expect("read Z");
        assert_eq!(got_z.first().copied(), Some(b'Z'));

        let _ = syscall::cap_delete(cap);
        let _ = fs_remove(svctest, name, ipc_buf);
        let _ = syscall::cap_delete(svctest);
        std::os::seraph::log!("fs_write_invariants: FAT chain past EOC ok");
    }

    std::os::seraph::log!("fs_write_invariants phase passed");
}

pub fn fs_open_relative_phase(_: &Caps)
{
    use std::fs::File;
    use std::io::Read;

    assert_ne!(
        std::os::seraph::current_dir_cap(),
        0,
        "fs_open_relative_phase pre-condition: startup cwd cap should still be present",
    );
    let pre_err =
        std::env::current_dir().expect_err("std::env::current_dir() pre-set should still fail");
    assert_eq!(pre_err.kind(), std::io::ErrorKind::Unsupported);

    std::os::seraph::set_current_dir("/data").expect("set_current_dir(/data) failed");
    assert_ne!(std::os::seraph::current_dir_cap(), 0);

    assert_eq!(
        std::env::current_dir().expect("std::env::current_dir after cap-native set"),
        std::path::PathBuf::from("/data"),
        "std::env::current_dir disagrees with cap-native set_current_dir",
    );

    std::env::set_current_dir("/data").expect("std::env::set_current_dir(/data) failed");
    assert_ne!(std::os::seraph::current_dir_cap(), 0);
    assert_eq!(
        std::env::current_dir().expect("std::env::current_dir after std-env set"),
        std::path::PathBuf::from("/data"),
    );

    let mut f = File::open("test.txt").expect("relative open after set_current_dir failed");
    let mut buf = String::new();
    f.read_to_string(&mut buf).expect("relative read failed");
    assert!(!buf.is_empty(), "relative open returned empty file");

    let abs_meta = File::open("/data/test.txt")
        .expect("absolute open after set_current_dir failed")
        .metadata()
        .expect("absolute metadata failed");
    assert_eq!(
        abs_meta.len(),
        buf.len() as u64,
        "absolute and relative opens disagree on size",
    );

    std::os::seraph::log!("fs_open_relative phase passed");
}
