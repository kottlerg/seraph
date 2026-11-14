// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/vfsd.rs

//! vfsd service surface: the `MOUNT` label's authority gate and its
//! rejection paths (services/vfsd/docs/vfs-ipc-interface.md § Label 10),
//! and the swap-partition hand-out (§ Label 14).
//!
//! svctest holds three SENDs on vfsd's service endpoint, all seed-only:
//! `vfsd.mount`, badged `MOUNT_AUTHORITY`, `vfsd.deny`, badged with no
//! verb bit, and `vfsd.swap`, badged `SWAP_AUTHORITY`. Every `MOUNT` case
//! leaves the mount table as it found it: the deny case and the rejection
//! cases install nothing and spawn no driver, which each checks through the
//! replies and the mounted filesystems afterwards.

use std::os::seraph::startup_info;

use crate::bootstrap::Caps;
use crate::runner::Phase;

pub fn phases() -> &'static [Phase]
{
    &[
        Phase {
            name: "vfsd_mount_deny",
            run: mount_deny_phase,
        },
        Phase {
            name: "vfsd_mount_rejects_mounted_paths",
            run: mount_rejects_mounted_paths_phase,
        },
        Phase {
            name: "vfsd_mount_short_path",
            run: mount_short_path_phase,
        },
        Phase {
            name: "vfsd_swap_partition",
            run: swap_partition_phase,
        },
    ]
}

/// `MountRole` wire bytes (vfs-ipc-interface.md § Label 10).
const ROLE_ROOT: u64 = 0;
const ROLE_DATA: u64 = 1;

/// Repeated rejected mounts: vfsd checks the mount point before it
/// registers a partition or spawns a driver, so every round must reply
/// `TABLE_FULL`; a rejection that started a spawn first would show as
/// `SPAWN_FAILED` (or another error) in a later round, or as a mount that
/// no longer answers.
const REJECT_ROUNDS: usize = 6;

/// A `MOUNT` request for `role` at `path`, with `path_len` as the stated
/// path length (normally `path.len()`).
fn mount_request(role: u64, path: &[u8], path_len: u64) -> ipc::IpcMessage
{
    ipc::IpcMessage::builder(ipc::vfsd_labels::MOUNT)
        .word(0, role)
        .word(1, path_len)
        .bytes(2, path)
        .build()
}

/// Send `msg` on `cap` and return the reply label, asserting it carries no
/// cap (none of these cases may yield a mount's namespace SEND).
fn mount_reply(cap: u64, msg: &ipc::IpcMessage, what: &str) -> u64
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(cap, msg, ipc_buf) }
        .unwrap_or_else(|_| panic!("{what}: MOUNT ipc_call failed"));
    assert!(
        reply.caps().is_empty(),
        "{what}: refused MOUNT carried a cap"
    );
    reply.label
}

/// The filesystems vfsd mounted at startup still answer: the root and the
/// ESP list, and the data tree resolves.
fn assert_mounts_answer(what: &str)
{
    for dir in ["/", "/esp"]
    {
        assert!(
            std::fs::read_dir(dir).is_ok(),
            "{what}: read_dir({dir}) failed after the refused MOUNTs"
        );
    }
    assert!(
        std::fs::metadata("/data").is_ok_and(|m| m.is_dir()),
        "{what}: /data no longer resolves as a directory"
    );
}

/// `MOUNT` on `vfsd.deny`, whose badge lacks `MOUNT_AUTHORITY`, replies
/// `UNAUTHORIZED` without mounting: the request names an unmounted path
/// for the data partition, which a granted `MOUNT` would install.
fn mount_deny_phase(caps: &Caps)
{
    const FRESH: &str = "/svctest-mount-deny";
    assert_ne!(caps.vfsd_deny, 0, "vfsd_mount_deny: no vfsd.deny seed");
    let msg = mount_request(ROLE_DATA, FRESH.as_bytes(), FRESH.len() as u64);
    let label = mount_reply(caps.vfsd_deny, &msg, "vfsd_mount_deny");
    assert_eq!(
        label,
        ipc::vfsd_errors::UNAUTHORIZED,
        "MOUNT without MOUNT_AUTHORITY must reply UNAUTHORIZED (got {label:#x})"
    );
    assert!(
        std::fs::metadata(FRESH).is_err(),
        "vfsd_mount_deny: {FRESH} exists after a refused MOUNT"
    );
    assert_mounts_answer("vfsd_mount_deny");
    std::os::seraph::log!("vfsd mount-deny phase passed (UNAUTHORIZED, nothing mounted)");
}

/// `MOUNT` of the root role at `/` and of the data role at `/esp`, both
/// already mount points, replies `TABLE_FULL` in every one of
/// `REJECT_ROUNDS` rounds, and the mounted filesystems still answer
/// afterwards.
fn mount_rejects_mounted_paths_phase(caps: &Caps)
{
    assert_ne!(caps.vfsd_mount, 0, "vfsd_mount_rejects: no vfsd.mount seed");
    for round in 0..REJECT_ROUNDS
    {
        for (role, path) in [(ROLE_ROOT, "/"), (ROLE_DATA, "/esp")]
        {
            let msg = mount_request(role, path.as_bytes(), path.len() as u64);
            let label = mount_reply(caps.vfsd_mount, &msg, "vfsd_mount_rejects");
            assert_eq!(
                label,
                ipc::vfsd_errors::TABLE_FULL,
                "MOUNT at mounted {path} (round {round}) must reply TABLE_FULL (got {label:#x})"
            );
        }
    }
    assert_mounts_answer("vfsd_mount_rejects");
    std::os::seraph::log!(
        "vfsd mounted-path phase passed ({REJECT_ROUNDS} rounds of TABLE_FULL, mounts answer)"
    );
}

/// `MOUNT` whose stated path length exceeds the path bytes the data words
/// carry replies `NOT_FOUND` (an invalid path length) instead of mounting a
/// NUL-padded name.
fn mount_short_path_phase(caps: &Caps)
{
    assert_ne!(
        caps.vfsd_mount, 0,
        "vfsd_mount_short_path: no vfsd.mount seed"
    );
    // One data word of path bytes (8), against a stated length of 20.
    let msg = mount_request(ROLE_DATA, b"/short", 20);
    let label = mount_reply(caps.vfsd_mount, &msg, "vfsd_mount_short_path");
    assert_eq!(
        label,
        ipc::vfsd_errors::NOT_FOUND,
        "MOUNT with path_len past its data must reply NOT_FOUND (got {label:#x})"
    );
    assert_mounts_answer("vfsd_mount_short_path");
    std::os::seraph::log!("vfsd short-path phase passed (NOT_FOUND)");
}

/// Size of the swap partition `cargo xtask` authors into `disk.img`
/// (`SWAP_PARTITION_SIZE` in `xtask/src/disk.rs`).
const SWAP_PARTITION_BYTES: u64 = 64 * 1024 * 1024;

/// Send `GET_SWAP_PARTITION` with `version` on `cap`: the reply label and
/// the caps it carries.
fn get_swap_partition(cap: u64, version: u64, what: &str) -> (u64, Vec<u64>)
{
    let msg = ipc::IpcMessage::builder(ipc::vfsd_labels::GET_SWAP_PARTITION)
        .word(0, version)
        .build();
    let ipc_buf = std::os::seraph::current_ipc_buf();
    // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(cap, &msg, ipc_buf) }
        .unwrap_or_else(|_| panic!("{what}: GET_SWAP_PARTITION ipc_call failed"));
    (reply.label, reply.caps().to_vec())
}

/// `BLK_GET_GEOMETRY` on the partition cap `blk`: `Ok((block size, length
/// in blocks))`, or `Err(())` when the call itself fails (a revoked cap).
fn geometry(blk: u64, what: &str) -> Result<(u64, u64), ()>
{
    let msg = ipc::IpcMessage::builder(ipc::blk_labels::BLK_GET_GEOMETRY)
        .word(0, u64::from(ipc::BLK_LABELS_VERSION))
        .build();
    let ipc_buf = std::os::seraph::current_ipc_buf();
    // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(blk, &msg, ipc_buf) }.map_err(|_| ())?;
    assert_eq!(
        reply.label,
        ipc::blk_errors::SUCCESS,
        "{what}: BLK_GET_GEOMETRY on the swap partition cap failed"
    );
    Ok((reply.word(0), reply.word(1)))
}

/// One block of `label` (`BLK_READ_INTO_MEMORY` or `BLK_WRITE_FROM_MEMORY`)
/// at `lba` through `blk`, lending the Memory cap in `*page`, which the
/// reply moves back (its slot may change). Returns the reply label.
fn block_io(blk: u64, label: u64, lba: u64, page: &mut u64, what: &str) -> u64
{
    let msg = ipc::IpcMessage::builder(label)
        .word(0, lba)
        .word(1, 1)
        .cap(*page)
        .build();
    let ipc_buf = std::os::seraph::current_ipc_buf();
    // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(blk, &msg, ipc_buf) }
        .unwrap_or_else(|_| panic!("{what}: block request ipc_call failed"));
    *page = reply
        .caps()
        .first()
        .copied()
        .unwrap_or_else(|| panic!("{what}: the block driver kept the Memory cap"));
    reply.label
}

/// The byte at offset `i` of the pattern written at `lba`: distinct per
/// block, so a read that reached the wrong block shows.
fn pattern(lba: u64, i: usize) -> u8
{
    (lba ^ i as u64 ^ 0xA5).to_le_bytes()[0]
}

/// Fill the first `len` bytes at `va` with the pattern of `lba`.
///
/// # Safety
/// `va` maps at least `len` writable bytes this phase owns.
unsafe fn fill(va: u64, len: usize, lba: u64)
{
    for i in 0..len
    {
        // SAFETY: the caller's contract; `i < len`. Volatile, since the
        // device reads the page through its own mapping.
        unsafe { core::ptr::write_volatile((va as *mut u8).wrapping_add(i), pattern(lba, i)) };
    }
}

/// Whether the first `len` bytes at `va` hold the pattern of `lba`.
///
/// # Safety
/// `va` maps at least `len` readable bytes this phase owns.
unsafe fn holds(va: u64, len: usize, lba: u64) -> bool
{
    (0..len).all(|i| {
        // SAFETY: the caller's contract; `i < len`. Volatile, since the
        // device wrote the page through its own mapping.
        unsafe { core::ptr::read_volatile((va as *const u8).wrapping_add(i)) == pattern(lba, i) }
    })
}

/// `GET_SWAP_PARTITION`: refused on `vfsd.deny` and on `vfsd.mount`, whose
/// badges lack `SWAP_AUTHORITY`, and for a stale version word; on
/// `vfsd.swap` it hands a cap that addresses exactly the swap partition (its
/// geometry, a written block read back at either end, and `OUT_OF_BOUNDS`
/// past it). A second hand-out revokes the first cap and reaches the same
/// partition.
#[expect(
    clippy::too_many_lines,
    reason = "one ordered transcript of the hand-out: the refusals, the first cap's reach, then \
              the second hand-out's revoke of it, with the one mapped page spanning all of them"
)]
fn swap_partition_phase(caps: &Caps)
{
    use syscall::{MAP_READ, MAP_WRITABLE};

    const WHAT: &str = "vfsd_swap_partition";
    let version = u64::from(ipc::VFSD_LABELS_VERSION);
    assert_ne!(caps.vfsd_swap, 0, "{WHAT}: no vfsd.swap seed");
    for (cap, shown) in [
        (caps.vfsd_deny, "vfsd.deny"),
        (caps.vfsd_mount, "vfsd.mount"),
    ]
    {
        assert_ne!(cap, 0, "{WHAT}: no {shown} seed");
        let (label, got) = get_swap_partition(cap, version, WHAT);
        assert_eq!(
            label,
            ipc::vfsd_errors::UNAUTHORIZED,
            "{WHAT}: GET_SWAP_PARTITION on {shown} must reply UNAUTHORIZED (got {label:#x})"
        );
        assert!(
            got.is_empty(),
            "{WHAT}: the refusal on {shown} carried a cap"
        );
    }
    let (label, got) = get_swap_partition(caps.vfsd_swap, version + 1, WHAT);
    assert_eq!(
        label,
        ipc::vfsd_errors::LABEL_VERSION_MISMATCH,
        "{WHAT}: a stale version must reply LABEL_VERSION_MISMATCH (got {label:#x})"
    );
    assert!(got.is_empty(), "{WHAT}: the version refusal carried a cap");

    let (label, got) = get_swap_partition(caps.vfsd_swap, version, WHAT);
    assert_eq!(
        label,
        ipc::vfsd_errors::SUCCESS,
        "{WHAT}: GET_SWAP_PARTITION on vfsd.swap must succeed (got {label:#x})"
    );
    let first = *got
        .first()
        .unwrap_or_else(|| panic!("{WHAT}: the hand-out carried no cap"));
    let (block, blocks) =
        geometry(first, WHAT).unwrap_or_else(|()| panic!("{WHAT}: BLK_GET_GEOMETRY call failed"));
    assert_eq!(
        block.checked_mul(blocks),
        Some(SWAP_PARTITION_BYTES),
        "{WHAT}: the cap addresses {blocks} blocks of {block} bytes, not the swap partition"
    );
    let len = usize::try_from(block).expect("vfsd_swap_partition: block size fits usize");
    assert!(
        block <= syscall_abi::PAGE_SIZE,
        "{WHAT}: block size {block} exceeds one page"
    );

    let info = startup_info();
    let (mut page, region_id) = crate::phases::memmgr::try_request_contiguous(1)
        .unwrap_or_else(|label| panic!("{WHAT}: REQUEST_MEMORY_CAPS status {label:#x}"));
    let range = std::os::seraph::reserve_pages(1).expect("vfsd_swap_partition: reserve");
    let va = range.va_start();
    // SAFETY: `range` is a fresh page reservation from the per-process arena,
    // owned here: VA no Rust object or IPC page occupies.
    unsafe {
        std::os::seraph::mem_map_funded(page, info.self_aspace, va, 0, 1, MAP_READ | MAP_WRITABLE)
    }
    .expect("vfsd_swap_partition: mem_map of the page failed");

    // A block at each end of the partition, each with its own pattern.
    let last = blocks
        .checked_sub(1)
        .unwrap_or_else(|| panic!("{WHAT}: the swap partition has no blocks"));
    for lba in [0, last]
    {
        // SAFETY: `va` maps the one writable page above; `len` <= one page.
        unsafe { fill(va, len, lba) };
        let label = block_io(
            first,
            ipc::blk_labels::BLK_WRITE_FROM_MEMORY,
            lba,
            &mut page,
            WHAT,
        );
        assert_eq!(
            label,
            ipc::blk_errors::SUCCESS,
            "{WHAT}: write at LBA {lba}"
        );
    }
    for lba in [0, last]
    {
        // SAFETY: as above.
        unsafe { fill(va, len, u64::MAX) };
        let label = block_io(
            first,
            ipc::blk_labels::BLK_READ_INTO_MEMORY,
            lba,
            &mut page,
            WHAT,
        );
        assert_eq!(label, ipc::blk_errors::SUCCESS, "{WHAT}: read at LBA {lba}");
        // SAFETY: as above.
        let read_back = unsafe { holds(va, len, lba) };
        assert!(
            read_back,
            "{WHAT}: LBA {lba} did not read back what was written"
        );
    }
    let label = block_io(
        first,
        ipc::blk_labels::BLK_READ_INTO_MEMORY,
        blocks,
        &mut page,
        WHAT,
    );
    assert_eq!(
        label,
        ipc::blk_errors::OUT_OF_BOUNDS,
        "{WHAT}: a read past the partition must reply OUT_OF_BOUNDS (got {label:#x})"
    );

    // The second hand-out revokes the first cap: one holder at a time. The
    // revoke frees the first cap's slot, and the second cap may land in it,
    // so a copy of the first in another slot is probed as well: every one of
    // the two slots the second cap did not take must be dead.
    let copy = syscall::cap_derive(first, syscall::RIGHTS_EP_SEND)
        .unwrap_or_else(|_| panic!("{WHAT}: cap_derive of the first cap failed"));
    let (label, got) = get_swap_partition(caps.vfsd_swap, version, WHAT);
    assert_eq!(
        label,
        ipc::vfsd_errors::SUCCESS,
        "{WHAT}: the second GET_SWAP_PARTITION must succeed (got {label:#x})"
    );
    let second = *got
        .first()
        .unwrap_or_else(|| panic!("{WHAT}: the second hand-out carried no cap"));
    let revoked: Vec<u64> = [first, copy].into_iter().filter(|&c| c != second).collect();
    for &cap in &revoked
    {
        assert!(
            geometry(cap, WHAT).is_err(),
            "{WHAT}: a cap from the first hand-out still reaches the partition after the second"
        );
    }
    assert_eq!(
        geometry(second, WHAT),
        Ok((block, blocks)),
        "{WHAT}: the second cap addresses a different range"
    );
    // SAFETY: as above.
    unsafe { fill(va, len, u64::MAX) };
    let label = block_io(
        second,
        ipc::blk_labels::BLK_READ_INTO_MEMORY,
        0,
        &mut page,
        WHAT,
    );
    assert_eq!(
        label,
        ipc::blk_errors::SUCCESS,
        "{WHAT}: read at LBA 0 through the second cap"
    );
    // SAFETY: as above.
    let read_back = unsafe { holds(va, len, 0) };
    assert!(
        read_back,
        "{WHAT}: the second cap does not reach the block the first wrote"
    );

    // SAFETY: `va` is the page mapped above, in this process's own address
    // space, and no Rust reference points into it.
    unsafe { syscall::mem_unmap(info.self_aspace, va, 1) }
        .expect("vfsd_swap_partition: mem_unmap failed");
    std::os::seraph::unreserve_pages(range);
    crate::phases::memmgr::release_grant(page, region_id);
    // The revoke already removed the first hand-out's caps; their slots are
    // empty, so a failed delete here is expected.
    for cap in revoked
    {
        let _ = syscall::cap_delete(cap);
    }
    syscall::cap_delete(second).expect("vfsd_swap_partition: cap_delete of the second cap");
    std::os::seraph::log!(
        "vfsd swap-partition phase passed (deny, mount and version refused; {blocks} blocks of \
         {block} bytes; the second hand-out revoked the first)"
    );
}
