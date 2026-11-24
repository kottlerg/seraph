// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/vfsd.rs

//! vfsd service surface: the `MOUNT` label's authority gate and its
//! rejection paths (services/vfsd/docs/vfs-ipc-interface.md § Label 10),
//! and the swap-partition refusals (§ Label 14); the hand-out itself is
//! swapd's, so svctest never makes one.
//!
//! svctest holds three SENDs on vfsd's service endpoint, all seed-only:
//! `vfsd.mount`, badged `MOUNT_AUTHORITY`, `vfsd.deny`, badged with no
//! verb bit, and `vfsd.swap`, badged `SWAP_AUTHORITY`. Every `MOUNT` case
//! leaves the mount table as it found it: the deny case and the rejection
//! cases (a mounted path, a mounted partition at a fresh path, a short
//! path) install nothing and spawn no driver, which each checks through the
//! replies and the mounted filesystems afterwards.

use super::unmount::data_named_for_data_path;
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
            name: "vfsd_mount_rejects_mounted_partition",
            run: mount_rejects_mounted_partition_phase,
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
/// afterwards. With the data partition named for `/data` alone
/// ([`data_named_for_data_path`]) the data role at `/esp` resolves on the
/// boot disk, which carries no data partition, so the data role is asked
/// at `/data`, where it resolves and the mount point is taken.
fn mount_rejects_mounted_paths_phase(caps: &Caps)
{
    assert_ne!(caps.vfsd_mount, 0, "vfsd_mount_rejects: no vfsd.mount seed");
    let data_path = if data_named_for_data_path()
    {
        "/data"
    }
    else
    {
        "/esp"
    };
    for round in 0..REJECT_ROUNDS
    {
        for (role, path) in [(ROLE_ROOT, "/"), (ROLE_DATA, data_path)]
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

/// `MOUNT` of the data role at a fresh path, while the data partition is
/// mounted at `/data`, replies `TABLE_FULL` in every one of
/// `REJECT_ROUNDS` rounds and installs nothing: one driver serves a
/// partition (vfs-ipc-interface.md § Label 10). A second driver over the
/// partition would show as `SUCCESS` and a path that resolves. With the
/// data partition named for `/data` alone ([`data_named_for_data_path`])
/// the fresh path resolves on the boot disk, which carries no data
/// partition, and each round replies `NO_MOUNT` instead: a partition the
/// statement names takes the role at its own path only.
fn mount_rejects_mounted_partition_phase(caps: &Caps)
{
    const FRESH: &str = "/svctest-data-again";
    assert_ne!(
        caps.vfsd_mount, 0,
        "vfsd_mount_rejects_partition: no vfsd.mount seed"
    );
    let (expected, name) = if data_named_for_data_path()
    {
        (ipc::vfsd_errors::NO_MOUNT, "NO_MOUNT")
    }
    else
    {
        (ipc::vfsd_errors::TABLE_FULL, "TABLE_FULL")
    };
    for round in 0..REJECT_ROUNDS
    {
        let msg = mount_request(ROLE_DATA, FRESH.as_bytes(), FRESH.len() as u64);
        let label = mount_reply(caps.vfsd_mount, &msg, "vfsd_mount_rejects_partition");
        assert_eq!(
            label, expected,
            "MOUNT of the data role at {FRESH} (round {round}) must reply {name} (got \
             {label:#x})"
        );
    }
    assert!(
        std::fs::metadata(FRESH).is_err(),
        "vfsd_mount_rejects_partition: {FRESH} exists after a refused MOUNT"
    );
    assert_mounts_answer("vfsd_mount_rejects_partition");
    std::os::seraph::log!(
        "vfsd mounted-partition phase passed ({REJECT_ROUNDS} rounds of {name}, nothing \
         mounted)"
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

/// `GET_SWAP_PARTITION`: refused on `vfsd.deny` and on `vfsd.mount`, whose
/// badges lack `SWAP_AUTHORITY`, and for a stale version word on
/// `vfsd.swap`. No call with the current version is made: the partition is
/// swapd's, and a hand-out would revoke its cap. The hand-out's reach is
/// exercised by swapd itself, and the revoke of an earlier holder by
/// vfsd-swap's host tests.
fn swap_partition_phase(caps: &Caps)
{
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
    std::os::seraph::log!(
        "vfsd swap-partition phase passed (deny and mount refused UNAUTHORIZED; stale version \
         refused LABEL_VERSION_MISMATCH)"
    );
}
