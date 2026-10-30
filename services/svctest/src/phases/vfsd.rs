// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/vfsd.rs

//! vfsd service surface: the `MOUNT` label's authority gate and its
//! rejection paths (services/vfsd/docs/vfs-ipc-interface.md § Label 10).
//!
//! svctest holds two SENDs on vfsd's service endpoint, both seed-only:
//! `vfsd.mount`, badged `MOUNT_AUTHORITY`, and `vfsd.deny`, badged with no
//! verb bit. Every case leaves the mount table as it found it: the deny
//! case and the rejection cases install nothing and spawn no driver, which
//! each checks through the replies and the mounted filesystems afterwards.

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
    ]
}

/// `MountRole` wire bytes (vfs-ipc-interface.md § Label 10).
const ROLE_ROOT: u64 = 0;
const ROLE_DATA: u64 = 1;

/// More rejected mounts than vfsd's four per-mount bootstrap slots: a
/// rejection that registered a partition, spawned a driver, or held a slot
/// before failing would turn a later reply into `SPAWN_FAILED` (or another
/// error) instead of `TABLE_FULL`.
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
fn mount_reply(cap: u32, msg: &ipc::IpcMessage, what: &str) -> u64
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
/// already mount points, replies `TABLE_FULL` every time across more
/// rounds than vfsd has bootstrap slots, and the mounted filesystems
/// still answer afterwards.
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
