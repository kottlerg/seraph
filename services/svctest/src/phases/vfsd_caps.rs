// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/vfsd_caps.rs

//! Caps a request on vfsd's namespace endpoint carries: vfsd deletes every
//! one, whatever the request's label and whatever it answers
//! (services/vfsd/docs/namespace-composition.md § Two endpoints, one process).
//!
//! A cap reaches that endpoint only through the cap vfsd mints for a
//! synthetic intermediate directory, `SEND_GRANT`; the system root is `SEND`
//! alone. The phase mounts the data partition over [`SHADOWED_DIR`], which
//! makes `/config` such a directory, with a fall-through to the root
//! filesystem's `/config`. Each request carries the Receive right of fresh
//! endpoints, and once it is answered a call on each endpoint must fail with
//! `NoReceiver`: the kernel fails it at once when no capability with the
//! Receive right is left (docs/ipc-design.md § Endpoints), and queues it while
//! vfsd keeps one.
//!
//! The phase runs after the unmount phases and leaves `/data` mounted, with
//! svctest's cwd set to it, as it found it.

use std::os::seraph::current_ipc_buf;

use ipc::{IpcMessage, IpcMessageBuilder};
use namespace_protocol::NsError;
use syscall_abi::MSG_CAP_SLOTS_MAX;

use super::unmount::{
    SHADOWED_DIR, UNFORCED, data_named_for_data_path, force_unmount_data, mount_data, unmount,
};
use crate::bootstrap::Caps;
use crate::ipc_util::ns::ns_lookup;
use crate::runner::Phase;

pub fn phases() -> &'static [Phase]
{
    &[Phase {
        name: "vfsd_namespace_stray_caps",
        run: stray_caps_phase,
    }]
}

/// Bound on the call that checks an endpoint has no Receive right left: a
/// bound for a hang, not a timing. A call fails at once with `NoReceiver`;
/// it waits out the bound only when vfsd kept the endpoint's Receive right.
const PROBE_BOUND_MS: u32 = 30_000;

/// `NS_LOOKUP` of `name` asking every right the parent allows.
fn lookup_request(name: &[u8]) -> IpcMessageBuilder
{
    IpcMessage::builder(ipc::ns_labels::NS_LOOKUP | ((name.len() as u64) << 16))
        .word(0, 0xFFFF)
        .bytes(1, name)
}

/// One request sent with stray caps, and the reply label vfsd must give.
struct Case
{
    what: &'static str,
    request: fn() -> IpcMessageBuilder,
    expected: u64,
}

/// The requests on `/config`: a label outside `NS_*` (`FS_SESSION`, which
/// std's create sends through a parent directory's cap), and each path of the
/// namespace dispatcher: a lookup and a listing served by the fall-through to
/// the root filesystem, and a lookup and a stat served by vfsd's own tree.
const CASES: [Case; 5] = [
    Case {
        what: "FS_SESSION",
        request: || IpcMessage::builder(ipc::fs_labels::FS_SESSION),
        expected: NsError::NotSupported.as_label(),
    },
    Case {
        what: "NS_LOOKUP of devmgr (fall-through)",
        request: || lookup_request(b"devmgr"),
        expected: 0,
    },
    Case {
        // Index 0 is the local child `svcmgr`; index 1 is the root
        // filesystem's first entry it does not shadow.
        what: "NS_READDIR at index 1 (fall-through)",
        request: || IpcMessage::builder(ipc::ns_labels::NS_READDIR).word(0, 1),
        expected: 0,
    },
    Case {
        what: "NS_LOOKUP of svcmgr (local child)",
        request: || lookup_request(b"svcmgr"),
        expected: 0,
    },
    Case {
        what: "NS_STAT",
        request: || IpcMessage::builder(ipc::ns_labels::NS_STAT),
        expected: 0,
    },
];

/// A new endpoint, whose cap holds its only Receive right.
fn new_endpoint() -> u64
{
    std::os::seraph::object_slab_retype(std::os::seraph::ENDPOINT_RETYPE_BYTES, |slab| {
        syscall::cap_create_endpoint(slab).ok()
    })
    .expect("vfsd_namespace_stray_caps: endpoint creation failed")
}

/// Send `case`'s request on `dir` carrying the Receive rights of
/// `MSG_CAP_SLOTS_MAX` fresh endpoints, check its reply label, and check that
/// none of the endpoints has a Receive right left once it is answered.
fn send_with_stray_caps(dir: u64, case: &Case, ipc_buf: *mut u64)
{
    let what = case.what;
    let mut probes = Vec::with_capacity(MSG_CAP_SLOTS_MAX);
    let mut builder = (case.request)();
    for _ in 0..MSG_CAP_SLOTS_MAX
    {
        let ep = new_endpoint();
        probes.push(
            syscall::cap_derive(ep, syscall::RIGHTS_EP_SEND)
                .expect("vfsd_namespace_stray_caps: deriving the probe Send cap failed"),
        );
        builder = builder.cap(ep);
    }
    // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(dir, &builder.build(), ipc_buf) }
        .unwrap_or_else(|e| panic!("vfsd_namespace_stray_caps: {what}: ipc_call failed: {e}"));
    for &cap in reply.caps()
    {
        let _ = syscall::cap_delete(cap);
    }
    assert_eq!(
        reply.label, case.expected,
        "vfsd_namespace_stray_caps: {what}: reply label"
    );
    for (slot, probe) in probes.into_iter().enumerate()
    {
        // SAFETY: as above.
        let answer =
            unsafe { ipc::ipc_call_timeout(probe, &IpcMessage::new(0), ipc_buf, PROBE_BOUND_MS) };
        assert_eq!(
            answer.err(),
            Some(syscall_abi::SyscallError::NoReceiver as i64),
            "vfsd_namespace_stray_caps: {what}: vfsd kept caps[{slot}], an endpoint's \
             Receive right"
        );
        let _ = syscall::cap_delete(probe);
    }
}

/// Mount the data partition over [`SHADOWED_DIR`], send each of [`CASES`]
/// with stray caps on the synthetic `/config`, then mount the partition at
/// `/data` again and set the cwd to it. With the data partition named for
/// `/data` alone ([`data_named_for_data_path`]) nothing can make `/config`
/// synthetic, and the phase is skipped.
fn stray_caps_phase(caps: &Caps)
{
    assert_ne!(
        caps.vfsd_mount, 0,
        "vfsd_namespace_stray_caps: no vfsd.mount seed"
    );
    if data_named_for_data_path()
    {
        std::os::seraph::log!(
            "vfsd_namespace_stray_caps: skipped: the storage statement names the data \
             partition for /data alone, so it cannot mount over {SHADOWED_DIR}"
        );
        return;
    }
    force_unmount_data(caps);
    mount_data(caps, SHADOWED_DIR);

    let ipc_buf = current_ipc_buf();
    let root = std::os::seraph::root_dir_cap();
    assert_ne!(root, 0, "vfsd_namespace_stray_caps: no root_dir_cap");
    let (config, kind, _) = ns_lookup(root, b"config", 0xFFFF, ipc_buf)
        .unwrap_or_else(|e| panic!("vfsd_namespace_stray_caps: NS_LOOKUP(/, config): {e:#x}"));
    assert_eq!(
        kind, 1,
        "vfsd_namespace_stray_caps: /config must be a directory"
    );
    for case in &CASES
    {
        send_with_stray_caps(config, case, ipc_buf);
    }
    let _ = syscall::cap_delete(config);

    let reply = unmount(caps.vfsd_mount, SHADOWED_DIR, UNFORCED);
    assert_eq!(
        reply.label,
        ipc::vfsd_errors::SUCCESS,
        "vfsd_namespace_stray_caps: UNMOUNT of {SHADOWED_DIR} (got {:#x})",
        reply.label
    );
    mount_data(caps, "/data");
    std::env::set_current_dir("/data")
        .expect("vfsd_namespace_stray_caps: set_current_dir(/data) after the remount");
    std::os::seraph::log!(
        "vfsd_namespace_stray_caps: vfsd deleted the caps of {} requests on /config",
        CASES.len()
    );
}
