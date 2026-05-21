// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! vfsd / namespace-protocol surface.
//!
//! Hosts the child-mode entries `sandbox_child_main` and
//! `bin_child_main`, spawned by `ns_sandbox_phase` and
//! `ns_bin_subtree_phase` respectively.

use std::os::seraph::startup_info;

use crate::bootstrap::Caps;
use crate::ipc_util::ns::{ns_lookup, ns_readdir, ns_stat};
use crate::runner::Phase;

/// Phases that run before the FS-IPC and FS-std clusters.
pub fn early() -> &'static [Phase]
{
    &[
        Phase {
            name: "ns",
            run: ns_phase,
        },
        Phase {
            name: "ns_system_root",
            run: ns_system_root_phase,
        },
        Phase {
            name: "ns_mount_boundary",
            run: ns_mount_boundary_phase,
        },
    ]
}

/// Phases that run after the FS clusters.
pub fn late() -> &'static [Phase]
{
    &[
        Phase {
            name: "ns_multi_component",
            run: ns_multi_component_phase,
        },
        Phase {
            name: "ns_sandbox",
            run: ns_sandbox_phase,
        },
        Phase {
            name: "ns_bin_subtree",
            run: ns_bin_subtree_phase,
        },
        Phase {
            name: "ns_startup_cwd",
            run: ns_startup_cwd_phase,
        },
        Phase {
            name: "ns_fallthrough_attenuation",
            run: ns_fallthrough_attenuation_phase,
        },
    ]
}

/// Child-mode dispatch for argv tokens this module owns. Matching
/// arms diverge via the child function's `std::process::exit`; on a
/// miss control returns to the caller.
pub fn reentry_main(role: &str)
{
    match role
    {
        "sandbox-child" => sandbox_child_main(),
        "bin-child" => bin_child_main(),
        _ =>
        {}
    }
}

fn sandbox_child_main() -> !
{
    let root = std::os::seraph::root_dir_cap();
    if root == 0
    {
        std::process::exit(3);
    }
    match std::fs::File::open("/srv/test.txt")
    {
        Ok(_) => std::process::exit(1),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => std::process::exit(0),
        Err(_) => std::process::exit(2),
    }
}

fn bin_child_main() -> !
{
    let root = std::os::seraph::root_dir_cap();
    if root == 0
    {
        std::process::exit(4);
    }
    if std::fs::File::open("/svctest").is_err()
    {
        std::process::exit(1);
    }
    match std::fs::File::open("/srv/test.txt")
    {
        Ok(_) => std::process::exit(2),
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied,
            ) =>
        {
            std::process::exit(0)
        }
        Err(_) => std::process::exit(3),
    }
}

#[allow(clippy::too_many_lines)]
pub fn ns_phase(caps: &Caps)
{
    use namespace_protocol::{NamespaceRights, rights};

    let root_fs = caps.root_fs;
    if root_fs == 0
    {
        std::os::seraph::log!("ns phase skipped: no root-fs cap delivered");
        return;
    }

    let info = startup_info();
    #[allow(clippy::cast_ptr_alignment)]
    let ipc_buf = info.ipc_buffer.cast::<u64>();

    let bin_cap = match ns_lookup(root_fs, b"bin", 0xFFFF, ipc_buf)
    {
        Ok((cap, kind, _size)) =>
        {
            assert_eq!(kind, 1, "expected /bin to be a directory (kind=1)");
            cap
        }
        Err(code) => panic!("NS_LOOKUP(root, \"bin\") failed: code={code}"),
    };
    std::os::seraph::log!("ns: NS_LOOKUP /bin ok");

    let (size, _mtime, kind) = ns_stat(bin_cap, ipc_buf).expect("NS_STAT on /bin must succeed");
    assert_eq!(kind, 1, "/bin stat: kind must be Dir");
    let _ = size;
    std::os::seraph::log!("ns: NS_STAT /bin ok");

    let mut readdir_names: Vec<Vec<u8>> = Vec::new();
    for idx in 0..32u64
    {
        match ns_readdir(bin_cap, idx, ipc_buf)
        {
            Ok(Some((entry_kind, name))) =>
            {
                std::os::seraph::log!(
                    "ns: readdir[{idx}] kind={entry_kind} name={:?}",
                    core::str::from_utf8(&name).unwrap_or("<non-utf8>")
                );
                readdir_names.push(name);
            }
            Ok(None) => break,
            Err(code) => panic!("NS_READDIR(/bin, {idx}) failed: code={code}"),
        }
    }
    for expected in [
        &b"svctest"[..],
        &b"pipefault"[..],
        &b"stackoverflow"[..],
        &b"stdiotest"[..],
    ]
    {
        assert!(
            readdir_names.iter().any(|n| n.as_slice() == expected),
            "NS_READDIR did not surface {:?} verbatim under /bin (LFN-canonical regression — \
             saw {:?})",
            core::str::from_utf8(expected).unwrap(),
            readdir_names
                .iter()
                .map(|n| core::str::from_utf8(n).unwrap_or("<non-utf8>"))
                .collect::<Vec<_>>(),
        );
    }
    std::os::seraph::log!("ns: NS_READDIR /bin saw lowercase LFN-canonical names");

    let svctest_cap = match ns_lookup(bin_cap, b"SVCTEST", 0xFFFF, ipc_buf)
    {
        Ok((cap, kind, _size)) =>
        {
            assert_eq!(kind, 0, "expected /bin/SVCTEST to be a file (kind=0)");
            cap
        }
        Err(code) => panic!("NS_LOOKUP(/bin, \"SVCTEST\") failed: code={code}"),
    };
    let _ = ns_stat(svctest_cap, ipc_buf).expect("NS_STAT on SVCTEST must succeed");
    let _ = syscall::cap_delete(svctest_cap);
    std::os::seraph::log!("ns: NS_LOOKUP /bin/SVCTEST ok");

    match ns_lookup(root_fs, b"nonexistent_xyz", 0xFFFF, ipc_buf)
    {
        Ok(_) => panic!("NS_LOOKUP for nonexistent name unexpectedly succeeded"),
        Err(code) =>
        {
            assert_eq!(
                code,
                namespace_protocol::NsError::NotFound.as_label(),
                "expected NOT_FOUND for nonexistent lookup, got {code}"
            );
        }
    }
    std::os::seraph::log!("ns: NS_LOOKUP nonexistent → NOT_FOUND");

    let stat_only = NamespaceRights::from_raw(rights::STAT).raw();
    let limited_cap = match ns_lookup(root_fs, b"bin", u64::from(stat_only), ipc_buf)
    {
        Ok((cap, _kind, _size)) => cap,
        Err(code) => panic!("NS_LOOKUP for limited /bin cap failed: code={code}"),
    };
    match ns_lookup(limited_cap, b"SVCTEST", 0xFFFF, ipc_buf)
    {
        Ok(_) => panic!("NS_LOOKUP through STAT-only cap unexpectedly succeeded"),
        Err(code) =>
        {
            assert_eq!(
                code,
                namespace_protocol::NsError::PermissionDenied.as_label(),
                "expected PERMISSION_DENIED for STAT-only cap lookup, got {code}"
            );
        }
    }
    let _ = syscall::cap_delete(limited_cap);
    std::os::seraph::log!("ns: NS_LOOKUP without LOOKUP right → PERMISSION_DENIED");

    let _ = syscall::cap_delete(bin_cap);

    std::os::seraph::log!("ns phase passed");
}

pub fn ns_system_root_phase(_: &Caps)
{
    let system_root_cap = std::os::seraph::root_dir_cap();
    assert!(
        system_root_cap != 0,
        "root_dir_cap() returned 0 — ProcessInfo.system_root_cap was \
         not delivered (init→procmgr→child plumbing regression)"
    );
    std::os::seraph::log!("ns_system_root: root_dir_cap()={system_root_cap:#x}");

    let info = startup_info();
    #[allow(clippy::cast_ptr_alignment)]
    let ipc_buf = info.ipc_buffer.cast::<u64>();

    let esp_cap = match ns_lookup(system_root_cap, b"esp", 0xFFFF, ipc_buf)
    {
        Ok((cap, kind, _size)) =>
        {
            assert_eq!(
                kind, 1,
                "expected /esp to be a directory through the synthetic root"
            );
            cap
        }
        Err(code) => panic!("NS_LOOKUP(system_root, \"esp\") failed: code={code}"),
    };
    std::os::seraph::log!("ns_system_root: NS_LOOKUP esp ok");

    let (_size, _mtime, kind) =
        ns_stat(esp_cap, ipc_buf).expect("NS_STAT on /esp synthetic-root cap must succeed");
    assert_eq!(kind, 1, "/esp stat: kind must be Dir");
    std::os::seraph::log!("ns_system_root: NS_STAT esp ok");

    match ns_lookup(system_root_cap, b"nonexistent_xyz", 0xFFFF, ipc_buf)
    {
        Ok(_) => panic!("NS_LOOKUP through synthetic root for absent name unexpectedly succeeded"),
        Err(code) =>
        {
            assert_eq!(
                code,
                namespace_protocol::NsError::NotFound.as_label(),
                "expected NOT_FOUND for absent synthetic-root name, got {code}"
            );
        }
    }
    std::os::seraph::log!("ns_system_root: absent → NOT_FOUND");

    let _ = syscall::cap_delete(esp_cap);
    std::os::seraph::log!("ns_system_root phase passed");
}

pub fn ns_mount_boundary_phase(_: &Caps)
{
    let system_root_cap = std::os::seraph::root_dir_cap();
    assert!(
        system_root_cap != 0,
        "ns_mount_boundary: root_dir_cap() returned 0"
    );

    let info = startup_info();
    #[allow(clippy::cast_ptr_alignment)]
    let ipc_buf = info.ipc_buffer.cast::<u64>();

    let (config_cap, kind, _size) = ns_lookup(system_root_cap, b"config", 0xFFFF, ipc_buf)
        .expect("ns_mount_boundary: NS_LOOKUP(system_root, \"config\") failed");
    assert_eq!(
        kind, 1,
        "ns_mount_boundary: /config must be Dir (transparent root delegation regression?)"
    );
    std::os::seraph::log!("ns_mount_boundary: NS_LOOKUP /config (delegated) ok");

    let (file_cap, kind, size_hint) = ns_lookup(config_cap, b"mounts.conf", 0xFFFF, ipc_buf)
        .expect("ns_mount_boundary: NS_LOOKUP(config, \"mounts.conf\") failed");
    assert_eq!(
        kind, 0,
        "ns_mount_boundary: /config/mounts.conf must be File"
    );
    std::os::seraph::log!("ns_mount_boundary: NS_LOOKUP mounts.conf ok (size_hint={size_hint})");

    let (size, _mtime, kind) =
        ns_stat(file_cap, ipc_buf).expect("ns_mount_boundary: NS_STAT mounts.conf failed");
    assert_eq!(kind, 0, "ns_mount_boundary: stat kind must be File");
    assert!(size > 0, "ns_mount_boundary: mounts.conf size must be > 0");

    let _ = syscall::cap_delete(file_cap);
    let _ = syscall::cap_delete(config_cap);
    std::os::seraph::log!("ns_mount_boundary phase passed");
}

pub fn ns_multi_component_phase(_: &Caps)
{
    let system_root_cap = std::os::seraph::root_dir_cap();
    assert!(
        system_root_cap != 0,
        "ns_multi_component: root_dir_cap() returned 0"
    );

    let info = startup_info();
    #[allow(clippy::cast_ptr_alignment)]
    let ipc_buf = info.ipc_buffer.cast::<u64>();

    let (srv_cap, kind, _) = ns_lookup(system_root_cap, b"srv", 0xFFFF, ipc_buf)
        .expect("ns_multi_component: NS_LOOKUP(/, srv) failed");
    assert_eq!(
        kind, 1,
        "ns_multi_component: /srv must be Dir (synthetic intermediate)"
    );
    std::os::seraph::log!("ns_multi_component: NS_LOOKUP /srv (synthetic) ok");

    let (data_cap, kind, _) = ns_lookup(srv_cap, b"data", 0xFFFF, ipc_buf)
        .expect("ns_multi_component: NS_LOOKUP(/srv, data) failed");
    assert_eq!(
        kind, 1,
        "ns_multi_component: /srv/data must be Dir (mount terminal)"
    );
    let (cfg_cap, kind, _) = ns_lookup(data_cap, b"config", 0xFFFF, ipc_buf)
        .expect("ns_multi_component: NS_LOOKUP(/srv/data, config) failed");
    assert_eq!(kind, 1, "ns_multi_component: /srv/data/config must be Dir");
    let _ = syscall::cap_delete(cfg_cap);
    std::os::seraph::log!("ns_multi_component: NS_LOOKUP /srv/data (terminal) ok");

    let (txt_cap, kind, _) = ns_lookup(srv_cap, b"test.txt", 0xFFFF, ipc_buf)
        .expect("ns_multi_component: NS_LOOKUP(/srv, test.txt) failed (fall-through regression?)");
    assert_eq!(
        kind, 0,
        "ns_multi_component: /srv/test.txt must be File (root-fs fall-through)"
    );
    let (size, _mtime, kind) =
        ns_stat(txt_cap, ipc_buf).expect("ns_multi_component: NS_STAT /srv/test.txt failed");
    assert_eq!(kind, 0, "ns_multi_component: stat kind must be File");
    assert!(
        size > 0,
        "ns_multi_component: /srv/test.txt size must be > 0"
    );
    let _ = syscall::cap_delete(txt_cap);
    let _ = syscall::cap_delete(data_cap);
    let _ = syscall::cap_delete(srv_cap);
    std::os::seraph::log!("ns_multi_component: NS_LOOKUP /srv/test.txt (fall-through) ok");

    let body = std::fs::read_to_string("/srv/test.txt")
        .expect("ns_multi_component: std::fs::read_to_string(/srv/test.txt) failed");
    assert!(
        body.contains("srv-test-marker"),
        "ns_multi_component: marker missing from /srv/test.txt body: {body:?}"
    );
    std::os::seraph::log!("ns_multi_component phase passed");
}

pub fn ns_sandbox_phase(_: &Caps)
{
    use namespace_protocol::{NamespaceRights, rights};
    use std::os::seraph::process::CommandExt;

    let root = std::os::seraph::root_dir_cap();
    if root == 0
    {
        std::os::seraph::log!("ns_sandbox phase skipped: no root_dir_cap");
        return;
    }

    let info = startup_info();
    #[allow(clippy::cast_ptr_alignment)]
    let ipc_buf = info.ipc_buffer.cast::<u64>();

    let stat_only = NamespaceRights::from_raw(rights::STAT).raw();
    let attenuated = match ns_lookup(root, b"srv", u64::from(stat_only), ipc_buf)
    {
        Ok((cap, _kind, _size)) => cap,
        Err(code) => panic!("ns_sandbox: walk-attenuate /srv failed: code={code}"),
    };

    let mut cmd = std::process::Command::new("/bin/svctest");
    cmd.arg("sandbox-child");
    cmd.namespace_cap(attenuated);
    let status = cmd
        .status()
        .expect("ns_sandbox: spawn /bin/svctest sandbox-child failed");

    assert!(
        status.success(),
        "ns_sandbox: child exit status {status:?}; expected exit code 0 (PermissionDenied \
         observed). 1 = open succeeded (attenuation failed), 2 = different error, 3 = no \
         system_root_cap delivered to child"
    );
    std::os::seraph::log!("ns_sandbox phase passed");
}

pub fn ns_bin_subtree_phase(_: &Caps)
{
    use namespace_protocol::{NamespaceRights, rights};
    use std::os::seraph::process::CommandExt;

    let root = std::os::seraph::root_dir_cap();
    if root == 0
    {
        std::os::seraph::log!("ns_bin_subtree phase skipped: no root_dir_cap");
        return;
    }

    let bin_rights = NamespaceRights::from_raw(rights::LOOKUP | rights::STAT | rights::READ).raw();
    let bin_cap = match std::os::seraph::namespace_lookup_dir(root, "/bin", u64::from(bin_rights))
    {
        Ok(c) => c,
        Err(e) => panic!("ns_bin_subtree: walk-attenuate /bin failed: {e}"),
    };

    let mut cmd = std::process::Command::new("/bin/svctest");
    cmd.arg("bin-child");
    cmd.namespace_cap(bin_cap);
    let status = cmd
        .status()
        .expect("ns_bin_subtree: spawn /bin/svctest bin-child failed");

    assert!(
        status.success(),
        "ns_bin_subtree: child exit status {status:?}; expected 0. \
         1 = /svctest open failed (cap not rooted at /bin), \
         2 = /srv/test.txt unexpectedly opened (cap not attenuated), \
         3 = /srv/test.txt failed with unexpected error kind, \
         4 = no system_root_cap delivered to child"
    );
    std::os::seraph::log!("ns_bin_subtree phase passed");
}

pub fn ns_startup_cwd_phase(_: &Caps)
{
    let cwd = std::os::seraph::current_dir_cap();
    assert_ne!(
        cwd, 0,
        "ns_startup_cwd: init did not install a startup cwd cap via CONFIGURE_NAMESPACE",
    );

    let info = startup_info();
    #[allow(clippy::cast_ptr_alignment)]
    let ipc_buf = info.ipc_buffer.cast::<u64>();

    let (file_cap, kind, _size) = ns_lookup(cwd, b"test.txt", 0xFFFF, ipc_buf).expect(
        "ns_startup_cwd: NS_LOOKUP test.txt from startup cwd cap failed — cwd cap \
         does not address /srv",
    );
    assert_eq!(
        kind, 0,
        "ns_startup_cwd: test.txt should be a file (kind=0), got {kind}",
    );
    let _ = syscall::cap_delete(file_cap);
    std::os::seraph::log!("ns_startup_cwd phase passed");
}

pub fn ns_fallthrough_attenuation_phase(_: &Caps)
{
    use namespace_protocol::{NamespaceRights, rights};

    let root = std::os::seraph::root_dir_cap();
    if root == 0
    {
        std::os::seraph::log!("ns_fallthrough_attenuation phase skipped: no root_dir_cap");
        return;
    }

    let info = startup_info();
    #[allow(clippy::cast_ptr_alignment)]
    let ipc_buf = info.ipc_buffer.cast::<u64>();

    let lookup_stat = NamespaceRights::from_raw(rights::LOOKUP | rights::STAT).raw();
    let (srv_cap, _kind, _) = ns_lookup(root, b"srv", u64::from(lookup_stat), ipc_buf)
        .expect("ns_fallthrough_attenuation: walk-attenuate /srv (LOOKUP|STAT) failed");

    let (file_cap, _kind, _) = ns_lookup(srv_cap, b"test.txt", 0xFFFF, ipc_buf)
        .expect("ns_fallthrough_attenuation: NS_LOOKUP /srv/test.txt across fall-through failed");

    let read_msg = ipc::IpcMessage::builder(ipc::fs_labels::FS_READ)
        .word(0, 0)
        .word(1, 4)
        .build();
    // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
    let read_reply = unsafe { ipc::ipc_call(file_cap, &read_msg, ipc_buf) }
        .expect("ns_fallthrough_attenuation: FS_READ ipc_call failed");
    assert_eq!(
        read_reply.label,
        ipc::fs_errors::PERMISSION_DENIED,
        "ns_fallthrough_attenuation: FS_READ on cap walked under LOOKUP|STAT-only parent \
         returned {} (expected PERMISSION_DENIED={}) — the fall-through forwarder is \
         laundering authority through the synthetic intermediate's full-rights cap",
        read_reply.label,
        ipc::fs_errors::PERMISSION_DENIED,
    );

    let _ = syscall::cap_delete(file_cap);
    let _ = syscall::cap_delete(srv_cap);
    std::os::seraph::log!("ns_fallthrough_attenuation phase passed");
}
