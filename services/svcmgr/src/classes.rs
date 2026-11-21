// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svcmgr/src/classes.rs

//! devmgr's device classes, configured from the class files of
//! `/config/devmgr/classes/` (`services/svcmgr/docs/service-definitions.md`
//! § Device class files), read through the directory's signed index
//! (`crate::config`): for each file the index names svcmgr asks devmgr for the SEND of
//! the class the file configures (`ipc::devmgr_labels::MINT_CLASS_SEND`) and
//! publishes it seed-only as `devmgr.class.<stem>`, the file's name without
//! `.class`, so a service reaches a class's drivers only when its definition
//! seeds that name.

use std::ops::ControlFlow;
use std::os::seraph::log;

use registry::Visibility;
use svcmgr_defs::class::{CLASS_FILE_SUFFIX, CLASSES_DIR, class_publication, parse_class};

use crate::config::IndexedDir;
use crate::definitions::reconcile::PendingRegistration;
use crate::endowed_servers;

/// Configure devmgr's classes from [`CLASSES_DIR`] through `devmgr_registry`,
/// the endowed badge-0 devmgr-registry source, and publish each class SEND.
/// The class files are those the directory's signed index names, each read
/// through procmgr's verified read ([`IndexedDir`]); an index that is missing
/// or refused configures no class, logged. A file that is missing, refused or
/// does not parse, or whose class devmgr refuses, is logged and skipped.
///
/// The files are read through vfsd and each class is minted by devmgr, so the
/// liveness of both is read from their registrations in `pending` before the
/// pass, vfsd's after every read that fails and devmgr's after every mint that
/// fails ([`endowed_servers::death`]), and a dead server ends the pass: a
/// later call to it fails with `NoReceiver`, which does not itself say that
/// the server died.
pub fn configure(
    registry: &mut registry::Registry,
    devmgr_registry: u64,
    pending: &[PendingRegistration],
    ipc_buf: *mut u64,
)
{
    if devmgr_registry == 0
    {
        log!(warn: "no devmgr-registry source; no device class configured");
        return;
    }
    if server_dead(pending, endowed_servers::VFSD, ipc_buf).is_break()
        || server_dead(pending, endowed_servers::DEVMGR, ipc_buf).is_break()
    {
        return;
    }
    let dir = match IndexedDir::open(CLASSES_DIR)
    {
        Ok(dir) => dir,
        Err(e) =>
        {
            log!(
                warn: "{CLASSES_DIR}/index not read ({:?}); no device class configured",
                e.kind()
            );
            return;
        }
    };
    dir.report_unnamed();
    let Ok(minter) = syscall::cap_derive_badge(
        devmgr_registry,
        syscall::RIGHTS_EP_SEND,
        ipc::devmgr_labels::CLASS_AUTHORITY,
    )
    else
    {
        log!(warn: "CLASS_AUTHORITY derive failed; no device class configured");
        return;
    };
    for filename in dir.names()
    {
        let Some(class) = filename.strip_suffix(CLASS_FILE_SUFFIX)
        else
        {
            log!(warn: "{CLASSES_DIR}/{filename}: named by the index but not a class file; not read");
            continue;
        };
        if configure_one(registry, minter, &dir, class, pending, ipc_buf).is_break()
        {
            break;
        }
    }
    let _ = syscall::cap_delete(minter);
}

/// `Break` when the server `server` names (vfsd or devmgr) is dead
/// ([`endowed_servers::death`]), logged: no further class file can be read,
/// or no further class minted.
fn server_dead(pending: &[PendingRegistration], server: &str, ipc_buf: *mut u64)
-> ControlFlow<()>
{
    if endowed_servers::death(pending, server, ipc_buf).is_some()
    {
        log!(warn: "{server} is dead; device classes not configured");
        return ControlFlow::Break(());
    }
    ControlFlow::Continue(())
}

/// Configure the class the file `<CLASSES_DIR>/<class>.class` names and
/// publish its SEND as `devmgr.class.<class>`, through `minter`, a
/// `CLASS_AUTHORITY` SEND on devmgr's registry. The file is read from `dir`
/// through procmgr's verified read. `class` is the file's stem,
/// which names the class configured only when the file sets no `class` key.
/// `Break` when the file's read failed and vfsd is dead, or devmgr's mint
/// failed and devmgr is dead ([`server_dead`]).
fn configure_one(
    registry: &mut registry::Registry,
    minter: u64,
    dir: &IndexedDir,
    class: &str,
    pending: &[PendingRegistration],
    ipc_buf: *mut u64,
) -> ControlFlow<()>
{
    // Fallible, as every copy svcmgr makes of configuration text is.
    let mut filename = String::new();
    if filename
        .try_reserve_exact(class.len().saturating_add(CLASS_FILE_SUFFIX.len()))
        .is_err()
    {
        log!(warn: "class {class}: no memory for its file name; not configured");
        return ControlFlow::Continue(());
    }
    filename.push_str(class);
    filename.push_str(CLASS_FILE_SUFFIX);
    let verified = match dir.read(&filename)
    {
        Ok(verified) => verified,
        Err(e) =>
        {
            log!(
                warn: "{CLASSES_DIR}/{filename}: named by the index, not read ({:?}); class not configured",
                e.kind()
            );
            return server_dead(pending, endowed_servers::VFSD, ipc_buf);
        }
    };
    let Ok(contents) = core::str::from_utf8(verified.bytes())
    else
    {
        log!(warn: "parse {CLASSES_DIR}/{filename}: not UTF-8; class not configured");
        return ControlFlow::Continue(());
    };
    let def = match parse_class(class, contents)
    {
        Ok(d) => d,
        Err(e) =>
        {
            log!(warn: "parse {CLASSES_DIR}/{filename}: {e}; class not configured");
            return ControlFlow::Continue(());
        }
    };
    // SAFETY: `ipc_buf` is svcmgr's registered IPC buffer.
    let send =
        match unsafe { ipc::mint_class_send(minter, def.name.as_bytes(), def.verbs, ipc_buf) }
        {
            Ok(send) => send,
            Err(e) =>
            {
                log!(warn: "class {class}: devmgr refused it ({e:?}); not configured");
                return server_dead(pending, endowed_servers::DEVMGR, ipc_buf);
            }
        };
    let Some(name) = class_publication(def.stem.as_bytes())
    else
    {
        log!(warn: "class {class}: no memory for its name; not published");
        let _ = syscall::cap_delete(send);
        return ControlFlow::Continue(());
    };
    if registry.publish(&name, send, Visibility::SeedOnly).is_err()
    {
        log!(warn: "class {class}: publish failed");
        let _ = syscall::cap_delete(send);
    }
    ControlFlow::Continue(())
}
