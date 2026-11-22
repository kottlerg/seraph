// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/verified_read.rs

//! procmgr's verified read of a data file (`procmgr_labels::READ_VERIFIED`,
//! `std::os::seraph::read_verified`): procmgr hands back the body of a file
//! signed in the role and under the name asked for, charged to the reader's
//! account while held, and refuses every other file (docs/signing.md
//! § Verifier Discipline).

use std::io::ErrorKind;
use std::os::seraph::{VerifiedRole, namespace_lookup_file, read_verified, root_dir_cap};

use crate::bootstrap::Caps;
use crate::runner::Phase;

/// The data-role fixture xtask synthesises and the pack signs under its
/// install path (`xtask/src/sysroot.rs`, `synthesise_svctest_verified`).
pub(super) const VERIFIED_PATH: &str = "/data/svctest/signed/verified.dat";

/// The fixture's body. Kept in sync with `xtask/src/sysroot.rs`,
/// `SVCTEST_VERIFIED_BODY`.
const VERIFIED_BODY: &[u8] = b"seraph: the body procmgr's verified read returns\n";

/// A copy of the fixture with one body byte flipped, which the phase
/// writes.
const TAMPERED_PATH: &str = "/data/svctest/tampered.dat";

/// A file with no signature, which the phase writes.
const UNSIGNED_PATH: &str = "/data/svctest/unsigned.dat";

/// A synthesised 64 KiB fixture, past `READ_VERIFIED_MAX`.
const OVERSIZED_PATH: &str = "/data/svctest/bench.bin";

pub fn phases() -> &'static [Phase]
{
    &[Phase {
        name: "procmgr_read_verified",
        run: procmgr_read_verified_phase,
    }]
}

/// The file cap and size hint of `path`, resolved from the universal root.
fn lookup(path: &str) -> (u64, u64)
{
    namespace_lookup_file(root_dir_cap(), path)
        .unwrap_or_else(|e| panic!("verified read: look up {path}: {e}"))
}

/// The reader's own pages on its memmgr account.
fn own_pages() -> u64
{
    crate::phases::budget::memory_usage()
        .expect("verified read: QUERY_MEMORY_USAGE")
        .0
}

/// The pages charged to this process's sub-nodes: its whole subtree less
/// its own node.
fn sub_node_pages() -> u64
{
    let (own, _, subtree) =
        crate::phases::budget::memory_usage().expect("verified read: QUERY_MEMORY_USAGE");
    subtree.saturating_sub(own)
}

/// How long the phase waits for the charge of procmgr's read session to
/// leave this process's subtree once the read is answered. A test wait
/// bound.
const SESSION_SETTLE: std::time::Duration = std::time::Duration::from_secs(60);

/// What a refused read asks for: the name, the length (the size hint when
/// `None`) and the role.
struct Request<'a>
{
    name: &'a str,
    len: Option<u64>,
    role: VerifiedRole,
}

impl<'a> Request<'a>
{
    /// A request in the data role for `name`, at the size hint.
    const fn data(name: &'a str) -> Self
    {
        Self {
            name,
            len: None,
            role: VerifiedRole::Data,
        }
    }
}

/// Read `path` through procmgr's verified read as `request` asks, and
/// assert it is refused with `want`.
fn expect_refused(path: &str, request: &Request<'_>, want: ErrorKind, what: &str)
{
    let (cap, size) = lookup(path);
    match read_verified(cap, request.len.unwrap_or(size), request.name, request.role)
    {
        Ok(_) => panic!("verified read: {what}: read back, not refused"),
        Err(e) => assert_eq!(e.kind(), want, "verified read: {what}: refused with {e}"),
    }
}

/// 1. The fixture reads back its body, and the copy's pages are charged to
///    this process while held and leave its account once dropped. The
///    session procmgr opens the file in is charged to a sub-node of this
///    process's node, and its charge leaves the subtree once the read ends
///    (services/procmgr/docs/ipc-interface.md § Label 13).
/// 2. The fixture asked for under another name, or in the configuration
///    role, is refused.
/// 3. A copy of it with one body byte flipped, asked for under the
///    fixture's name, is refused.
/// 4. A file with no signature is refused.
/// 5. A request past `READ_VERIFIED_MAX`, and one of zero bytes, are
///    refused before any read.
fn procmgr_read_verified_phase(_caps: &Caps)
{
    let before = own_pages();
    let sessions_before = sub_node_pages();
    let (cap, size) = lookup(VERIFIED_PATH);
    let data = read_verified(cap, size, VERIFIED_PATH, VerifiedRole::Data)
        .expect("verified read: the fixture");
    assert_eq!(
        data.bytes(),
        VERIFIED_BODY,
        "verified read: the body returned"
    );
    let held = own_pages();
    let pages = size.div_ceil(syscall_abi::PAGE_SIZE);
    assert!(
        held >= before.saturating_add(pages),
        "verified read: {pages} copy pages not charged while held ({before} -> {held})"
    );
    drop(data);
    let after = own_pages();
    assert!(
        after.saturating_add(pages) <= held,
        "verified read: the copy's {pages} pages not released ({held} -> {after})"
    );
    let start = std::time::Instant::now();
    loop
    {
        crate::phases::memmgr::recheck_deferred();
        let now = sub_node_pages();
        if now == sessions_before
        {
            break;
        }
        assert!(
            start.elapsed() < SESSION_SETTLE,
            "verified read: the read session's charge stayed on this process's subtree \
             ({sessions_before} -> {now} pages)"
        );
        std::thread::yield_now();
    }

    expect_refused(
        VERIFIED_PATH,
        &Request::data("/data/svctest/signed/other.dat"),
        ErrorKind::InvalidData,
        "the fixture under another name",
    );
    expect_refused(
        VERIFIED_PATH,
        &Request {
            role: VerifiedRole::Configuration,
            ..Request::data(VERIFIED_PATH)
        },
        ErrorKind::InvalidData,
        "the data fixture in the configuration role",
    );

    let mut tampered = std::fs::read(VERIFIED_PATH).expect("verified read: read the fixture");
    let first = tampered
        .first_mut()
        .expect("verified read: the fixture is not empty");
    *first ^= 1;
    std::fs::write(TAMPERED_PATH, &tampered).expect("verified read: write the tampered copy");
    expect_refused(
        TAMPERED_PATH,
        &Request::data(VERIFIED_PATH),
        ErrorKind::InvalidData,
        "a body byte flipped",
    );

    std::fs::write(UNSIGNED_PATH, VERIFIED_BODY).expect("verified read: write the unsigned file");
    expect_refused(
        UNSIGNED_PATH,
        &Request::data(UNSIGNED_PATH),
        ErrorKind::InvalidData,
        "an unsigned file",
    );

    expect_refused(
        OVERSIZED_PATH,
        &Request::data(OVERSIZED_PATH),
        ErrorKind::InvalidInput,
        "a file past READ_VERIFIED_MAX",
    );
    expect_refused(
        VERIFIED_PATH,
        &Request {
            len: Some(0),
            ..Request::data(VERIFIED_PATH)
        },
        ErrorKind::InvalidInput,
        "a length of zero",
    );

    std::fs::remove_file(TAMPERED_PATH).expect("verified read: remove the tampered copy");
    std::fs::remove_file(UNSIGNED_PATH).expect("verified read: remove the unsigned file");
}
