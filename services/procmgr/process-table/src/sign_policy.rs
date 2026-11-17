// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/procmgr/process-table/src/sign_policy.rs

//! The signature policy procmgr keeps on each creator's record
//! (docs/signing.md § Signature Policy in procmgr): the set of object kinds
//! the creator's creates may load. A create's object is verified with the
//! creator's set as the kinds it accepts, so a create of an object of any
//! other kind is refused; a child takes its creator's set, narrowed by its
//! own verified kind ([`child_kinds`]), so no child holds more than its
//! creator.

use ipc::IpcMessage;
use objsig::{Kind, KindSet};

/// The name a create request `req` expects its object to be signed under:
/// its name block (`ipc::procmgr_labels::create_name`), when that is in the
/// canonical form xtask signs under (`objsig::name_is_canonical`). `None`,
/// which procmgr refuses `INVALID_ARGUMENT` before it reads any object,
/// when the block is missing or malformed or the name is not canonical.
#[must_use]
pub fn requested_name(req: &IpcMessage) -> Option<&[u8]>
{
    ipc::procmgr_labels::create_name(req).filter(|name| objsig::name_is_canonical(name))
}

/// The un-badged creator's set (init, and svcmgr's mint source): every kind
/// procmgr loads as a process. `Kernel` and `Init` are loaded by the
/// bootloader alone, and `Data` is never code.
pub const LOADABLE: KindSet =
    KindSet::of(&[Kind::BootModule, Kind::Service, Kind::Driver, Kind::Program]);

/// The set of a child whose verified kind is `kind`, created by a creator
/// whose set is `creator`: a program's creates load programs only, so it is
/// `creator` narrowed to `Program`; a child of any other kind keeps
/// `creator`. Never wider than `creator`.
#[must_use]
pub const fn child_kinds(creator: KindSet, kind: Kind) -> KindSet
{
    match kind
    {
        Kind::Program => creator.intersection(KindSet::of(&[Kind::Program])),
        Kind::Kernel
        | Kind::Init
        | Kind::BootModule
        | Kind::Service
        | Kind::Driver
        | Kind::Data => creator,
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    use ipc::procmgr_labels::{
        CREATE_FROM_FILE, CREATE_MEMORY_MAX, CREATE_NAME_MAX, CREATE_PROCESS, with_create_name,
    };

    const ALL_KINDS: [Kind; 7] = Kind::ALL;

    // Defect guarded: a request name the wire carries but the canonical form
    // refuses, or the reverse, so a creator's well-formed name is refused or
    // a name naming its file another way reaches the verifier.
    #[test]
    fn the_wire_bound_on_a_name_is_the_canonical_forms()
    {
        assert_eq!(CREATE_NAME_MAX, objsig::NAME_MAX);
    }

    fn request(label: u64, name: &[u8]) -> IpcMessage
    {
        let builder = IpcMessage::builder(label).word(0, 4096).word(1, 9);
        with_create_name(builder, label, name).unwrap().build()
    }

    #[test]
    fn a_canonical_name_is_the_requested_name()
    {
        let label = CREATE_FROM_FILE | CREATE_MEMORY_MAX;
        let msg = request(label, b"/services/svcmgr");
        assert_eq!(requested_name(&msg), Some(&b"/services/svcmgr"[..]));
        let msg = request(CREATE_PROCESS, b"devmgr");
        assert_eq!(requested_name(&msg), Some(&b"devmgr"[..]));
    }

    // Defect guarded: a creator passing a name that names the file another
    // way, or none, and procmgr verifying under it.
    #[test]
    fn a_name_not_in_the_canonical_form_or_missing_is_refused()
    {
        for name in [
            &b"/services//svcmgr"[..],
            b"services/svcmgr",
            b"/services/../svcmgr",
            b"a\0",
        ]
        {
            assert_eq!(
                requested_name(&request(CREATE_FROM_FILE, name)),
                None,
                "{name:?}"
            );
        }
        let bare = IpcMessage::builder(CREATE_FROM_FILE).word(0, 4096).build();
        assert_eq!(requested_name(&bare), None);
    }

    #[test]
    fn the_unbadged_set_holds_every_process_kind_and_nothing_else()
    {
        for kind in ALL_KINDS
        {
            let process = matches!(
                kind,
                Kind::BootModule | Kind::Service | Kind::Driver | Kind::Program
            );
            assert_eq!(LOADABLE.contains(kind), process, "{kind:?}");
        }
    }

    #[test]
    fn a_program_child_creates_programs_only()
    {
        let kinds = child_kinds(LOADABLE, Kind::Program);
        assert_eq!(kinds, KindSet::of(&[Kind::Program]));
        // Its own program children keep that set.
        assert_eq!(child_kinds(kinds, Kind::Program), kinds);
    }

    #[test]
    fn a_system_child_keeps_its_creators_set()
    {
        for kind in [Kind::BootModule, Kind::Service, Kind::Driver]
        {
            assert_eq!(child_kinds(LOADABLE, kind), LOADABLE, "{kind:?}");
        }
    }

    #[test]
    fn no_child_set_is_wider_than_its_creators()
    {
        let creators = [
            KindSet::EMPTY,
            KindSet::of(&[Kind::Program]),
            KindSet::of(&[Kind::Service, Kind::Driver]),
            LOADABLE,
        ];
        for creator in creators
        {
            for kind in ALL_KINDS
            {
                let child = child_kinds(creator, kind);
                assert_eq!(child.intersection(creator), child, "{creator:?} {kind:?}");
            }
        }
    }
}
