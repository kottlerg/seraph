// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/procmgr/process-table/src/sign_policy.rs

//! The signature policy procmgr keeps on each creator's record
//! (docs/signing.md § Signature Policy in procmgr): the set of roles the
//! creator's creates may load. A create's object is verified with the
//! creator's set as the roles it accepts, so a create of an object whose
//! set holds none of them is refused; a child takes its creator's set,
//! narrowed by its own verified set ([`child_roles`]), so no child holds
//! more than its creator.

use ipc::IpcMessage;
use objsig::{Role, RoleSet};

/// The name a create request `req` expects its object to be signed under:
/// its name block (`ipc::procmgr_labels::create_name`), when that is an
/// install path in the canonical form xtask signs under
/// (`objsig::name_is_install_path`). `None`, which procmgr refuses
/// `INVALID_ARGUMENT` before it reads any object, when the block is missing
/// or malformed or the name is not a canonical install path: the slot names
/// `kernel` and `init` name objects the bootloader alone loads.
#[must_use]
pub fn requested_name(req: &IpcMessage) -> Option<&[u8]>
{
    ipc::procmgr_labels::create_name(req).filter(|name| objsig::name_is_install_path(name))
}

/// The un-badged creator's set (init, and svcmgr's mint source): every role
/// a process runs in. `Kernel` and `Init` are loaded by the bootloader
/// alone, `BootModule` is the bootloader's permission alone, and `Data` is
/// never code, so a bundle entry is started in the role it runs in.
pub const LOADABLE: RoleSet = RoleSet::of(&[Role::Service, Role::Driver, Role::Program]);

/// The set of a child whose verified role set is `roles`, created by a
/// creator whose set is `creator`: a program's creates load programs only,
/// so a child whose set holds `Program` takes `creator` narrowed to
/// `Program`; any other child keeps `creator`. Never wider than
/// `creator`.
#[must_use]
pub const fn child_roles(creator: RoleSet, roles: RoleSet) -> RoleSet
{
    let program = RoleSet::of(&[Role::Program]);
    if roles.meets(program)
    {
        creator.intersection(program)
    }
    else
    {
        creator
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    use ipc::procmgr_labels::{
        CREATE_FROM_FILE, CREATE_MEMORY_MAX, CREATE_NAME_MAX, CREATE_PROCESS, with_create_name,
    };

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
    fn an_install_path_is_the_requested_name()
    {
        let label = CREATE_FROM_FILE | CREATE_MEMORY_MAX;
        let msg = request(label, b"/services/svcmgr");
        assert_eq!(requested_name(&msg), Some(&b"/services/svcmgr"[..]));
        let msg = request(CREATE_PROCESS, b"/services/devmgr");
        assert_eq!(requested_name(&msg), Some(&b"/services/devmgr"[..]));
    }

    // Defect guarded: a creator passing a name that names the file another
    // way, or none, and procmgr verifying under it; or a slot name or a
    // bundle entry name of the earlier format, under which no process
    // image is signed.
    #[test]
    fn a_name_that_is_not_a_canonical_install_path_or_missing_is_refused()
    {
        for label in [CREATE_FROM_FILE, CREATE_PROCESS]
        {
            for name in [
                &b"/services//svcmgr"[..],
                b"services/svcmgr",
                b"/services/../svcmgr",
                b"a\0",
                b"init",
                b"kernel",
                b"devmgr",
                b"trust-store",
            ]
            {
                assert_eq!(requested_name(&request(label, name)), None, "{name:?}");
            }
        }
        let bare = IpcMessage::builder(CREATE_FROM_FILE).word(0, 4096).build();
        assert_eq!(requested_name(&bare), None);
    }

    // Defect guarded: a creator's set holding the boot-module role, so a
    // bundle entry starts as a boot module, not in the role it runs in.
    #[test]
    fn the_unbadged_set_holds_every_runtime_role_and_nothing_else()
    {
        for role in Role::ALL
        {
            let process = matches!(role, Role::Service | Role::Driver | Role::Program);
            assert_eq!(LOADABLE.contains(role), process, "{role:?}");
        }
    }

    #[test]
    fn a_program_child_creates_programs_only()
    {
        let program = RoleSet::of(&[Role::Program]);
        let roles = child_roles(LOADABLE, program);
        assert_eq!(roles, program);
        // Its own program children keep that set.
        assert_eq!(child_roles(roles, program), roles);
        // A set that holds program beside another role narrows too.
        let both = RoleSet::of(&[Role::Program, Role::BootModule]);
        assert_eq!(child_roles(LOADABLE, both), program);
    }

    #[test]
    fn a_system_child_keeps_its_creators_set()
    {
        for roles in [
            RoleSet::of(&[Role::Service]),
            RoleSet::of(&[Role::Service, Role::BootModule]),
            RoleSet::of(&[Role::Driver, Role::BootModule]),
        ]
        {
            assert_eq!(child_roles(LOADABLE, roles), LOADABLE, "{roles:?}");
        }
    }

    #[test]
    fn no_child_set_is_wider_than_its_creators()
    {
        let creators = [
            RoleSet::EMPTY,
            RoleSet::of(&[Role::Program]),
            RoleSet::of(&[Role::Service, Role::Driver]),
            LOADABLE,
        ];
        for creator in creators
        {
            for bits in 0..=u8::MAX
            {
                let Some(roles) = RoleSet::from_signed(bits)
                else
                {
                    continue;
                };
                let child = child_roles(creator, roles);
                assert!(child.is_subset(creator), "{creator:?} {roles:?}");
            }
        }
    }
}
