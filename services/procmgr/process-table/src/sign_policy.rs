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
/// `kernel`, `init` and `trust-request` name objects the bootloader alone
/// loads.
#[must_use]
pub fn requested_name(req: &IpcMessage) -> Option<&[u8]>
{
    ipc::procmgr_labels::create_name(req).filter(|name| objsig::name_is_install_path(name))
}

/// The role a `READ_VERIFIED` request's role word names
/// (`ipc::procmgr_labels::READ_VERIFIED_ROLE_WORD`): data or configuration,
/// the two roles of a file a reader takes as trusted input, or driver, an
/// image whose declaration its reader parses before it creates the driver
/// from the same run (docs/driver-binding.md § Driver Declarations). `None`
/// for any other value, so a service or program image or a bundle-only
/// object is never handed to a reader. A file read this way is never code to
/// its reader: only a create runs a driver image, verified again.
#[must_use]
pub const fn readable_role(word: u64) -> Option<Role>
{
    match word
    {
        ipc::procmgr_labels::READ_VERIFIED_DATA => Some(Role::Data),
        ipc::procmgr_labels::READ_VERIFIED_CONFIGURATION => Some(Role::Configuration),
        ipc::procmgr_labels::READ_VERIFIED_DRIVER => Some(Role::Driver),
        _ => None,
    }
}

/// The most bytes a `READ_VERIFIED` file in `role` may hold, its trailer
/// included: `READ_VERIFIED_IMAGE_MAX` for a driver image,
/// `READ_VERIFIED_MAX` for a data or configuration file.
#[must_use]
pub const fn read_bound(role: Role) -> u64
{
    match role
    {
        Role::Driver => ipc::procmgr_labels::READ_VERIFIED_IMAGE_MAX,
        Role::Kernel
        | Role::Init
        | Role::BootModule
        | Role::Service
        | Role::Program
        | Role::Data
        | Role::Configuration
        | Role::Enrolment => ipc::procmgr_labels::READ_VERIFIED_MAX,
    }
}

/// What a checked `READ_VERIFIED` request asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedRead<'a>
{
    /// The file's length in bytes, 1 to the role's [`read_bound`].
    pub len: u64,
    /// The role the file must be signed in ([`readable_role`]).
    pub role: Role,
    /// The install path the file must be signed under.
    pub name: &'a [u8],
}

impl VerifiedRead<'_>
{
    /// The roles the copy is verified in: [`Self::role`] alone.
    #[must_use]
    pub const fn roles(&self) -> RoleSet
    {
        RoleSet::of(&[self.role])
    }

    /// Whether a sender whose signature policy is `policy` may make the
    /// read: a data or configuration file any sender may; a driver image only
    /// a sender whose policy loads drivers, for which the read is the first
    /// half of a create it may make.
    #[must_use]
    pub const fn admitted_by(&self, policy: RoleSet) -> bool
    {
        match self.role
        {
            Role::Data | Role::Configuration => true,
            role @ (Role::Kernel
            | Role::Init
            | Role::BootModule
            | Role::Service
            | Role::Driver
            | Role::Program
            | Role::Enrolment) => policy.contains(role),
        }
    }
}

/// The read a `READ_VERIFIED` request `req` asks for: its length,
/// `data[0]`, when it is 1 to its role's [`read_bound`];
/// its role word, when it names a [`readable_role`]; and its name block,
/// when that is a canonical install path (`objsig::name_is_install_path`).
/// `None`, which procmgr refuses `INVALID_ARGUMENT` before it opens the
/// file, otherwise: a length past the bound would have procmgr reserve and
/// map a copy the request does not bound.
#[must_use]
pub fn verified_read(req: &IpcMessage) -> Option<VerifiedRead<'_>>
{
    use ipc::procmgr_labels::READ_VERIFIED_ROLE_WORD;
    let len = req.word(0);
    if req.word_count() <= READ_VERIFIED_ROLE_WORD || len == 0
    {
        return None;
    }
    let role = readable_role(req.word(READ_VERIFIED_ROLE_WORD))?;
    if len > read_bound(role)
    {
        return None;
    }
    let name = ipc::procmgr_labels::read_verified_name(req)
        .filter(|name| objsig::name_is_install_path(name))?;
    Some(VerifiedRead { len, role, name })
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

    fn data_request(len: u64, name: &[u8]) -> IpcMessage
    {
        role_request(len, ipc::procmgr_labels::READ_VERIFIED_DATA, name)
    }

    fn role_request(len: u64, role: u64, name: &[u8]) -> IpcMessage
    {
        use ipc::procmgr_labels::{
            READ_VERIFIED, READ_VERIFIED_NAME_WORD, READ_VERIFIED_ROLE_WORD,
        };
        let builder = IpcMessage::builder(READ_VERIFIED)
            .word(0, len)
            .word(READ_VERIFIED_ROLE_WORD, role);
        ipc::with_name_block(builder, READ_VERIFIED_NAME_WORD, name, CREATE_NAME_MAX)
            .unwrap()
            .build()
    }

    #[test]
    fn a_read_within_the_bound_under_an_install_path_is_admitted()
    {
        use ipc::procmgr_labels::{READ_VERIFIED_CONFIGURATION, READ_VERIFIED_MAX};
        let name = &b"/config/devmgr/platform/qemu-virt.platform"[..];
        for len in [1, 4096, READ_VERIFIED_MAX]
        {
            assert_eq!(
                verified_read(&data_request(len, name)),
                Some(VerifiedRead {
                    len,
                    role: Role::Data,
                    name
                }),
                "{len}"
            );
        }
        let name = &b"/config/svcmgr/services/index"[..];
        let request = role_request(64, READ_VERIFIED_CONFIGURATION, name);
        let read = verified_read(&request).unwrap();
        assert_eq!(read.roles(), RoleSet::of(&[Role::Configuration]));
    }

    // Defect guarded: a request past the size bound, or of no bytes, reaching
    // the read, so procmgr reserves and maps a copy no bound limits; a
    // request whose name names the file another way reaching the verifier.
    #[test]
    fn a_read_past_the_bound_empty_or_misnamed_is_refused()
    {
        use ipc::procmgr_labels::{READ_VERIFIED, READ_VERIFIED_MAX};
        let name = &b"/data/x"[..];
        assert_eq!(verified_read(&data_request(0, name)), None);
        assert_eq!(
            verified_read(&data_request(READ_VERIFIED_MAX + 1, name)),
            None
        );
        assert_eq!(verified_read(&data_request(u64::MAX, name)), None);
        for name in [&b"/data//x"[..], b"data/x", b"init", b"kernel"]
        {
            assert_eq!(verified_read(&data_request(64, name)), None, "{name:?}");
        }
        let bare = IpcMessage::builder(READ_VERIFIED).word(0, 64).build();
        assert_eq!(verified_read(&bare), None);
        assert_eq!(verified_read(&IpcMessage::new(READ_VERIFIED)), None);
    }

    // Defect guarded: a verified read accepting a service, program or bundle
    // role, so a reader is handed a signed program as input it trusts; or a
    // role word read in another numbering than the signed one.
    #[test]
    fn a_read_names_the_data_configuration_or_driver_role_alone()
    {
        for role in Role::ALL
        {
            let readable = matches!(role, Role::Data | Role::Configuration | Role::Driver);
            assert_eq!(
                readable_role(role as u64),
                readable.then_some(role),
                "{role:?}"
            );
            let request = role_request(64, role as u64, b"/data/x");
            assert_eq!(verified_read(&request).is_some(), readable, "{role:?}");
        }
        for word in [0, 10, 31, u64::MAX]
        {
            assert_eq!(readable_role(word), None, "{word}");
        }
    }

    // Defect guarded: a driver image refused at the data bound, so no
    // driver larger than 32 KiB binds; or a data or configuration read
    // admitted past its own bound, so procmgr maps a copy as large as an
    // image for a file that holds a table.
    #[test]
    fn a_driver_read_takes_the_image_bound_and_the_others_the_data_bound()
    {
        use ipc::procmgr_labels::{
            READ_VERIFIED_DRIVER, READ_VERIFIED_IMAGE_MAX, READ_VERIFIED_MAX,
        };
        let name = &b"/services/drivers/virtio-rng"[..];
        for len in [READ_VERIFIED_MAX + 1, READ_VERIFIED_IMAGE_MAX]
        {
            let request = role_request(len, READ_VERIFIED_DRIVER, name);
            let read = verified_read(&request);
            assert_eq!(read.map(|read| read.role), Some(Role::Driver), "{len}");
            assert_eq!(verified_read(&data_request(len, name)), None, "{len}");
        }
        let past = role_request(READ_VERIFIED_IMAGE_MAX + 1, READ_VERIFIED_DRIVER, name);
        assert_eq!(verified_read(&past), None);
        assert_eq!(read_bound(Role::Driver), READ_VERIFIED_IMAGE_MAX);
        for role in [Role::Data, Role::Configuration]
        {
            assert_eq!(read_bound(role), READ_VERIFIED_MAX, "{role:?}");
        }
    }

    // Defect guarded: a process whose policy loads no driver reading a
    // driver image through procmgr, so a program is handed a signed driver's
    // bytes it could never run; or a data or configuration read refused to a
    // sender whose policy holds neither role, which every reader is.
    #[test]
    fn a_driver_read_is_admitted_only_to_a_policy_that_loads_drivers()
    {
        use ipc::procmgr_labels::READ_VERIFIED_DRIVER;
        let driver = role_request(64, READ_VERIFIED_DRIVER, b"/services/drivers/x");
        let driver = verified_read(&driver).unwrap();
        assert!(driver.admitted_by(LOADABLE));
        assert!(driver.admitted_by(RoleSet::of(&[Role::Driver])));
        let program = RoleSet::of(&[Role::Program]);
        for policy in [program, child_roles(LOADABLE, program), RoleSet::EMPTY]
        {
            assert!(!driver.admitted_by(policy), "{policy:?}");
        }
        let data = data_request(64, b"/data/x");
        assert!(verified_read(&data).unwrap().admitted_by(RoleSet::EMPTY));
        let configuration = role_request(
            64,
            ipc::procmgr_labels::READ_VERIFIED_CONFIGURATION,
            b"/config/x",
        );
        assert!(verified_read(&configuration).unwrap().admitted_by(program));
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
            // Every signed set lies within 0..=RoleSet::ALL, whose highest bit is the
            // highest defined role.
            for bits in 0..=RoleSet::ALL.bits()
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
