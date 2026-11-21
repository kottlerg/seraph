// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/procmgr/process-table/src/request_caps.rs

//! Positional cap layouts of procmgr requests.
//!
//! Every cap a request transfers lands in procmgr's `CSpace`, whether or not
//! the request's wire layout names it (`services/procmgr/docs/ipc-interface.md`
//! § Capability Transfer). The handlers therefore split the transferred caps
//! into the ones the layout names and the rest, which procmgr deletes. The
//! create split is the one with a client-controlled shape (the death-relay
//! cap, and the argv/env Memory cap or the snapshot's object handle, are
//! peeled off the tail), so it lives here, host-tested.

use ipc::procmgr_labels;

/// The caps a `CREATE_PROCESS` or `CREATE_FROM_FILE` request transfers,
/// split by role.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CreateCaps<'a>
{
    /// cap[0]: the module Memory cap or the binary's file cap (nonzero).
    pub source: u64,
    /// cap[1]: the optional creator endpoint; zero when absent.
    pub creator: u64,
    /// The argv/env Memory cap when `CREATE_ARGV_ENV` is set: the last cap
    /// before the relay, or the last cap without one. Zero otherwise.
    pub argv_env: u64,
    /// The snapshot's object handle when `CREATE_RESTORE` is set, in the
    /// argv/env cap's place, which a restore does not carry. Zero otherwise.
    pub snapshot: u64,
    /// The last cap when `CREATE_DEATH_RELAY` is set; zero otherwise.
    pub relay: u64,
    /// The node handle when `CREATE_CHARGE_NODE` is set: the cap before the
    /// argv/env cap or the snapshot handle, before the relay without one, or
    /// the last without either. Zero otherwise.
    pub charge: u64,
    /// Caps the layout does not name, which procmgr deletes.
    pub extra: &'a [u64],
}

/// The tail caps a create label flags: whether the request carries the
/// charge node's handle (`CREATE_CHARGE_NODE`), the argv/env Memory cap
/// (`CREATE_ARGV_ENV`) or the snapshot's object handle (`CREATE_RESTORE`),
/// and the death-relay cap (`CREATE_DEATH_RELAY`) after its creator
/// endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "each field is one independent label flag, read as the label sets it"
)]
pub struct CreateTailCaps
{
    /// The label sets `CREATE_ARGV_ENV`.
    pub argv_env: bool,
    /// The label sets `CREATE_DEATH_RELAY`.
    pub death_relay: bool,
    /// The label sets `CREATE_CHARGE_NODE`.
    pub charge_node: bool,
    /// The label sets `CREATE_RESTORE`.
    pub restore: bool,
}

impl CreateTailCaps
{
    /// The tail caps of a `CREATE_PROCESS` or `CREATE_FROM_FILE` label: both
    /// opcodes read the four flags alike.
    #[must_use]
    pub const fn of_create(label: u64) -> Self
    {
        Self {
            argv_env: label & procmgr_labels::CREATE_ARGV_ENV != 0,
            death_relay: label & procmgr_labels::CREATE_DEATH_RELAY != 0,
            charge_node: label & procmgr_labels::CREATE_CHARGE_NODE != 0,
            restore: label & procmgr_labels::CREATE_RESTORE != 0,
        }
    }
}

/// Split the caps of a create request whose label flags `tail`.
///
/// The relay cap is then the last cap, the argv/env cap or the snapshot
/// handle the one before it (or the last, without a relay), and the charge
/// node's handle the one before those it follows; each must be a cap of its
/// own, so a
/// request needs one cap past the source cap for each tail cap it flags. The
/// creator endpoint is cap[1] when a cap sits between the source cap and the
/// flagged tail caps; every cap after it, up to them, is extra.
///
/// Returns `None` when no cap arrived, cap[0] is zero, the label flags
/// more tail caps than arrived after the source cap, or it flags both
/// `CREATE_ARGV_ENV` and `CREATE_RESTORE`, since a restore carries the
/// checkpoint's argv and env (docs/checkpoint-restore.md § Restore creation).
/// The caller then releases every transferred cap and refuses the request.
#[must_use]
pub fn split_create_caps(caps: &[u64], tail: CreateTailCaps) -> Option<CreateCaps<'_>>
{
    let (&source, rest) = caps.split_first()?;
    if source == 0 || (tail.argv_env && tail.restore)
    {
        return None;
    }
    let (rest, relay) = if tail.death_relay
    {
        let (&relay, rest) = rest.split_last()?;
        (rest, relay)
    }
    else
    {
        (rest, 0)
    };
    let (rest, blob) = if tail.argv_env || tail.restore
    {
        let (&blob, rest) = rest.split_last()?;
        (rest, blob)
    }
    else
    {
        (rest, 0)
    };
    let (argv_env, snapshot) = if tail.restore { (0, blob) } else { (blob, 0) };
    let (middle, charge) = if tail.charge_node
    {
        let (&charge, middle) = rest.split_last()?;
        (middle, charge)
    }
    else
    {
        (rest, 0)
    };
    let (creator, extra) = match middle.split_first()
    {
        Some((&creator, extra)) => (creator, extra),
        None => (0, middle),
    };
    Some(CreateCaps {
        source,
        creator,
        argv_env,
        snapshot,
        relay,
        charge,
        extra,
    })
}

#[cfg(test)]
mod tests
{
    use super::*;

    const NONE: CreateTailCaps = CreateTailCaps {
        argv_env: false,
        death_relay: false,
        charge_node: false,
        restore: false,
    };
    const RELAY: CreateTailCaps = CreateTailCaps {
        death_relay: true,
        ..NONE
    };
    const ARGV: CreateTailCaps = CreateTailCaps {
        argv_env: true,
        ..NONE
    };
    const BOTH: CreateTailCaps = CreateTailCaps {
        argv_env: true,
        death_relay: true,
        ..NONE
    };

    // Defect guarded: a label decode that reads a tail flag from the wrong
    // bit, or ignores the relay on one of the two create opcodes.
    #[test]
    fn tail_caps_follow_the_label_flags()
    {
        use ipc::procmgr_labels::{
            CREATE_ARGV_ENV, CREATE_DEATH_RELAY, CREATE_FROM_FILE, CREATE_PROCESS,
        };
        for opcode in [CREATE_PROCESS, CREATE_FROM_FILE]
        {
            let label = opcode | CREATE_ARGV_ENV | CREATE_DEATH_RELAY;
            assert_eq!(CreateTailCaps::of_create(label), BOTH);
            assert_eq!(
                CreateTailCaps::of_create(opcode | CREATE_DEATH_RELAY),
                RELAY
            );
            assert_eq!(CreateTailCaps::of_create(opcode | CREATE_ARGV_ENV), ARGV);
            assert_eq!(CreateTailCaps::of_create(opcode), NONE);
        }
    }

    // Defect guarded: a `CREATE_PROCESS` that flags the relay without a cap
    // of its own taken as well-formed, so the module or creator cap is bound
    // as the relay and released twice; the handler answers `None` with
    // `INVALID_ARGUMENT` (`services/procmgr/docs/ipc-interface.md` § Label 1).
    #[test]
    fn create_process_relay_without_its_cap_is_rejected()
    {
        use ipc::procmgr_labels::{CREATE_ARGV_ENV, CREATE_DEATH_RELAY, CREATE_PROCESS};
        let relay = CreateTailCaps::of_create(CREATE_PROCESS | CREATE_DEATH_RELAY);
        assert_eq!(split_create_caps(&[5], relay), None);
        let both = CreateTailCaps::of_create(CREATE_PROCESS | CREATE_DEATH_RELAY | CREATE_ARGV_ENV);
        assert_eq!(split_create_caps(&[5, 8], both), None);
        assert_eq!(
            split_create_caps(&[5, 6, 9], relay),
            Some(caps(5, 6, 0, 9, &[]))
        );
    }

    fn caps(source: u64, creator: u64, argv_env: u64, relay: u64, extra: &[u64]) -> CreateCaps<'_>
    {
        CreateCaps {
            source,
            creator,
            argv_env,
            snapshot: 0,
            relay,
            charge: 0,
            extra,
        }
    }

    // Defect guarded: a restore's object handle taken from the wrong
    // position, or bound as an argv/env cap, or a restore that also carries
    // argv and env taken as well-formed.
    #[test]
    fn a_restore_takes_its_object_handle_in_the_argv_env_place()
    {
        use ipc::procmgr_labels::{
            CREATE_ARGV_ENV, CREATE_CHARGE_NODE, CREATE_DEATH_RELAY, CREATE_PROCESS, CREATE_RESTORE,
        };
        let restore = CreateTailCaps::of_create(CREATE_PROCESS | CREATE_RESTORE);
        assert!(restore.restore && !restore.argv_env);
        let split = split_create_caps(&[5, 6, 8], restore).unwrap();
        assert_eq!((split.creator, split.argv_env, split.snapshot), (6, 0, 8));
        let all = CreateTailCaps::of_create(
            CREATE_PROCESS | CREATE_RESTORE | CREATE_DEATH_RELAY | CREATE_CHARGE_NODE,
        );
        let split = split_create_caps(&[5, 7, 8, 9], all).unwrap();
        assert_eq!(
            (split.charge, split.snapshot, split.relay, split.argv_env),
            (7, 8, 9, 0)
        );
        assert_eq!(split_create_caps(&[5], restore), None);
        let both = CreateTailCaps::of_create(CREATE_PROCESS | CREATE_RESTORE | CREATE_ARGV_ENV);
        assert_eq!(split_create_caps(&[5, 6, 8], both), None);
    }

    #[test]
    fn flagged_tail_caps_without_their_own_slot_are_rejected()
    {
        // The one cap is the source cap; taking it as a tail cap as well
        // would release one slot twice.
        assert_eq!(split_create_caps(&[5], RELAY), None);
        assert_eq!(split_create_caps(&[5], ARGV), None);
        // Both flags need two caps past the source cap.
        assert_eq!(split_create_caps(&[5, 9], BOTH), None);
    }

    #[test]
    fn missing_or_zero_source_cap_is_rejected()
    {
        assert_eq!(split_create_caps(&[], NONE), None);
        assert_eq!(split_create_caps(&[], BOTH), None);
        assert_eq!(split_create_caps(&[0, 6], NONE), None);
    }

    #[test]
    fn tail_caps_peel_off_the_end_and_creator_stays_at_cap_one()
    {
        assert_eq!(
            split_create_caps(&[5, 9], RELAY),
            Some(caps(5, 0, 0, 9, &[]))
        );
        assert_eq!(
            split_create_caps(&[5, 6, 9], RELAY),
            Some(caps(5, 6, 0, 9, &[]))
        );
        assert_eq!(
            split_create_caps(&[5, 8], ARGV),
            Some(caps(5, 0, 8, 0, &[]))
        );
        assert_eq!(
            split_create_caps(&[5, 6, 8], ARGV),
            Some(caps(5, 6, 8, 0, &[]))
        );
        assert_eq!(
            split_create_caps(&[5, 8, 9], BOTH),
            Some(caps(5, 0, 8, 9, &[]))
        );
        assert_eq!(
            split_create_caps(&[5, 6, 8, 9], BOTH),
            Some(caps(5, 6, 8, 9, &[]))
        );
    }

    #[test]
    fn caps_the_layout_does_not_name_are_extra()
    {
        assert_eq!(
            split_create_caps(&[5, 6, 7, 9], RELAY),
            Some(caps(5, 6, 0, 9, &[7]))
        );
        assert_eq!(
            split_create_caps(&[5, 6, 7, 8], NONE),
            Some(caps(5, 6, 0, 0, &[7, 8]))
        );
        assert_eq!(
            split_create_caps(&[5, 6, 7, 8], ARGV),
            Some(caps(5, 6, 8, 0, &[7]))
        );
        assert_eq!(split_create_caps(&[5], NONE), Some(caps(5, 0, 0, 0, &[])));
    }

    // Defect guarded: the charge node's handle taken from the wrong position,
    // so procmgr charges the child to a node the creator did not name or
    // hands memmgr the argv/env or relay cap as the handle.
    #[test]
    fn the_charge_node_precedes_the_argv_env_and_relay_caps()
    {
        use ipc::procmgr_labels::{
            CREATE_ARGV_ENV, CREATE_CHARGE_NODE, CREATE_DEATH_RELAY, CREATE_FROM_FILE,
        };
        let all = CreateTailCaps::of_create(
            CREATE_FROM_FILE | CREATE_CHARGE_NODE | CREATE_ARGV_ENV | CREATE_DEATH_RELAY,
        );
        assert!(all.charge_node);
        let split = split_create_caps(&[5, 6, 7, 8], all).unwrap();
        assert_eq!(
            (
                split.source,
                split.creator,
                split.charge,
                split.argv_env,
                split.relay
            ),
            (5, 0, 6, 7, 8)
        );
        let charge = CreateTailCaps::of_create(CREATE_FROM_FILE | CREATE_CHARGE_NODE);
        let split = split_create_caps(&[5, 6, 7], charge).unwrap();
        assert_eq!((split.creator, split.charge, split.extra), (6, 7, &[][..]));
        // The handle needs a cap of its own past the source cap.
        assert_eq!(split_create_caps(&[5], charge), None);
        assert_eq!(split_create_caps(&[5, 7, 8], all), None);
    }
}
