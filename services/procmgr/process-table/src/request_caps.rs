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
//! and argv/env caps are peeled off the tail), so it lives here, host-tested.

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
    /// The last cap when `CREATE_DEATH_RELAY` is set; zero otherwise.
    pub relay: u64,
    /// Caps the layout does not name, which procmgr deletes.
    pub extra: &'a [u64],
}

/// The tail caps a create label flags: whether the request carries the
/// argv/env Memory cap (`CREATE_ARGV_ENV`) and the death-relay cap
/// (`CREATE_DEATH_RELAY`) after its creator endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CreateTailCaps
{
    /// The label sets `CREATE_ARGV_ENV`.
    pub argv_env: bool,
    /// The label sets `CREATE_DEATH_RELAY` and the opcode honours it.
    pub death_relay: bool,
}

impl CreateTailCaps
{
    /// The tail caps of a `CREATE_PROCESS` label, which ignores
    /// `CREATE_DEATH_RELAY`.
    #[must_use]
    pub const fn of_create_process(label: u64) -> Self
    {
        Self {
            argv_env: label & procmgr_labels::CREATE_ARGV_ENV != 0,
            death_relay: false,
        }
    }

    /// The tail caps of a `CREATE_FROM_FILE` label.
    #[must_use]
    pub const fn of_create_from_file(label: u64) -> Self
    {
        Self {
            argv_env: label & procmgr_labels::CREATE_ARGV_ENV != 0,
            death_relay: label & procmgr_labels::CREATE_DEATH_RELAY != 0,
        }
    }
}

/// Split the caps of a create request whose label flags `tail`.
///
/// The relay cap is then the last cap and the argv/env cap the one before it
/// (or the last, without a relay); each must be a cap of its own, so a
/// request needs one cap past the source cap for each tail cap it flags. The
/// creator endpoint is cap[1] when a cap sits between the source cap and the
/// flagged tail caps; every cap after it, up to them, is extra.
///
/// Returns `None` when no cap arrived, cap[0] is zero, or the label flags
/// more tail caps than arrived after the source cap. The caller then
/// releases every transferred cap and refuses the request.
#[must_use]
pub fn split_create_caps(caps: &[u64], tail: CreateTailCaps) -> Option<CreateCaps<'_>>
{
    let (&source, rest) = caps.split_first()?;
    if source == 0
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
    let (middle, argv_env) = if tail.argv_env
    {
        let (&argv_env, middle) = rest.split_last()?;
        (middle, argv_env)
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
        relay,
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
    };
    const RELAY: CreateTailCaps = CreateTailCaps {
        argv_env: false,
        death_relay: true,
    };
    const ARGV: CreateTailCaps = CreateTailCaps {
        argv_env: true,
        death_relay: false,
    };
    const BOTH: CreateTailCaps = CreateTailCaps {
        argv_env: true,
        death_relay: true,
    };

    // Defect guarded: a label decode that reads a tail flag from the wrong
    // bit, or honours the relay on `CREATE_PROCESS`, which ignores it.
    #[test]
    fn tail_caps_follow_the_label_flags()
    {
        use ipc::procmgr_labels::{CREATE_ARGV_ENV, CREATE_DEATH_RELAY};
        let label = CREATE_ARGV_ENV | CREATE_DEATH_RELAY;
        assert_eq!(CreateTailCaps::of_create_from_file(label), BOTH);
        assert_eq!(CreateTailCaps::of_create_process(label), ARGV);
        assert_eq!(
            CreateTailCaps::of_create_from_file(CREATE_DEATH_RELAY),
            RELAY
        );
        assert_eq!(CreateTailCaps::of_create_process(0), NONE);
    }

    fn caps(
        source: u64,
        creator: u64,
        argv_env: u64,
        relay: u64,
        extra: &[u64],
    ) -> Option<CreateCaps<'_>>
    {
        Some(CreateCaps {
            source,
            creator,
            argv_env,
            relay,
            extra,
        })
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
        assert_eq!(split_create_caps(&[5, 9], RELAY), caps(5, 0, 0, 9, &[]));
        assert_eq!(split_create_caps(&[5, 6, 9], RELAY), caps(5, 6, 0, 9, &[]));
        assert_eq!(split_create_caps(&[5, 8], ARGV), caps(5, 0, 8, 0, &[]));
        assert_eq!(split_create_caps(&[5, 6, 8], ARGV), caps(5, 6, 8, 0, &[]));
        assert_eq!(split_create_caps(&[5, 8, 9], BOTH), caps(5, 0, 8, 9, &[]));
        assert_eq!(
            split_create_caps(&[5, 6, 8, 9], BOTH),
            caps(5, 6, 8, 9, &[])
        );
    }

    #[test]
    fn caps_the_layout_does_not_name_are_extra()
    {
        assert_eq!(
            split_create_caps(&[5, 6, 7, 9], RELAY),
            caps(5, 6, 0, 9, &[7])
        );
        assert_eq!(
            split_create_caps(&[5, 6, 7, 8], NONE),
            caps(5, 6, 0, 0, &[7, 8])
        );
        assert_eq!(
            split_create_caps(&[5, 6, 7, 8], ARGV),
            caps(5, 6, 8, 0, &[7])
        );
        assert_eq!(split_create_caps(&[5], NONE), caps(5, 0, 0, 0, &[]));
    }
}
