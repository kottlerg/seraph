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

/// Split the caps of a create request.
///
/// `argv_env` is whether the label sets `CREATE_ARGV_ENV`, `death_relay`
/// whether it sets `CREATE_DEATH_RELAY` (always `false` for
/// `CREATE_PROCESS`, which ignores the bit). The relay cap is then the last
/// cap and the argv/env cap the one before it (or the last, without a
/// relay); each must be a cap of its own, so a request needs one cap past
/// the source cap for each flag it sets. The creator endpoint is cap[1]
/// when a cap sits between the source cap and the flagged tail caps; every
/// cap after it, up to them, is extra.
///
/// Returns `None` when no cap arrived, cap[0] is zero, or the flags name
/// more tail caps than arrived after the source cap. The caller then
/// releases every transferred cap and refuses the request.
#[must_use]
pub fn split_create_caps(caps: &[u64], argv_env: bool, death_relay: bool)
-> Option<CreateCaps<'_>>
{
    let (&source, rest) = caps.split_first()?;
    if source == 0
    {
        return None;
    }
    let (rest, relay) = peel_last(rest, death_relay)?;
    let (middle, argv_env) = peel_last(rest, argv_env)?;
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

/// Take the last cap of `caps` when `present`, as a flagged tail cap.
/// `None` when it is flagged but no cap is left for it.
fn peel_last(caps: &[u64], present: bool) -> Option<(&[u64], u64)>
{
    if !present
    {
        return Some((caps, 0));
    }
    let (&last, rest) = caps.split_last()?;
    Some((rest, last))
}

#[cfg(test)]
mod tests
{
    use super::*;

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
        assert_eq!(split_create_caps(&[5], false, true), None);
        assert_eq!(split_create_caps(&[5], true, false), None);
        // Both flags need two caps past the source cap.
        assert_eq!(split_create_caps(&[5, 9], true, true), None);
    }

    #[test]
    fn missing_or_zero_source_cap_is_rejected()
    {
        assert_eq!(split_create_caps(&[], false, false), None);
        assert_eq!(split_create_caps(&[], true, true), None);
        assert_eq!(split_create_caps(&[0, 6], false, false), None);
    }

    #[test]
    fn tail_caps_peel_off_the_end_and_creator_stays_at_cap_one()
    {
        assert_eq!(
            split_create_caps(&[5, 9], false, true),
            caps(5, 0, 0, 9, &[])
        );
        assert_eq!(
            split_create_caps(&[5, 6, 9], false, true),
            caps(5, 6, 0, 9, &[])
        );
        assert_eq!(
            split_create_caps(&[5, 8], true, false),
            caps(5, 0, 8, 0, &[])
        );
        assert_eq!(
            split_create_caps(&[5, 6, 8], true, false),
            caps(5, 6, 8, 0, &[])
        );
        assert_eq!(
            split_create_caps(&[5, 8, 9], true, true),
            caps(5, 0, 8, 9, &[])
        );
        assert_eq!(
            split_create_caps(&[5, 6, 8, 9], true, true),
            caps(5, 6, 8, 9, &[])
        );
    }

    #[test]
    fn caps_the_layout_does_not_name_are_extra()
    {
        assert_eq!(
            split_create_caps(&[5, 6, 7, 9], false, true),
            caps(5, 6, 0, 9, &[7])
        );
        assert_eq!(
            split_create_caps(&[5, 6, 7, 8], false, false),
            caps(5, 6, 0, 0, &[7, 8])
        );
        assert_eq!(
            split_create_caps(&[5, 6, 7, 8], true, false),
            caps(5, 6, 8, 0, &[7])
        );
        assert_eq!(split_create_caps(&[5], false, false), caps(5, 0, 0, 0, &[]));
    }
}
