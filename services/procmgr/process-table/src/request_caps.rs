// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/procmgr/process-table/src/request_caps.rs

//! Positional cap layouts of procmgr requests.
//!
//! Every cap a request transfers lands in procmgr's `CSpace`, whether or not
//! the request's wire layout names it (`services/procmgr/docs/ipc-interface.md`
//! § Capability Transfer). The handlers therefore split the transferred caps
//! into the ones the layout names and the rest, which procmgr deletes. The
//! `CREATE_FROM_FILE` split is the one with a client-controlled shape (the
//! death-relay cap is peeled off the tail), so it lives here, host-tested.

/// The caps a `CREATE_FROM_FILE` request transfers, split by role.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileCreateCaps<'a>
{
    /// cap[0]: the file cap for the binary (nonzero).
    pub file: u32,
    /// cap[1]: the optional creator endpoint; zero when absent.
    pub creator: u32,
    /// The last cap when `CREATE_DEATH_RELAY` is set; zero otherwise.
    pub relay: u32,
    /// Caps the layout does not name, which procmgr deletes.
    pub extra: &'a [u32],
}

/// Split the caps of a `CREATE_FROM_FILE` request.
///
/// `death_relay` is whether the label sets `CREATE_DEATH_RELAY`. The relay
/// cap is then the last cap, and it must be a cap of its own: a message whose
/// only cap is the file cap cannot also carry the relay, so a relay request
/// needs at least two caps. The creator endpoint is cap[1] when a cap sits
/// between the file cap and the relay (or after the file cap when there is
/// no relay); every cap after it, up to the relay, is extra.
///
/// Returns `None` when no cap arrived, cap[0] is zero, or the relay flag is
/// set on a single-cap message. The caller then releases every transferred
/// cap and replies `INVALID_ARGUMENT`.
#[must_use]
pub fn split_create_from_file_caps(caps: &[u32], death_relay: bool) -> Option<FileCreateCaps<'_>>
{
    let (&file, rest) = caps.split_first()?;
    if file == 0
    {
        return None;
    }
    let (middle, relay) = if death_relay
    {
        let (&relay, middle) = rest.split_last()?;
        (middle, relay)
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
    Some(FileCreateCaps {
        file,
        creator,
        relay,
        extra,
    })
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn relay_flag_on_a_single_cap_message_is_rejected()
    {
        // The one cap is the file cap; taking it as the relay as well would
        // release one slot twice.
        assert_eq!(split_create_from_file_caps(&[5], true), None);
    }

    #[test]
    fn missing_or_zero_file_cap_is_rejected()
    {
        assert_eq!(split_create_from_file_caps(&[], false), None);
        assert_eq!(split_create_from_file_caps(&[], true), None);
        assert_eq!(split_create_from_file_caps(&[0, 6], false), None);
    }

    #[test]
    fn relay_is_the_last_cap_and_creator_stays_at_cap_one()
    {
        assert_eq!(
            split_create_from_file_caps(&[5, 9], true),
            Some(FileCreateCaps {
                file: 5,
                creator: 0,
                relay: 9,
                extra: &[],
            })
        );
        assert_eq!(
            split_create_from_file_caps(&[5, 6, 9], true),
            Some(FileCreateCaps {
                file: 5,
                creator: 6,
                relay: 9,
                extra: &[],
            })
        );
    }

    #[test]
    fn caps_the_layout_does_not_name_are_extra()
    {
        assert_eq!(
            split_create_from_file_caps(&[5, 6, 7, 9], true),
            Some(FileCreateCaps {
                file: 5,
                creator: 6,
                relay: 9,
                extra: &[7],
            })
        );
        assert_eq!(
            split_create_from_file_caps(&[5, 6, 7, 8], false),
            Some(FileCreateCaps {
                file: 5,
                creator: 6,
                relay: 0,
                extra: &[7, 8],
            })
        );
        assert_eq!(
            split_create_from_file_caps(&[5], false),
            Some(FileCreateCaps {
                file: 5,
                creator: 0,
                relay: 0,
                extra: &[],
            })
        );
    }
}
