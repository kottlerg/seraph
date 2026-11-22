// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/death-set/src/members.rs

//! The member count of the main wait set [`crate::DeathSet`] creates with a
//! service endpoint: pure, so its overflow is host-tested here.

use death_queues::queues::FIRST_WAIT_SET_MEMBERS;

/// The members of the first main wait set of a set with room for `members`
/// members of the caller's beside its service endpoint, and for at least one
/// queue: those `members + 2` rounded up to a power of two, as every
/// replacement doubles them, and at least `FIRST_WAIT_SET_MEMBERS`. Returns
/// the members the set reserves room for other than the queues
/// (`members + 1`) and the wait set's member count, or `None` when either
/// overflows a `u32`.
pub(crate) fn first_wait_set(members: u32) -> Option<(u32, u32)>
{
    let reserved = members.checked_add(1)?;
    let size = reserved.checked_add(1)?.checked_next_power_of_two()?;
    Some((reserved, FIRST_WAIT_SET_MEMBERS.max(size)))
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn the_set_rounds_the_endpoint_members_and_a_queue_up_to_a_power_of_two()
    {
        assert_eq!(first_wait_set(0), Some((1, FIRST_WAIT_SET_MEMBERS.max(2))));
        assert_eq!(first_wait_set(1), Some((2, 4)));
        assert_eq!(first_wait_set(3), Some((4, 8)));
    }

    #[test]
    fn a_count_whose_power_of_two_overflows_is_refused()
    {
        // 2^31 - 2 members need 2^31 entries; one more needs 2^32.
        assert_eq!(
            first_wait_set((1 << 31) - 2),
            Some(((1 << 31) - 1, 1 << 31))
        );
        assert_eq!(first_wait_set((1 << 31) - 1), None);
        assert_eq!(first_wait_set(u32::MAX - 1), None);
        assert_eq!(first_wait_set(u32::MAX), None);
    }
}
