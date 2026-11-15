// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svcmgr/svc-defs/src/death_caps.rs

//! A service's death as the caps svcmgr holds on it show it: its main thread's
//! state and, for a service whose address space svcmgr holds (memmgr and
//! procmgr), the space's retained terminal fault. svcmgr reads both with
//! `cap_info` and decodes them here, for a supervised service's entry and for
//! a substrate registration not yet reconciled alike. The specification is
//! `services/svcmgr/docs/restart-protocol.md` § Death detection.

use syscall_abi::{EXIT_KILLED, THREAD_STATE_EXITED};

/// The exit reason of a service its caps show dead, else `None`.
///
/// `thread_state` is the result of `cap_info(CAP_INFO_THREAD_STATE)` on its
/// main-thread cap, and `aspace_fault` that of
/// `cap_info(CAP_INFO_ASPACE_TERMINAL_FAULT)` on its address-space cap; `None`
/// for a cap svcmgr does not hold. An exited thread gives the reason the kernel
/// recorded, the low half of the packed state. A thread cap that no longer
/// resolves gives `EXIT_KILLED`, since procmgr's teardown of the process
/// revokes it. A non-zero retained fault gives that fault's reason. A thread
/// that runs or has not started, a space with no retained fault, and a failed
/// read of the space show nothing.
#[must_use]
pub fn caps_death(
    thread_state: Option<Result<u64, i64>>,
    aspace_fault: Option<Result<u64, i64>>,
) -> Option<u64>
{
    match thread_state
    {
        Some(Ok(packed)) if packed >> 32 == u64::from(THREAD_STATE_EXITED) =>
        {
            return Some(packed & 0xFFFF_FFFF);
        }
        Some(Err(_)) => return Some(EXIT_KILLED),
        Some(Ok(_)) | None =>
        {}
    }
    match aspace_fault
    {
        Some(Ok(reason)) if reason != 0 => Some(reason),
        _ => None,
    }
}

#[cfg(test)]
mod tests
{
    use super::*;
    use syscall_abi::{EXIT_FAULT_BASE, THREAD_STATE_ALIVE, THREAD_STATE_CREATED};

    /// A thread cap's `CAP_INFO_THREAD_STATE` reading: the state code in the
    /// high half, the exit reason in the low.
    fn packed(code: u32, reason: u64) -> u64
    {
        (u64::from(code) << 32) | reason
    }

    #[test]
    fn an_exited_thread_gives_its_recorded_reason()
    {
        assert_eq!(
            caps_death(Some(Ok(packed(THREAD_STATE_EXITED, 0))), None),
            Some(0)
        );
        assert_eq!(
            caps_death(
                Some(Ok(packed(THREAD_STATE_EXITED, EXIT_FAULT_BASE + 14))),
                None
            ),
            Some(EXIT_FAULT_BASE + 14)
        );
    }

    #[test]
    fn a_thread_cap_that_no_longer_resolves_is_killed()
    {
        assert_eq!(caps_death(Some(Err(-1)), None), Some(EXIT_KILLED));
        // The thread's reading wins over the space's.
        assert_eq!(caps_death(Some(Err(-1)), Some(Ok(7))), Some(EXIT_KILLED));
    }

    #[test]
    fn a_live_thread_and_a_clean_space_show_nothing()
    {
        for code in [THREAD_STATE_CREATED, THREAD_STATE_ALIVE]
        {
            assert_eq!(caps_death(Some(Ok(packed(code, 0))), None), None);
            assert_eq!(caps_death(Some(Ok(packed(code, 0))), Some(Ok(0))), None);
        }
        assert_eq!(caps_death(None, None), None);
    }

    #[test]
    fn a_retained_fault_of_another_thread_is_the_death()
    {
        let fault = EXIT_FAULT_BASE + 13;
        assert_eq!(
            caps_death(Some(Ok(packed(THREAD_STATE_ALIVE, 0))), Some(Ok(fault))),
            Some(fault)
        );
        assert_eq!(caps_death(None, Some(Ok(fault))), Some(fault));
    }

    #[test]
    fn a_failed_read_of_the_space_shows_nothing()
    {
        assert_eq!(
            caps_death(Some(Ok(packed(THREAD_STATE_ALIVE, 0))), Some(Err(-1))),
            None
        );
    }
}
