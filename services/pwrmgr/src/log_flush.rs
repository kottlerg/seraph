// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/pwrmgr/src/log_flush.rs

//! The wait for logd's flush barrier before pwrmgr powers the system off or
//! resets it (`services/logd/docs/ipc-interface.md` § Flush barrier): ask
//! logd with `LOG_FLUSH`, and while it answers `FLUSH_PENDING` sleep its
//! retry hint and ask again with its token, until it answers `FLUSHED`, it
//! refuses or does not answer, or the wait's bound passes. The binary makes
//! the calls and the sleeps; this module decides each step, so the wait
//! never outlasts its bound, whatever logd answers.

use ipc::IpcMessage;
use ipc::log_flush::FlushAnswer;

/// What the wait does after a call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Next
{
    /// The wait is over: the log is flushed, logd refused the call or did
    /// not answer it, or the bound has passed.
    Done,
    /// Sleep `wait_ms`, then ask again with `token`.
    Again
    {
        token: u64, wait_ms: u64
    },
}

/// The timeout, in milliseconds, of a call made `elapsed_ms` into a wait
/// bounded by `bound_ms`: the time left, or `None` once none is.
#[must_use]
pub fn call_timeout(elapsed_ms: u64, bound_ms: u32) -> Option<u32>
{
    let left = u64::from(bound_ms).saturating_sub(elapsed_ms);
    u32::try_from(left).ok().filter(|&ms| ms > 0)
}

/// What follows a call that logd answered with `reply` (`None` for a call
/// that failed or timed out), `elapsed_ms` into a wait bounded by
/// `bound_ms`: the hint is slept, at least 1 ms and never past the bound.
#[must_use]
pub fn next(reply: Option<&IpcMessage>, elapsed_ms: u64, bound_ms: u32) -> Next
{
    let Some(reply) = reply
    else
    {
        return Next::Done;
    };
    match FlushAnswer::decode(reply)
    {
        Ok(FlushAnswer::Pending { token, retry_ms }) =>
        {
            let left = u64::from(bound_ms).saturating_sub(elapsed_ms);
            if left == 0
            {
                Next::Done
            }
            else
            {
                Next::Again {
                    token,
                    wait_ms: u64::from(retry_ms).clamp(1, left),
                }
            }
        }
        Ok(FlushAnswer::Flushed { .. }) | Err(_) => Next::Done,
    }
}

#[cfg(test)]
mod tests
{
    use ipc::log_flush::{FLUSH_DENIED, refusal};

    use super::*;

    fn pending(token: u64, retry_ms: u32) -> IpcMessage
    {
        FlushAnswer::Pending { token, retry_ms }.reply()
    }

    // Defect caught: a wait that went on after logd said the log is flushed,
    // refused the call, or did not answer it, holding the power-off for its
    // whole bound.
    #[test]
    fn the_wait_ends_on_flushed_a_refusal_or_no_answer()
    {
        let flushed = FlushAnswer::Flushed { token: 9 }.reply();
        assert_eq!(next(Some(&flushed), 0, 1000), Next::Done);
        assert_eq!(next(Some(&refusal(FLUSH_DENIED)), 0, 1000), Next::Done);
        assert_eq!(next(None, 0, 1000), Next::Done);
    }

    // Defect caught: a wait that dropped the token, so each call started a
    // new flush that lines logged meanwhile could keep pending.
    #[test]
    fn a_pending_answer_is_asked_again_with_its_token_after_its_hint()
    {
        assert_eq!(
            next(Some(&pending(41, 12)), 100, 1000),
            Next::Again {
                token: 41,
                wait_ms: 12
            }
        );
    }

    // Defect caught: a wait that outlasted its bound on a long hint, or spun
    // on a zero one.
    #[test]
    fn the_hint_is_clamped_to_the_time_left_and_at_least_a_millisecond()
    {
        assert_eq!(
            next(Some(&pending(1, 900)), 950, 1000),
            Next::Again {
                token: 1,
                wait_ms: 50
            }
        );
        assert_eq!(
            next(Some(&pending(1, 0)), 0, 1000),
            Next::Again {
                token: 1,
                wait_ms: 1
            }
        );
        assert_eq!(next(Some(&pending(1, 5)), 1000, 1000), Next::Done);
        assert_eq!(next(Some(&pending(1, 5)), u64::MAX, 1000), Next::Done);
    }

    #[test]
    fn a_call_gets_the_time_left()
    {
        assert_eq!(call_timeout(0, 5000), Some(5000));
        assert_eq!(call_timeout(4999, 5000), Some(1));
        assert_eq!(call_timeout(5000, 5000), None);
        assert_eq!(call_timeout(u64::MAX, 5000), None);
    }
}
