// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/fuzz/engine/src/minimize.rs

//! Crash minimization: shrink a failing input while it still fails the same
//! way, so the report and the regression input hold only what the defect
//! needs.

/// The smallest input the search finds from `input` for which `still_fails`
/// holds, trying at most `budget` candidates; `still_fails(input)` is taken to
/// hold.
///
/// Blocks are removed, halving the block size from half the input down to one
/// byte, until a pass removes nothing; then each byte left is set to zero
/// where the failure allows it. The search is deterministic.
pub fn minimize(input: &[u8], budget: usize, mut still_fails: impl FnMut(&[u8]) -> bool)
-> Vec<u8>
{
    let mut current = input.to_vec();
    let mut tries = 0usize;
    let mut attempt = |candidate: &[u8]| {
        if tries >= budget
        {
            return false;
        }
        tries = tries.saturating_add(1);
        still_fails(candidate)
    };
    loop
    {
        let before = current.len();
        let mut block = current.len().div_ceil(2);
        while block > 0
        {
            let mut at = 0usize;
            while at < current.len()
            {
                let end = at.saturating_add(block).min(current.len());
                let candidate: Vec<u8> = current
                    .iter()
                    .take(at)
                    .chain(current.iter().skip(end))
                    .copied()
                    .collect();
                if attempt(&candidate)
                {
                    current = candidate;
                }
                else
                {
                    at = end;
                }
            }
            block /= 2;
        }
        if current.len() == before
        {
            break;
        }
    }
    for at in 0..current.len()
    {
        if current.get(at).is_some_and(|&byte| byte != 0)
        {
            let mut candidate = current.clone();
            if let Some(byte) = candidate.get_mut(at)
            {
                *byte = 0;
            }
            if attempt(&candidate)
            {
                current = candidate;
            }
        }
    }
    current
}

#[cfg(test)]
mod tests
{
    use super::*;

    // Defect caught: a minimizer that keeps bytes the failure does not need,
    // or returns an input that no longer fails.
    #[test]
    fn minimization_keeps_only_the_bytes_the_failure_needs()
    {
        let fails = |data: &[u8]| data.windows(3).any(|w| w == b"BUG");
        let input = b"padding BUG more padding and BUG again".to_vec();
        let minimized = minimize(&input, 10_000, fails);
        assert_eq!(minimized, b"BUG");
        let zeroed = minimize(b"xxAyy", 10_000, |data: &[u8]| {
            data.contains(&b'A') && data.len() >= 2
        });
        assert_eq!(zeroed.len(), 2);
        assert!(zeroed.contains(&b'A') && zeroed.contains(&0), "{zeroed:?}");
    }

    #[test]
    fn minimization_stops_at_its_budget()
    {
        let mut calls = 0;
        let minimized = minimize(&[1; 64], 5, |_| {
            calls += 1;
            false
        });
        assert_eq!(calls, 5);
        assert_eq!(minimized, [1; 64]);
    }
}
