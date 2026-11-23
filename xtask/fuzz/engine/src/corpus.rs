// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/fuzz/engine/src/corpus.rs

//! Coverage novelty and corpus minimization over bucketed edge counters.
//!
//! An execution's coverage is the set of its features: each edge it hit, with
//! the AFL bucket of the edge's hit count. An input is novel when it reaches a
//! feature no earlier execution of the run reached, and the corpus keeps it.

use std::collections::BTreeSet;

/// One feature: an edge's counter index and the bucket bit of its hit count.
pub type Feature = u64;

/// The bucket of a hit count, one bit per class: 1, 2, 3, 4-7, 8-15, 16-31,
/// 32-127 and 128-255 hits; 0 for an edge not hit.
#[must_use]
pub const fn bucket(hits: u8) -> u8
{
    match hits
    {
        0 => 0,
        1 => 1,
        2 => 2,
        3 => 4,
        4..=7 => 8,
        8..=15 => 16,
        16..=31 => 32,
        32..=127 => 64,
        128..=255 => 128,
    }
}

/// The feature of `hits` on counter `index`.
#[must_use]
pub fn feature(index: usize, hits: u8) -> Feature
{
    u64::try_from(index).unwrap_or(u64::MAX).wrapping_shl(8) | u64::from(bucket(hits))
}

/// The features a run has reached: for each counter, the bucket bits of the
/// hit counts any execution gave it.
pub struct Coverage
{
    seen: Vec<u8>,
    edges: usize,
}

impl Coverage
{
    /// The coverage of a run over `counters` counters, none reached yet.
    #[must_use]
    pub fn new(counters: usize) -> Self
    {
        Self {
            seen: vec![0; counters],
            edges: 0,
        }
    }

    /// Whether `hits` on counter `index` is a feature no execution reached.
    #[must_use]
    pub fn is_new(&self, index: usize, hits: u8) -> bool
    {
        self.seen
            .get(index)
            .is_some_and(|&seen| seen & bucket(hits) == 0)
    }

    /// Record `hits` on counter `index` as reached.
    pub fn add(&mut self, index: usize, hits: u8)
    {
        if let Some(seen) = self.seen.get_mut(index)
        {
            if *seen == 0
            {
                self.edges = self.edges.saturating_add(1);
            }
            *seen |= bucket(hits);
        }
    }

    /// The number of edges some execution hit.
    #[must_use]
    pub fn edges(&self) -> usize
    {
        self.edges
    }
}

/// Corpus minimization by coverage: the indices of a subset of `inputs`, each
/// given as its length and its features, that reaches every feature any of
/// them reaches.
///
/// The first `kept` inputs (the checked-in seeds and regressions) are always
/// in it; each other input joins, shortest first, when it reaches a feature
/// the inputs before it do not. The indices are in the order chosen.
#[must_use]
pub fn cover(inputs: &[(usize, Vec<Feature>)], kept: usize) -> Vec<usize>
{
    let mut reached: BTreeSet<Feature> = BTreeSet::new();
    let mut chosen: Vec<usize> = Vec::new();
    for (index, (_, features)) in inputs.iter().enumerate().take(kept)
    {
        reached.extend(features);
        chosen.push(index);
    }
    let mut rest: Vec<(usize, usize)> = inputs
        .iter()
        .enumerate()
        .skip(kept)
        .map(|(index, &(len, _))| (len, index))
        .collect();
    rest.sort_unstable();
    for (_, index) in rest
    {
        let Some((_, features)) = inputs.get(index)
        else
        {
            continue;
        };
        if features.iter().any(|f| !reached.contains(f))
        {
            reached.extend(features);
            chosen.push(index);
        }
    }
    chosen
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn hit_counts_fall_in_afl_buckets()
    {
        let classes = [
            (0, 0),
            (1, 1),
            (2, 2),
            (3, 4),
            (4, 8),
            (7, 8),
            (8, 16),
            (15, 16),
        ];
        for (hits, expected) in classes.into_iter().chain([
            (16, 32),
            (31, 32),
            (32, 64),
            (127, 64),
            (128, 128),
            (255, 128),
        ])
        {
            assert_eq!(bucket(hits), expected, "{hits}");
        }
    }

    // Defect caught: novelty that ignores a new hit-count bucket of an edge
    // already hit, so a loop run more times never counts as progress.
    #[test]
    fn a_new_edge_or_a_new_bucket_of_a_known_edge_is_novel_and_a_repeat_is_not()
    {
        let mut coverage = Coverage::new(4);
        assert!(coverage.is_new(2, 1));
        coverage.add(2, 1);
        assert!(!coverage.is_new(2, 1));
        assert!(coverage.is_new(2, 5));
        coverage.add(2, 5);
        assert!(!coverage.is_new(2, 6));
        assert_eq!(coverage.edges(), 1);
        assert!(
            !coverage.is_new(9, 1),
            "a counter past the end is never novel"
        );
    }

    // Defect caught: minimization that drops a checked-in input, or keeps a
    // longer input where a shorter one reaches the same features.
    #[test]
    fn the_cover_keeps_the_fixed_inputs_and_the_shortest_input_of_each_new_feature()
    {
        let inputs = vec![
            (10, vec![1, 2]),
            (50, vec![3, 4]),
            (20, vec![3]),
            (30, vec![1]),
            (40, vec![4, 3]),
        ];
        assert_eq!(cover(&inputs, 1), [0, 2, 4]);
        assert_eq!(cover(&inputs, 0), [0, 2, 4]);
        assert_eq!(cover(&inputs, 2), [0, 1]);
    }
}
