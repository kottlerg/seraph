// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// runtime/ruststd/fs-sessions/src/lib.rs

//! Lookup of the seraph std overlay's filesystem session table, as pure
//! host-tested logic (runtime/ruststd/README.md § Filesystem sessions).
//!
//! The overlay keeps one session per filesystem driver it opens files on
//! (services/fs/docs/fs-driver-protocol.md § Label 23). A session cap carries
//! `RIGHTS_EP_IDENTIFY`, so the overlay asks the kernel, with each session
//! cap as the key, whether a node cap names that session's driver endpoint
//! (`SYS_ENDPOINT_IDENTIFY`). [`lookup`] decides from those answers: the
//! first key that matches is the node's session; no match means the node's
//! driver has none yet. A failed inquiry is the key's fault or the node cap's:
//! the key is asked about itself, and a key that fails that too is dead (its
//! cap gone or no longer an endpoint) and reported for removal, while a live
//! key leaves the failure as the node cap's own. The inquiry stays with the
//! caller. See
//! [coding-standards.md](../../../../docs/coding-standards.md#d-testing-invariants).

#![cfg_attr(feature = "rustc-dep-of-std", feature(no_core))]
#![cfg_attr(
    feature = "rustc-dep-of-std",
    expect(
        internal_features,
        reason = "`no_core` is an internal feature, needed to build as a dependency of std"
    )
)]
#![cfg_attr(not(feature = "rustc-dep-of-std"), no_std)]
#![cfg_attr(feature = "rustc-dep-of-std", no_core)]

#[cfg(feature = "rustc-dep-of-std")]
extern crate rustc_std_workspace_core as core;

// Cargo records no source file of a `-Z build-std` unit, only the environment variables it
// reads: reading xtask's digest of the sources of every crate std depends on makes a change to
// any of them rebuild this unit (docs/build-system.md § Build Output: the Sysroot).
#[cfg(feature = "rustc-dep-of-std")]
const _: &str = core::env!("SERAPH_STD_DEPS_DIGEST");

#[cfg(feature = "rustc-dep-of-std")]
use core::prelude::rust_2024::*;

/// What [`lookup`] found for a node cap.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Found<E>
{
    /// The session at this index of the keys serves the node's driver.
    Session(usize),
    /// No live key names the node's driver: it has no session yet.
    Missing,
    /// The inquiry about the node cap failed with a live key: the node cap
    /// is not one the caller can ask about.
    NodeError(E),
}

/// Find the session of `node` among `keys`, the session caps in table order.
/// `identify(key, cap)` answers whether `cap` names the endpoint `key`
/// names (`SYS_ENDPOINT_IDENTIFY`). Each key whose own inquiry fails is
/// passed to `dead` by index, in order, and skipped.
pub fn lookup<E>(
    keys: impl IntoIterator<Item = u64>,
    node: u64,
    mut identify: impl FnMut(u64, u64) -> Result<bool, E>,
    mut dead: impl FnMut(usize),
) -> Found<E>
{
    for (index, key) in keys.into_iter().enumerate()
    {
        match identify(key, node)
        {
            Ok(true) => return Found::Session(index),
            Ok(false) =>
            {}
            Err(error) =>
            {
                if identify(key, key).is_ok()
                {
                    return Found::NodeError(error);
                }
                dead(index);
            }
        }
    }
    Found::Missing
}

#[cfg(test)]
mod tests
{
    extern crate std;
    use std::vec::Vec;

    use super::*;

    /// A kernel of endpoints: `endpoint_of(cap)` is the endpoint a cap
    /// names, `None` for a dead cap. Keys in `live` carry Identify.
    struct Kernel
    {
        caps: Vec<(u64, Option<u64>)>,
    }

    impl Kernel
    {
        fn endpoint_of(&self, cap: u64) -> Option<u64>
        {
            self.caps
                .iter()
                .find(|(c, _)| *c == cap)
                .and_then(|(_, e)| *e)
        }

        fn identify(&self, key: u64, cap: u64) -> Result<bool, &'static str>
        {
            let k = self.endpoint_of(key).ok_or("dead key")?;
            let c = self.endpoint_of(cap).ok_or("dead cap")?;
            Ok(k == c)
        }
    }

    fn run(kernel: &Kernel, keys: &[u64], node: u64) -> (Found<&'static str>, Vec<usize>)
    {
        let mut dead = Vec::new();
        let found = lookup(
            keys.iter().copied(),
            node,
            |k, c| kernel.identify(k, c),
            |i| dead.push(i),
        );
        (found, dead)
    }

    #[test]
    fn the_key_on_the_node_s_endpoint_is_its_session()
    {
        // Two drivers, endpoints 100 and 200; session caps 1 and 2; node caps
        // 11 (driver 100) and 22 (driver 200).
        let kernel = Kernel {
            caps: [
                (1, Some(100)),
                (2, Some(200)),
                (11, Some(100)),
                (22, Some(200)),
            ]
            .into(),
        };
        assert_eq!(run(&kernel, &[1, 2], 11), (Found::Session(0), Vec::new()));
        assert_eq!(run(&kernel, &[1, 2], 22), (Found::Session(1), Vec::new()));
    }

    #[test]
    fn a_node_of_a_driver_with_no_key_finds_none()
    {
        let kernel = Kernel {
            caps: [(1, Some(100)), (33, Some(300))].into(),
        };
        assert_eq!(run(&kernel, &[1], 33), (Found::Missing, Vec::new()));
        assert_eq!(run(&kernel, &[], 33), (Found::Missing, Vec::new()));
    }

    #[test]
    fn a_dead_key_is_reported_and_skipped()
    {
        let kernel = Kernel {
            caps: [(1, None), (2, Some(200)), (3, None), (22, Some(200))].into(),
        };
        assert_eq!(run(&kernel, &[1, 2], 22), (Found::Session(1), [0].into()));
        assert_eq!(run(&kernel, &[1, 3], 22), (Found::Missing, [0, 1].into()));
    }

    #[test]
    fn a_dead_node_cap_with_a_live_key_is_the_node_s_error()
    {
        let kernel = Kernel {
            caps: [(1, None), (2, Some(200)), (44, None)].into(),
        };
        // Key 1 is dead and reported; key 2 is live, so the failure is the
        // node cap's, and the keys after it are not asked.
        assert_eq!(
            run(&kernel, &[1, 2, 3], 44),
            (Found::NodeError("dead cap"), [0].into())
        );
    }

    #[test]
    fn a_dead_node_cap_with_only_dead_keys_finds_none()
    {
        let kernel = Kernel {
            caps: [(1, None), (44, None)].into(),
        };
        assert_eq!(run(&kernel, &[1], 44), (Found::Missing, [0].into()));
    }
}
