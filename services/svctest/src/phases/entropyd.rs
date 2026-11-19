// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/entropyd.rs

//! The entropy-contribution path end to end: svcmgr gives entropyd the
//! `EntropyControl` copy its `entropy_authority` recipe names, entropyd reads
//! the virtio-rng driver through the `hwrng` class, and the kernel accepts the
//! bytes through `SYS_ENTROPY_CONTRIBUTE`.
//!
//! entropyd logs one line once the kernel has accepted its first contribution,
//! and only then, so the line in logd's history is the evidence. svctest holds
//! no `EntropyControl` cap of its own: svcmgr gives the authority to one
//! service. Runs early, before logd's history holds enough to evict the line
//! and before the `logd_restart` phase replaces logd's table.

use std::time::{Duration, Instant};

use crate::bootstrap::Caps;
use crate::runner::Phase;

/// The start of entropyd's line for its first accepted contribution.
const ACCEPTED_LINE: &[u8] = b"entropy contribution accepted: ";

/// How long the phase waits for the line: entropyd contributes at its start,
/// which needs devmgr's settled `hwrng` driver and one `READ`, bounded by the
/// driver's 1 s wait, so the bound is slack against a slow TCG boot.
const LINE_WAIT: Duration = Duration::from_secs(30);

/// How often logd's history is read while the phase waits.
const POLL_INTERVAL: Duration = Duration::from_millis(50);

pub fn phases() -> &'static [Phase]
{
    &[Phase {
        name: "entropyd_contribution",
        run: contribution_phase,
    }]
}

/// Wait for entropyd's first-contribution line in logd's history.
fn contribution_phase(caps: &Caps)
{
    assert!(
        caps.logd_query != 0,
        "entropyd_contribution: no logd.query cap"
    );
    let start = Instant::now();
    loop
    {
        let found = super::procmgr::logd_history_with(caps.logd_query, None, |entry| {
            entry
                .bytes
                .windows(ACCEPTED_LINE.len())
                .any(|w| w == ACCEPTED_LINE)
        })
        .into_iter()
        .any(|hit| hit);
        if found
        {
            return;
        }
        assert!(
            start.elapsed() < LINE_WAIT,
            "entropyd_contribution: no accepted contribution logged by entropyd within {LINE_WAIT:?}"
        );
        std::thread::sleep(POLL_INTERVAL);
    }
}
