// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! Stress test: deep capability derivation chains.
//!
//! Derives a chain 8 levels deep from a root signal, verifies each level
//! can operate, then revokes at the root and verifies cascading invalidation.

use syscall::{cap_create_signal, cap_delete, cap_derive, cap_revoke, signal_send};

use crate::{TestContext, TestResult};

const CHAIN_DEPTH: usize = 8;
const PASSES: usize = 50;
const RIGHTS_SIGNAL: u64 = 1 << 7;

pub fn run(_ctx: &TestContext) -> TestResult
{
    for _pass in 0..PASSES
    {
        let root = cap_create_signal().map_err(|_| "cap_tree_deep: create_signal failed")?;

        // Build chain: root → level[0] → level[1] → ... → level[7]
        let mut chain = [0u32; CHAIN_DEPTH];
        let mut parent = root;
        for slot in &mut chain
        {
            let derived = cap_derive(parent, RIGHTS_SIGNAL)
                .map_err(|_| "cap_tree_deep: cap_derive failed")?;
            *slot = derived;
            parent = derived;
        }

        // Verify every level can send.
        for (i, &cap) in chain.iter().enumerate()
        {
            if signal_send(cap, 0x1).is_err()
            {
                crate::log_u64("cap_tree_deep: send failed at level ", i as u64);
                return Err("cap_tree_deep: derived cap not functional");
            }
        }
        // Drain accumulated bits.
        syscall::signal_wait(root).ok();

        // Revoke at root — all descendants must become invalid.
        cap_revoke(root).map_err(|_| "cap_tree_deep: cap_revoke failed")?;

        for (i, &cap) in chain.iter().enumerate()
        {
            if signal_send(cap, 0x1).is_ok()
            {
                crate::log_u64("cap_tree_deep: cap still valid at level ", i as u64);
                return Err("cap_tree_deep: cascading revocation incomplete");
            }
        }

        // Root must still be valid.
        signal_send(root, 0x1).map_err(|_| "cap_tree_deep: root invalid after revoke")?;
        syscall::signal_wait(root).ok();

        cap_delete(root).map_err(|_| "cap_tree_deep: cap_delete root failed")?;
    }
    Ok(())
}
