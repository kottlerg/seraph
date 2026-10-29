// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/integration/cspace_nested_teardown.rs

//! Integration: deleting the root of a deep chain of nested `CSpace`s.
//!
//! Builds a chain of [`DEPTH`] `CSpace`s in which each one's only capability
//! lives in a slot of the previous one, then deletes the capability to the
//! first. The kernel tears the whole chain down in that one `cap_delete`;
//! [capability-internals.md](../../../kernel/docs/capability-internals.md)
//! § Teardown bounds the stack that teardown uses by a constant, whatever the
//! nesting depth. A teardown that recursed one frame per level would overflow
//! the four-page kernel stack well before [`DEPTH`] levels. The test also
//! asserts that every `CSpace` in the chain is reclaimed: the source Memory
//! cap's `available_bytes` return to their value before the chain was built.

use syscall::{cap_create_cspace, cap_delete, cap_info, cap_move};
use syscall_abi::CAP_INFO_MEMORY_AVAILABLE;

use crate::{TestContext, TestResult};

/// Chain length. Far past the depth at which one kernel-stack frame per level
/// would exhaust a four-page kernel stack.
const DEPTH: usize = 256;

/// Pages per `CSpace`: the wrapper page and one slot page, enough for the one
/// slot each `CSpace` in the chain holds.
const PAGES_PER_CSPACE: u64 = 2;

fn available(memory: u32) -> Result<u64, &'static str>
{
    cap_info(memory, CAP_INFO_MEMORY_AVAILABLE)
        .map_err(|_| "integration::cspace_nested_teardown: cap_info(MEMORY_AVAILABLE) failed")
}

pub fn run(ctx: &TestContext) -> TestResult
{
    let memory = ctx.memory_base;
    let baseline = available(memory)?;

    let mut chain = [0u32; DEPTH];
    for (i, entry) in chain.iter_mut().enumerate()
    {
        match cap_create_cspace(memory, 0, PAGES_PER_CSPACE)
        {
            Ok(cs) => *entry = cs,
            Err(_) =>
            {
                for &cs in &chain[..i]
                {
                    cap_delete(cs).ok();
                }
                return Err("integration::cspace_nested_teardown: cap_create_cspace failed");
            }
        }
    }

    // Move each CSpace's capability into its predecessor, deepest first, so
    // every CSpace but the first is referenced only by its predecessor's slot.
    for i in (1..DEPTH).rev()
    {
        if cap_move(chain[i], chain[i - 1], 0).is_err()
        {
            // The CSpaces already moved go down with their holders.
            for &cs in &chain[..=i]
            {
                cap_delete(cs).ok();
            }
            return Err("integration::cspace_nested_teardown: cap_move into predecessor failed");
        }
    }

    cap_delete(chain[0])
        .map_err(|_| "integration::cspace_nested_teardown: cap_delete(chain root) failed")?;

    if available(memory)? != baseline
    {
        return Err(
            "integration::cspace_nested_teardown: the chain's CSpaces were not all reclaimed",
        );
    }
    Ok(())
}
