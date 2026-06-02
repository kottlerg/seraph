// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! Integration: a single Memory cap is mappable into two distinct address
//! spaces and the kernel reports the same physical backing in both.
//!
//! Mints a fresh `AddressSpace` cap, then maps one Memory cap from the pool
//! both into ktest's own aspace at one VA and into the new aspace at a
//! different VA. `aspace_query` on each VA returns the underlying physical
//! address; the two phys addresses must be equal — that's the kernel-side
//! invariant that proves the backing is shared.
//!
//! Not validated here (would require running user code in the secondary
//! aspace): writes via VA-A become observable through VA-B. That requires
//! the secondary aspace to also map ktest's code/data/stack, which is a
//! bigger setup than this integration test covers. The phys-equality check
//! is the kernel-level invariant the test cares about.

use syscall::{MAP_WRITABLE, aspace_query, cap_create_aspace, cap_delete, mem_map, mem_unmap};

use crate::{TestContext, TestResult};

/// Distinct VAs so the mappings don't alias each other within the same
/// aspace (we map at `VA_A` in ktest's aspace and `VA_B` in the second aspace).
const VA_A: u64 = 0x5800_0000;
const VA_B: u64 = 0x5900_0000;

pub fn run(ctx: &TestContext) -> TestResult
{
    crate::log("shared_memory_two_aspaces: starting");

    // Mint a fresh address space.
    let aspace_b = cap_create_aspace(ctx.memory_base, 0, 8)
        .map_err(|_| "shared_memory_two_aspaces: cap_create_aspace failed")?;

    // Pull one Memory cap from the pool — backed by ktest's own RAM cap.
    let memory_cap = crate::frame_pool::alloc()
        .ok_or("shared_memory_two_aspaces: frame_pool::alloc returned None")?;

    // Map into ktest's aspace.
    mem_map(memory_cap, ctx.aspace_cap, VA_A, 0, 1, MAP_WRITABLE)
        .map_err(|_| "shared_memory_two_aspaces: mem_map (aspace A) failed")?;

    // Map the same Memory cap into the new aspace at a different VA.
    mem_map(memory_cap, aspace_b, VA_B, 0, 1, MAP_WRITABLE)
        .map_err(|_| "shared_memory_two_aspaces: mem_map (aspace B) failed")?;

    // Both queries must return the same physical address — the kernel-side
    // proof that the Memory cap backs both mappings.
    let phys_a = aspace_query(ctx.aspace_cap, VA_A)
        .map_err(|_| "shared_memory_two_aspaces: aspace_query (A) failed")?;
    let phys_b = aspace_query(aspace_b, VA_B)
        .map_err(|_| "shared_memory_two_aspaces: aspace_query (B) failed")?;
    if phys_a != phys_b
    {
        crate::log_u64("shared_memory_two_aspaces: phys_a=", phys_a);
        crate::log_u64("shared_memory_two_aspaces: phys_b=", phys_b);
        return Err(
            "shared_memory_two_aspaces: same Memory cap mapped in two aspaces has different phys",
        );
    }

    // Cleanup: unmap from both aspaces before returning the cap to the pool.
    mem_unmap(ctx.aspace_cap, VA_A, 1)
        .map_err(|_| "shared_memory_two_aspaces: mem_unmap (A) failed")?;
    mem_unmap(aspace_b, VA_B, 1).map_err(|_| "shared_memory_two_aspaces: mem_unmap (B) failed")?;

    // SAFETY: memory_cap is from pool and now unmapped from both aspaces.
    unsafe { crate::frame_pool::free(memory_cap) };
    cap_delete(aspace_b).ok();
    Ok(())
}
