// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/integration/mmio_spill_withdrawn.rs

//! Integration: an `Mmio` object's mappings past its inline records are
//! withdrawn with it.
//!
//! Derives `granted` from the `Mmio` capability for a side-effect-free
//! register page (`crate::arch::MMIO_PROBE_PHYS`) and maps it at [`PLACES`]
//! distinct VAs of ktest's address space: four go to the object's inline
//! records and the rest to two spill chunks from ktest's `CSpace` arena
//! ([core/kernel/docs/capability-internals.md § Mmio
//! Mappings](../../../kernel/docs/capability-internals.md#mmio-mappings)).
//! Mapping one VA again reuses its record. Deleting `granted` must unmap every
//! VA: a record lost or skipped in a spill chunk would leave its page mapped
//! after the capability is gone.

use init_protocol::{CapType, InitInfo};
use syscall::{aspace_query, cap_delete, cap_derive, mmio_map};

use crate::{TestContext, TestResult};

/// Mapping VA of the first place, distinct from every other test's mapping
/// window; place `i` is `i` pages above it.
const SPILL_VA: u64 = 0x1_5E00_0000;

/// Distinct places mapped: past the 4 inline records and one 7-record spill
/// chunk, so a second chunk is chained.
const PLACES: u64 = 12;

const PAGE: u64 = 4096;

pub fn run(ctx: &TestContext) -> TestResult
{
    // SAFETY: the kernel maps the read-only InitInfo page at init_info_va for
    // ktest's lifetime.
    let info = unsafe { &*(ctx.init_info_va as *const InitInfo) };
    let Some(boot_cap) = crate::init_info::descriptors(info)
        .iter()
        .find(|d| d.cap_type == CapType::Mmio && d.aux0 == crate::arch::MMIO_PROBE_PHYS)
        .map(|d| d.slot)
    else
    {
        crate::log("ktest: integration::mmio_spill_withdrawn SKIP (no probe Mmio cap)");
        return Ok(());
    };
    let granted = cap_derive(boot_cap, syscall::RIGHTS_ALL)
        .map_err(|_| "integration::mmio_spill_withdrawn: cap_derive(granted) failed")?;
    let mapped = map_all(ctx, granted);
    cap_delete(granted).map_err(|_| "integration::mmio_spill_withdrawn: cap_delete failed")?;
    mapped?;
    if (0..PLACES).any(|i| aspace_query(ctx.aspace_cap, SPILL_VA + i * PAGE).is_ok())
    {
        return Err("integration::mmio_spill_withdrawn: a mapping survived the object");
    }
    Ok(())
}

fn map_all(ctx: &TestContext, granted: u32) -> TestResult
{
    for i in (0..PLACES).chain(core::iter::once(PLACES - 1))
    {
        // SAFETY: the window is a scratch VA range (crate docs § Scratch VAs),
        // holding no Rust object or IPC page of ktest; nothing reads the
        // mapping, so no reference to it exists (`mmio_map` § Safety).
        unsafe { mmio_map(ctx.aspace_cap, granted, SPILL_VA + i * PAGE, 0) }
            .map_err(|_| "integration::mmio_spill_withdrawn: mmio_map failed")?;
    }
    if (0..PLACES).any(|i| aspace_query(ctx.aspace_cap, SPILL_VA + i * PAGE).is_err())
    {
        return Err("integration::mmio_spill_withdrawn: a place was not mapped");
    }
    Ok(())
}
