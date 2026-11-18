// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/init_info.rs

//! The `InitInfo` region's boot-module name table and capability-descriptor
//! array, read for every ktest module that looks up an initial capability.

use init_protocol::{CapDescriptor, InitInfo, InitModuleName, MODULE_NAMES_OFFSET};

/// The `count` values of `T` at byte `offset` of the `InitInfo` region
/// `info` heads.
///
/// `info` is the kernel's `InitInfo` page, the only `InitInfo` ktest ever
/// holds: `_start` receives its address and ktest constructs none.
///
/// # Safety
/// The kernel must have written `count` valid `T`s at `offset` of the
/// region, at an offset aligned for `T`.
unsafe fn region_slice<T>(info: &InitInfo, offset: usize, count: usize) -> &[T]
{
    let base = core::ptr::from_ref::<InitInfo>(info).cast::<u8>();
    // SAFETY: the caller's contract puts `offset` inside the same InitInfo
    // region, aligned for `T`: both tables sit at multiples of 8 past the
    // page-aligned base (abi/init-protocol asserts the sizes of `InitInfo`
    // and `InitModuleName` are), the alignment the `u64` fields of both
    // entry types require.
    let ptr = unsafe { base.add(offset) }.cast::<T>();
    // SAFETY: the caller's contract: `count` valid values inside the same
    // read-only InitInfo region, which stays mapped for ktest's lifetime.
    unsafe { core::slice::from_raw_parts(ptr, count) }
}

/// The `CapDescriptor` array the kernel wrote into the `InitInfo` region.
pub fn descriptors(info: &InitInfo) -> &[CapDescriptor]
{
    // SAFETY: the kernel sets `cap_descriptors_offset` and
    // `cap_descriptor_count` to describe that many valid descriptors in the
    // region.
    unsafe {
        region_slice(
            info,
            info.cap_descriptors_offset as usize,
            info.cap_descriptor_count as usize,
        )
    }
}

/// The boot-module name table the kernel wrote into the `InitInfo` region,
/// right after the header.
pub fn module_names(info: &InitInfo) -> &[InitModuleName]
{
    let count = (info.module_name_count as usize).min(init_protocol::INIT_MAX_NAMED_MODULES);
    // SAFETY: the kernel writes `module_name_count` valid entries, at most
    // `INIT_MAX_NAMED_MODULES`, at `MODULE_NAMES_OFFSET` of the region.
    unsafe { region_slice(info, MODULE_NAMES_OFFSET, count) }
}
