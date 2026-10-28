// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/init_info.rs

//! The `InitInfo` capability-descriptor array, read once for every ktest
//! module that looks up an initial capability.

use init_protocol::{CapDescriptor, InitInfo};

/// The `CapDescriptor` array that follows `info` in the `InitInfo` page.
///
/// `info` is the kernel's `InitInfo` page, the only `InitInfo` ktest ever
/// holds: `_start` receives its address and ktest constructs none.
pub fn descriptors(info: &InitInfo) -> &[CapDescriptor]
{
    let base = core::ptr::from_ref::<InitInfo>(info).cast::<u8>();
    // SAFETY: the kernel sets `cap_descriptors_offset` and
    // `cap_descriptor_count` to describe `cap_descriptor_count` valid
    // descriptors inside the same read-only InitInfo region, which stays
    // mapped for ktest's lifetime.
    // cast_ptr_alignment: `cap_descriptors_offset` is `size_of::<InitInfo>()`
    // past the page-aligned base, which abi/init-protocol asserts is a
    // multiple of 8, the alignment the `u64` fields of `CapDescriptor`
    // require.
    #[allow(clippy::cast_ptr_alignment)]
    unsafe {
        let ptr = base
            .add(info.cap_descriptors_offset as usize)
            .cast::<CapDescriptor>();
        core::slice::from_raw_parts(ptr, info.cap_descriptor_count as usize)
    }
}
