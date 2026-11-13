// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/driver-binding/src/lib.rs

//! Driver declarations and the resource-list bootstrap of
//! [docs/driver-binding.md](../../../docs/driver-binding.md).
//!
//! A driver states what it serves in its binary, in the `.note.seraph.driver`
//! ELF note the [`driver_declaration!`] macro emits ([`decl`], [`note`]);
//! devmgr locates the note with `shared/elf`'s `find_note` or
//! `find_note_streaming` and decodes it with [`decl::decode`], rejecting a
//! declaration that breaks any bound whole. Once devmgr binds the driver to a
//! device it delivers the device's capabilities as one self-describing
//! resource list ([`resources`]), which the driver decodes.
//!
//! The crate names standards and the system's own structure only: no driver,
//! device, or device class appears in it, so it does not grow with the
//! drivers a deployment ships.

#![cfg_attr(not(test), no_std)]
#![warn(clippy::allow_attributes, clippy::allow_attributes_without_reason)]
#![warn(clippy::multiple_unsafe_ops_per_block)]
// Staged roll-out of these lints: docs/coding-standards.md § Clippy. The
// test configuration is exempt from the second set, as from `unwrap_used`.
#![warn(
    clippy::large_stack_frames,
    clippy::significant_drop_tightening,
    clippy::volatile_composites,
    clippy::wildcard_enum_match_arm
)]
#![cfg_attr(
    not(test),
    warn(
        clippy::panic,
        clippy::panic_in_result_fn,
        clippy::string_slice,
        clippy::unreachable,
        clippy::unwrap_in_result
    )
)]

pub mod decl;
pub mod note;
pub mod resources;

/// Section carrying a driver's declaration note.
pub const DRIVER_NOTE_SECTION: &str = ".note.seraph.driver";
