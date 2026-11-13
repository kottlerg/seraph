// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/drivers/framebuffer/src/lib.rs

//! Host-testable logic of the framebuffer driver.
//!
//! [`render::FramebufferWriter`] blits glyph bitmaps into a mapped linear
//! framebuffer and validates the framebuffer geometry its pointer
//! arithmetic relies on. It touches only the memory it is handed, so a
//! host test can drive it over a heap buffer; the driver binary
//! (`main.rs`) supplies the real MMIO mapping. [`authority::authorized`]
//! is the service endpoint's verb-bit gate.

#![warn(clippy::allow_attributes, clippy::allow_attributes_without_reason)]
#![warn(clippy::multiple_unsafe_ops_per_block)]
#![warn(clippy::large_stack_frames)]
// Staged roll-out of these lints: docs/coding-standards.md § Clippy. The
// test configuration is exempt from the second set, as from `unwrap_used`.
#![warn(
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

pub mod authority;
pub mod render;
