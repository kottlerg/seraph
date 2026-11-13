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

pub mod authority;
pub mod render;
