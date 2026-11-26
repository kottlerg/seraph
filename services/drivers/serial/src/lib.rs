// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/drivers/serial/src/lib.rs

//! Host-testable parts of the serial driver: the transmit ring ([`ring`]),
//! the reading of the 16550's identification register ([`uart`]), and the
//! waits of a write and of the transmitter ([`wait`]). The binary
//! (`src/main.rs`) drives the UART through them; the bin target is
//! `test = false`.

#![cfg_attr(not(test), no_std)]

pub mod ring;
pub mod uart;
pub mod wait;
