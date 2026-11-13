// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/gdb-rsp/src/lib.rs

//! The GDB remote serial protocol: framing, packet parse and encode, and the
//! target descriptions a stub serves for x86-64 and riscv64.
//!
//! The protocol is a byte stream of packets, `$<body>#<checksum>`, each
//! acknowledged with `+` or refused with `-` until both sides enter no-ack
//! mode, plus the out-of-band interrupt byte `0x03`. [`frame`] splits the
//! stream into [`frame::Event`]s and writes packets; [`command`] parses a
//! packet body GDB sends into a [`command::Command`]; [`frame::PacketWriter`]
//! carries the reply encoders; [`target`] gives each architecture's register
//! layout and target description XML.
//!
//! `no_std`, no allocation, no dependencies. The crate depends on no Seraph
//! service: the stub maps the parsed commands onto the system's debugging
//! mechanism (docs/fault-handling.md § Debugging).

#![no_std]
#![warn(clippy::allow_attributes, clippy::allow_attributes_without_reason)]

pub mod command;
pub mod frame;
pub mod hex;
pub mod target;

/// The largest packet body (the bytes between `$` and `#`, as sent) a stub
/// using this crate accepts: the `PacketSize` it advertises in its
/// `qSupported` reply, and the buffer size of its
/// [`frame::PacketReader`]. With the framing, a whole packet is at most four
/// bytes longer. It holds the body of a `G` packet of either architecture's
/// whole register block in hex ([`target::Arch::register_block_len`] bytes,
/// twice that in hex digits).
pub const PACKET_SIZE: usize = 4096;

/// Why a packet could not be parsed or written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error
{
    /// The bytes do not have the form the packet requires: a missing
    /// separator, a non-hex digit, a number that overflows 64 bits, a data
    /// length that disagrees with the length the packet states, or an escape
    /// byte with nothing after it.
    Malformed,
    /// The output does not fit the buffer it is written into.
    Overflow,
}
