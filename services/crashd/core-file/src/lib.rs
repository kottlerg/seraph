// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/crashd/core-file/src/lib.rs

//! The core file crashd writes for a process that died on a fault, and the
//! policy around it (services/crashd/docs/core-format.md).
//!
//! - [`policy`]: which processes the `CORE_DUMP` setting names.
//! - [`notes`]: the `PT_NOTE` contents, in the Linux layouts host `gdb` reads.
//! - [`layout`]: the ELF header, the program headers, and which page runs
//!   fit the per-core byte budget.
//! - [`snapshot`]: a procmgr `SNAPSHOT` object's layout, checked, as the
//!   source of a live process's core.
//! - [`store`]: the core directory's file names and which older cores leave
//!   it so a new one fits its byte budget.
//!
//! Everything here is computation on bytes and numbers the caller read, so it
//! is host-tested; crashd does the reading and the writing.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub mod layout;
pub mod notes;
pub mod policy;
pub mod snapshot;
pub mod store;

/// The machine a core describes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Machine
{
    /// x86-64: `EM_X86_64`.
    X86_64,
    /// riscv64: `EM_RISCV`.
    Riscv64,
}

/// Append `value` little-endian.
fn put_u16(out: &mut alloc::vec::Vec<u8>, value: u16)
{
    out.extend_from_slice(&value.to_le_bytes());
}

/// Append `value` little-endian.
fn put_u32(out: &mut alloc::vec::Vec<u8>, value: u32)
{
    out.extend_from_slice(&value.to_le_bytes());
}

/// Append `value` little-endian.
fn put_u64(out: &mut alloc::vec::Vec<u8>, value: u64)
{
    out.extend_from_slice(&value.to_le_bytes());
}

/// Append zero bytes until `out` is a multiple of `align` long.
fn pad_to(out: &mut alloc::vec::Vec<u8>, align: usize)
{
    let rem = out.len().checked_rem(align).unwrap_or(0);
    if rem != 0
    {
        out.resize(out.len().saturating_add(align.saturating_sub(rem)), 0);
    }
}
