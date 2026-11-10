// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/gdbstub/src/breakpoints.rs

//! The software breakpoints GDB inserted (`Z0`): each one's address, the
//! instruction bytes the stub wrote there, and the bytes it replaced, which
//! the removal (`z0`) and a detach write back.

use gdb_rsp::target::Arch;

extern crate alloc;
use alloc::vec::Vec;

/// The longest breakpoint instruction: riscv64's 4-byte `ebreak`.
pub const MAX_BREAKPOINT_BYTES: usize = 4;

/// The breakpoint instruction GDB's `kind` asks for on `arch`: x86-64
/// `int3` (kind 1); riscv64 `c.ebreak` (kind 2) or `ebreak` (kind 4), each
/// the length of the instruction it replaces. `None` for any other kind.
#[must_use]
pub fn instruction(arch: Arch, kind: u64) -> Option<&'static [u8]>
{
    match (arch, kind)
    {
        (Arch::X86_64, 1) => Some(&[0xCC]),
        (Arch::Riscv64, 2) => Some(&riscv_step::C_EBREAK),
        // ebreak: 0x0010_0073, little-endian.
        (Arch::Riscv64, 4) => Some(&[0x73, 0x00, 0x10, 0x00]),
        _ => None,
    }
}

/// One inserted breakpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Breakpoint
{
    /// The address the breakpoint instruction is planted at.
    pub addr: u64,
    /// The breakpoint instruction's length, and the count of saved bytes.
    pub len: usize,
    /// The bytes the breakpoint replaced.
    pub saved: [u8; MAX_BREAKPOINT_BYTES],
}

impl Breakpoint
{
    /// The bytes to write back at [`Self::addr`].
    #[must_use]
    pub fn original(&self) -> &[u8]
    {
        &self.saved[..self.len]
    }
}

/// The inserted breakpoints, one per address.
#[derive(Debug, Default)]
pub struct Breakpoints
{
    inserted: Vec<Breakpoint>,
}

impl Breakpoints
{
    /// No breakpoint inserted.
    #[must_use]
    pub const fn new() -> Self
    {
        Self {
            inserted: Vec::new(),
        }
    }

    /// Whether a breakpoint is inserted at `addr`.
    #[must_use]
    pub fn contains(&self, addr: u64) -> bool
    {
        self.inserted.iter().any(|b| b.addr == addr)
    }

    /// Record a breakpoint written at `addr` over `saved`. A second insert
    /// at an address keeps the first's saved bytes, which are the program's;
    /// the second's would be the breakpoint itself.
    pub fn insert(&mut self, addr: u64, saved: &[u8])
    {
        if self.contains(addr) || saved.len() > MAX_BREAKPOINT_BYTES
        {
            return;
        }
        let mut bytes = [0u8; MAX_BREAKPOINT_BYTES];
        bytes[..saved.len()].copy_from_slice(saved);
        self.inserted.push(Breakpoint {
            addr,
            len: saved.len(),
            saved: bytes,
        });
    }

    /// Forget the breakpoint at `addr`, returning it so its saved bytes are
    /// written back.
    pub fn remove(&mut self, addr: u64) -> Option<Breakpoint>
    {
        let i = self.inserted.iter().position(|b| b.addr == addr)?;
        Some(self.inserted.swap_remove(i))
    }

    /// Forget every breakpoint, returning them, for a detach.
    pub fn take_all(&mut self) -> Vec<Breakpoint>
    {
        core::mem::take(&mut self.inserted)
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn each_kind_plants_the_instruction_of_its_length()
    {
        assert_eq!(instruction(Arch::X86_64, 1), Some(&[0xCC][..]));
        assert_eq!(instruction(Arch::Riscv64, 2).map(<[u8]>::len), Some(2));
        assert_eq!(
            instruction(Arch::Riscv64, 4),
            Some(&[0x73, 0x00, 0x10, 0x00][..])
        );
        assert_eq!(instruction(Arch::X86_64, 2), None);
        assert_eq!(instruction(Arch::Riscv64, 1), None);
    }

    #[test]
    fn a_removal_returns_the_bytes_the_insert_saved()
    {
        let mut b = Breakpoints::new();
        b.insert(0x1000, &[0x55]);
        b.insert(0x2000, &[0x13, 0x01, 0x01, 0xff]);
        assert!(b.contains(0x1000));
        assert_eq!(
            b.remove(0x2000).unwrap().original(),
            &[0x13, 0x01, 0x01, 0xff]
        );
        assert!(b.remove(0x2000).is_none());
        assert_eq!(b.take_all().len(), 1);
        assert!(!b.contains(0x1000));
    }

    #[test]
    fn a_second_insert_at_an_address_keeps_the_programs_bytes()
    {
        let mut b = Breakpoints::new();
        b.insert(0x1000, &[0x55]);
        b.insert(0x1000, &[0xCC]);
        assert_eq!(b.remove(0x1000).unwrap().original(), &[0x55]);
    }
}
