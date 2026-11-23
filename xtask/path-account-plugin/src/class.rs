// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/path-account-plugin/src/class.rs

//! What an instruction is to the recorder, read from its bytes: a read of the
//! cycle counter, an instruction that traps by design, or any other.

/// A guest architecture the recorder knows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Arch
{
    /// `x86_64`.
    X86_64,
    /// `riscv64`.
    Riscv64,
}

impl Arch
{
    /// The architecture QEMU names `target` (`qemu_info_t::target_name`).
    #[must_use]
    pub fn from_target(target: &str) -> Option<Self>
    {
        match target
        {
            "x86_64" => Some(Self::X86_64),
            "riscv64" => Some(Self::Riscv64),
            _ => None,
        }
    }

    /// The name QEMU gives the architecture, which the record's header carries.
    #[must_use]
    pub const fn name(self) -> &'static str
    {
        match self
        {
            Self::X86_64 => "x86_64",
            Self::Riscv64 => "riscv64",
        }
    }
}

/// Where a counter read leaves the value it read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dest
{
    /// `rdtsc`: the low half in EAX, the high half in EDX.
    EdxEax,
    /// `csrr rd, cycle`: general register `x<rd>`.
    Gpr(u8),
}

/// An instruction's class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class
{
    /// An instruction that is neither of the others.
    Plain,
    /// An instruction that traps by design (a system call, a breakpoint): it
    /// retires, so the trap it raises does not interrupt it.
    Trap,
    /// A read of the cycle counter: `rdtsc`, or `csrr rd, cycle`.
    Read(Dest),
}

/// The class of the instruction whose bytes `bytes` starts with, on `arch`.
#[must_use]
pub fn classify(arch: Arch, bytes: &[u8]) -> Class
{
    match arch
    {
        Arch::X86_64 => match bytes
        {
            [0x0f, 0x31, ..] => Class::Read(Dest::EdxEax),
            // syscall, sysenter, int3, int imm8, int1.
            [0x0f, 0x05 | 0x34, ..] | [0xcc | 0xcd | 0xf1, ..] => Class::Trap,
            _ => Class::Plain,
        },
        Arch::Riscv64 => match bytes
        {
            // c.ebreak.
            [0x02, 0x90, ..] => Class::Trap,
            [b0, b1, b2, b3, ..] if b0 & 3 == 3 =>
            {
                let word = u32::from_le_bytes([*b0, *b1, *b2, *b3]);
                match word
                {
                    // ecall, ebreak.
                    0x0000_0073 | 0x0010_0073 => Class::Trap,
                    // csrrs rd, cycle (0xc00), x0.
                    w if w & 0xffff_f07f == 0xc000_2073 => u8::try_from((w >> 7) & 31)
                        .map_or(Class::Plain, |rd| Class::Read(Dest::Gpr(rd))),
                    _ => Class::Plain,
                }
            }
            _ => Class::Plain,
        },
    }
}

/// Whether `pc` is in the lower, user, half of the address space on both
/// architectures (the kernel's half has the top bit set).
#[must_use]
pub const fn user_half(pc: u64) -> bool
{
    pc >> 63 == 0
}

#[cfg(test)]
mod tests
{
    use super::{Arch, Class, Dest, classify, user_half};

    #[test]
    fn x86_64_reads_traps_and_others()
    {
        let c = |b: &[u8]| classify(Arch::X86_64, b);
        assert_eq!(c(&[0x0f, 0x31]), Class::Read(Dest::EdxEax));
        assert_eq!(c(&[0x0f, 0x05]), Class::Trap);
        assert_eq!(c(&[0x0f, 0x34]), Class::Trap);
        assert_eq!(c(&[0xcc]), Class::Trap);
        assert_eq!(c(&[0xcd, 0x80]), Class::Trap);
        assert_eq!(c(&[0x0f, 0x01, 0xf9]), Class::Plain);
        assert_eq!(c(&[0x48, 0x89, 0xc3]), Class::Plain);
        assert_eq!(c(&[0x0f]), Class::Plain);
        assert_eq!(c(&[]), Class::Plain);
    }

    #[test]
    fn riscv64_reads_traps_and_others()
    {
        let c = |w: u32| classify(Arch::Riscv64, &w.to_le_bytes());
        // csrr a0, cycle; csrr t1, cycle.
        assert_eq!(c(0xc000_2573), Class::Read(Dest::Gpr(10)));
        assert_eq!(c(0xc000_2373), Class::Read(Dest::Gpr(6)));
        // csrr a0, time (0xc01) and csrr a0, instret (0xc02) are not cycle reads.
        assert_eq!(c(0xc010_2573), Class::Plain);
        assert_eq!(c(0xc020_2573), Class::Plain);
        // csrrs a0, cycle, a1 writes the counter's bits: not a plain read.
        assert_eq!(c(0xc005_a573), Class::Plain);
        assert_eq!(c(0x0000_0073), Class::Trap);
        assert_eq!(c(0x0010_0073), Class::Trap);
        assert_eq!(classify(Arch::Riscv64, &[0x02, 0x90]), Class::Trap);
        // c.addi a0, 1 is compressed: never read as a word.
        assert_eq!(
            classify(Arch::Riscv64, &[0x05, 0x05, 0x73, 0x00]),
            Class::Plain
        );
        assert_eq!(c(0x0000_0013), Class::Plain);
    }

    #[test]
    fn the_user_half_is_the_top_bit_clear()
    {
        assert!(user_half(0x0000_7fff_ffff_ffff));
        assert!(user_half(0x36_e721_e000));
        assert!(!user_half(0xffff_ffff_8000_0000));
        assert!(!user_half(0xffff_ffc0_0000_0000));
    }

    #[test]
    fn target_names_round_trip()
    {
        for arch in [Arch::X86_64, Arch::Riscv64]
        {
            assert_eq!(Arch::from_target(arch.name()), Some(arch));
        }
        assert_eq!(Arch::from_target("aarch64"), None);
    }
}
