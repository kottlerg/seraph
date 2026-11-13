// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/riscv-step/src/lib.rs

//! The successor-address decoder a debugger single-steps a riscv64 thread
//! with (docs/fault-handling.md § Debugging).
//!
//! RISC-V has no user-mode single-step without a debug trigger, and the
//! kernel programs none. A debugger steps a stopped thread instead by
//! planting [`C_EBREAK`] at the address the next instruction will run from,
//! resuming the thread, and taking the breakpoint there. [`successor`] gives
//! that address from the instruction at the thread's pointer and its
//! registers: the fall-through for every instruction that does not transfer
//! control, the taken or not-taken target of a conditional branch, and the
//! target of a jump. [`instruction_len`] gives how many bytes to read.
//!
//! `no_std`, no allocation, no dependencies; RV64GC encodings.

#![no_std]
#![warn(clippy::allow_attributes, clippy::allow_attributes_without_reason)]
#![warn(clippy::multiple_unsafe_ops_per_block)]

/// `c.ebreak` (0x9002), little-endian: the breakpoint a debugger plants at the
/// successor. Two bytes, so it never reaches past the successor's first
/// 16-bit parcel, whatever that instruction's length; the C extension that
/// encodes it is in the riscv64 required floor
/// (docs/platform-requirements.md § riscv64 Classification).
pub const C_EBREAK: [u8; 2] = [0x02, 0x90];

/// Why [`successor`] or [`instruction_len`] gives no address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StepError
{
    /// The bytes are one of the invalid encodings the decoder recognises: an
    /// all-zero parcel, the reserved `c.jr x0`, or a conditional branch with
    /// an undefined condition (`funct3` 2 or 3). Other reserved encodings
    /// are not recognised and fall through by their length.
    Illegal,
    /// An instruction longer than 32 bits, which RV64GC does not define.
    TooLong,
    /// The instruction is itself a breakpoint (`ebreak` or `c.ebreak`): the
    /// thread would trap at it, not at its successor.
    Breakpoint,
    /// The successor lies within the instruction's own bytes: a jump to
    /// itself (`j .`), or a 4-byte jump or taken branch to its own second
    /// parcel. A breakpoint planted there overwrites the instruction before
    /// it runs, so the thread either traps without advancing or runs altered
    /// bytes.
    SelfTarget,
}

/// The length in bytes (2 or 4) of the instruction whose first 16-bit parcel
/// is `parcel`.
///
/// # Errors
/// - `TooLong`: the parcel starts an instruction of 48 bits or more.
pub fn instruction_len(parcel: u16) -> Result<usize, StepError>
{
    if parcel & 0b11 != 0b11
    {
        Ok(2)
    }
    else if parcel & 0b1_1100 != 0b1_1100
    {
        Ok(4)
    }
    else
    {
        Err(StepError::TooLong)
    }
}

/// The address the thread runs next after the instruction `insn` at `pc`,
/// reading integer register `xN` through `reg(N)` (`N` in `1..=31`; `x0` is
/// zero and never read). For a compressed instruction only the low 16 bits of
/// `insn` are read.
///
/// `ecall` falls through: the syscall returns to the instruction after it.
/// A reserved encoding the decoder does not recognise falls through by its
/// length; the thread then raises an illegal-instruction exception at `pc`
/// instead of reaching the successor.
///
/// # Errors
/// - `Illegal`: an all-zero parcel, the reserved `c.jr x0`, or a conditional
///   branch with `funct3` 2 or 3.
/// - `TooLong`: an instruction of 48 bits or more.
/// - `Breakpoint`: `ebreak` or `c.ebreak`.
/// - `SelfTarget`: the successor lies within the instruction's own bytes
///   (`pc` itself, or `pc + 2` for a 4-byte instruction).
pub fn successor(pc: u64, insn: u32, reg: impl Fn(u32) -> u64) -> Result<u64, StepError>
{
    #[expect(
        clippy::cast_possible_truncation,
        reason = "truncating to the low parcel is intended; it is what instruction_len reads"
    )]
    let parcel = insn as u16;
    let len = instruction_len(parcel)?;
    let next = if len == 2
    {
        compressed_successor(pc, parcel, &reg)?
    }
    else
    {
        full_successor(pc, insn, &reg)?
    };
    // The planted c.ebreak covers [next, next + 2); a successor inside the
    // stepped instruction's own bytes would overwrite it before it runs.
    if next.wrapping_sub(pc) < len as u64
    {
        return Err(StepError::SelfTarget);
    }
    Ok(next)
}

/// The value of `xN`, `x0` reading zero.
fn read(reg: &impl Fn(u32) -> u64, n: u32) -> u64
{
    if n == 0 { 0 } else { reg(n) }
}

/// Bits `hi..=lo` of `x`, shifted down.
fn bits(x: u32, hi: u32, lo: u32) -> u32
{
    // Every caller passes a constant field with `lo <= hi < 32`; a 32-bit
    // field takes the whole word.
    let width = hi.saturating_sub(lo).saturating_add(1);
    let mask = 1u32
        .checked_shl(width)
        .map_or(u32::MAX, |bit| bit.saturating_sub(1));
    (x >> lo) & mask
}

/// `value`, a `width`-bit two's-complement number, sign-extended.
fn sext(value: u32, width: u32) -> i64
{
    // Every caller passes a width of at most 64.
    let shift = 64u32.saturating_sub(width);
    (i64::from(value) << shift) >> shift
}

/// `pc` plus a signed offset, wrapping as the hardware does.
fn offset(pc: u64, off: i64) -> u64
{
    pc.wrapping_add_signed(off)
}

/// The successor of the 32-bit instruction `insn` at `pc`.
fn full_successor(pc: u64, insn: u32, reg: &impl Fn(u32) -> u64) -> Result<u64, StepError>
{
    /// `ebreak`, the one 32-bit encoding a step cannot pass.
    const EBREAK: u32 = 0x0010_0073;

    let rs1 = bits(insn, 19, 15);
    let rs2 = bits(insn, 24, 20);
    match insn & 0x7F
    {
        // jal: imm[20|10:1|11|19:12] in bits 31|30:21|20|19:12.
        0x6F =>
        {
            let imm = (bits(insn, 31, 31) << 20)
                | (bits(insn, 30, 21) << 1)
                | (bits(insn, 20, 20) << 11)
                | (bits(insn, 19, 12) << 12);
            Ok(offset(pc, sext(imm, 21)))
        }
        // jalr: rs1 + imm[11:0], the low bit cleared.
        0x67 if bits(insn, 14, 12) == 0 =>
        {
            let imm = sext(bits(insn, 31, 20), 12);
            Ok(read(reg, rs1).wrapping_add_signed(imm) & !1)
        }
        // Conditional branches: imm[12|10:5] in bits 31|30:25, imm[4:1|11] in 11:8|7.
        0x63 =>
        {
            let imm = (bits(insn, 31, 31) << 12)
                | (bits(insn, 30, 25) << 5)
                | (bits(insn, 11, 8) << 1)
                | (bits(insn, 7, 7) << 11);
            let (a, b) = (read(reg, rs1), read(reg, rs2));
            #[expect(
                clippy::cast_possible_wrap,
                reason = "the signed comparisons read the registers as two's-complement, as blt \
                          and bge do"
            )]
            let taken = match bits(insn, 14, 12)
            {
                0 => a == b,
                1 => a != b,
                4 => (a as i64) < (b as i64),
                5 => (a as i64) >= (b as i64),
                6 => a < b,
                7 => a >= b,
                _ => return Err(StepError::Illegal),
            };
            Ok(
                if taken
                {
                    offset(pc, sext(imm, 13))
                }
                else
                {
                    pc.wrapping_add(4)
                },
            )
        }
        _ if insn == EBREAK => Err(StepError::Breakpoint),
        _ => Ok(pc.wrapping_add(4)),
    }
}

/// The successor of the compressed instruction `h` at `pc`.
fn compressed_successor(pc: u64, h: u16, reg: &impl Fn(u32) -> u64) -> Result<u64, StepError>
{
    let h = u32::from(h);
    if h == 0
    {
        return Err(StepError::Illegal);
    }
    let funct3 = bits(h, 15, 13);
    match (h & 0b11, funct3)
    {
        // c.j: offset[11|4|9:8|10|6|7|3:1|5] in bits 12|11|10:9|8|7|6|5:3|2.
        (0b01, 0b101) =>
        {
            let imm = (bits(h, 12, 12) << 11)
                | (bits(h, 11, 11) << 4)
                | (bits(h, 10, 9) << 8)
                | (bits(h, 8, 8) << 10)
                | (bits(h, 7, 7) << 6)
                | (bits(h, 6, 6) << 7)
                | (bits(h, 5, 3) << 1)
                | (bits(h, 2, 2) << 5);
            Ok(offset(pc, sext(imm, 12)))
        }
        // c.beqz / c.bnez: rs1' in bits 9:7 (x8..x15); offset[8|4:3] in
        // bits 12|11:10, offset[7:6|2:1|5] in bits 6:5|4:3|2.
        (0b01, 0b110 | 0b111) =>
        {
            let imm = (bits(h, 12, 12) << 8)
                | (bits(h, 11, 10) << 3)
                | (bits(h, 6, 5) << 6)
                | (bits(h, 4, 3) << 1)
                | (bits(h, 2, 2) << 5);
            // The 3-bit field names x8..=x15: bit 3 set, the field below it.
            let zero = read(reg, 8 | bits(h, 9, 7)) == 0;
            let taken = if funct3 == 0b110 { zero } else { !zero };
            Ok(
                if taken
                {
                    offset(pc, sext(imm, 9))
                }
                else
                {
                    pc.wrapping_add(2)
                },
            )
        }
        // c.jr, c.jalr, c.ebreak (and c.mv / c.add, which fall through).
        (0b10, 0b100) =>
        {
            let rs1 = bits(h, 11, 7);
            let rs2 = bits(h, 6, 2);
            match (bits(h, 12, 12), rs1, rs2)
            {
                (0, 0, 0) => Err(StepError::Illegal),
                (1, 0, 0) => Err(StepError::Breakpoint),
                (_, rs1, 0) => Ok(read(reg, rs1) & !1),
                _ => Ok(pc.wrapping_add(2)),
            }
        }
        _ => Ok(pc.wrapping_add(2)),
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    /// A register file where `xN` reads `vals[N]`.
    fn regs(vals: [(u32, u64); 2]) -> impl Fn(u32) -> u64
    {
        move |n| {
            vals.iter()
                .find(|(r, _)| *r == n)
                .map_or(0xDEAD_0000 + u64::from(n), |(_, v)| *v)
        }
    }

    const PC: u64 = 0x1_0000;

    // Defect caught: a length test that misreads the low two bits takes a
    // compressed instruction for a 32-bit one, so a debugger reads and plants
    // past the instruction, or refuses a 48-bit encoding it cannot step.
    #[test]
    fn instruction_len_reads_the_low_bits_of_the_first_parcel()
    {
        assert_eq!(instruction_len(0x0505), Ok(2)); // c.addi a0, 1
        assert_eq!(instruction_len(0x9002), Ok(2)); // c.ebreak
        assert_eq!(instruction_len(0x0513), Ok(4)); // low parcel of addi
        assert_eq!(instruction_len(0x001F), Err(StepError::TooLong));
    }

    // Defect caught: an instruction that transfers no control stepped to any
    // address but the next one.
    #[test]
    fn a_plain_instruction_falls_through_by_its_length()
    {
        let r = regs([(0, 0), (0, 0)]);
        assert_eq!(successor(PC, 0x0015_0513, &r), Ok(PC + 4)); // addi a0, a0, 1
        assert_eq!(successor(PC, 0x0000_0073, &r), Ok(PC + 4)); // ecall
        assert_eq!(successor(PC, 0x0505, &r), Ok(PC + 2)); // c.addi a0, 1
        assert_eq!(successor(PC, 0x852E, &r), Ok(PC + 2)); // c.mv a0, a1
    }

    // Defect caught: a scrambled jal immediate sends the breakpoint to the
    // wrong address, forward or backward.
    #[test]
    fn jal_jumps_by_its_signed_offset()
    {
        let r = regs([(0, 0), (0, 0)]);
        assert_eq!(successor(PC, 0x0080_006F, &r), Ok(PC + 8)); // jal x0, 8
        assert_eq!(successor(PC, 0xFFDF_F0EF, &r), Ok(PC - 4)); // jal ra, -4
    }

    // Defect caught: jalr that ignores rs1 or the immediate, or keeps the
    // low bit the hardware clears.
    #[test]
    fn jalr_jumps_to_rs1_plus_its_offset_with_the_low_bit_clear()
    {
        let r = regs([(10, 0x2001), (5, 0x3000)]);
        assert_eq!(successor(PC, 0x0045_0067, &r), Ok(0x2004)); // jalr x0, 4(a0)
        assert_eq!(successor(PC, 0xFF02_80E7, &r), Ok(0x2FF0)); // jalr ra, -16(t0)
    }

    // Defect caught: a branch condition evaluated wrongly, or signed and
    // unsigned comparisons swapped, so the breakpoint lands on the path the
    // thread does not take and the step never ends.
    #[test]
    fn a_branch_steps_to_its_target_when_taken_and_falls_through_otherwise()
    {
        let equal = regs([(10, 7), (11, 7)]);
        let less = regs([(10, u64::MAX), (11, 1)]); // -1 < 1 signed; MAX > 1 unsigned
        assert_eq!(successor(PC, 0x00B5_0863, &equal), Ok(PC + 16)); // beq a0, a1, 16
        assert_eq!(successor(PC, 0x00B5_0863, &less), Ok(PC + 4));
        assert_eq!(successor(PC, 0xFEB5_1CE3, &less), Ok(PC - 8)); // bne a0, a1, -8
        assert_eq!(successor(PC, 0xFEB5_1CE3, &equal), Ok(PC + 4));
        assert_eq!(successor(PC, 0x00B5_4863, &less), Ok(PC + 16)); // blt
        assert_eq!(successor(PC, 0x00B5_5863, &less), Ok(PC + 4)); // bge
        assert_eq!(successor(PC, 0x00B5_6863, &less), Ok(PC + 4)); // bltu
        assert_eq!(successor(PC, 0x00B5_7863, &less), Ok(PC + 16)); // bgeu
    }

    // Defect caught: a branch with an undefined funct3 (2 or 3) stepped as
    // though it were defined.
    #[test]
    fn a_branch_with_an_undefined_condition_is_illegal()
    {
        let r = regs([(0, 0), (0, 0)]);
        assert_eq!(successor(PC, 0x00B5_2863, &r), Err(StepError::Illegal));
    }

    // Defect caught: a scrambled c.j offset, forward or backward.
    #[test]
    fn c_j_jumps_by_its_signed_offset()
    {
        let r = regs([(0, 0), (0, 0)]);
        assert_eq!(successor(PC, 0xA021, &r), Ok(PC + 8)); // c.j 8
        assert_eq!(successor(PC, 0xBFFD, &r), Ok(PC - 2)); // c.j -2
    }

    // Defect caught: c.beqz / c.bnez reading the wrong register (rs1' is
    // x8..x15) or the wrong offset, or the two conditions swapped.
    #[test]
    fn c_beqz_and_c_bnez_test_their_register_against_zero()
    {
        let zero = regs([(10, 0), (0, 0)]);
        let nonzero = regs([(10, 5), (0, 0)]);
        assert_eq!(successor(PC, 0xC501, &zero), Ok(PC + 8)); // c.beqz a0, 8
        assert_eq!(successor(PC, 0xC501, &nonzero), Ok(PC + 2));
        assert_eq!(successor(PC, 0xFD75, &nonzero), Ok(PC - 4)); // c.bnez a0, -4
        assert_eq!(successor(PC, 0xFD75, &zero), Ok(PC + 2));
    }

    // Defect caught: c.jr / c.jalr taken for c.mv / c.add, or their target
    // read from the wrong register.
    #[test]
    fn c_jr_and_c_jalr_jump_to_their_register()
    {
        let r = regs([(1, 0x4002), (15, 0x5001)]);
        assert_eq!(successor(PC, 0x8082, &r), Ok(0x4002)); // c.jr ra (ret)
        assert_eq!(successor(PC, 0x9782, &r), Ok(0x5000)); // c.jalr a5
    }

    // Defect caught: a breakpoint stepped as an ordinary instruction, whose
    // own trap the debugger would then take for the step's.
    #[test]
    fn a_breakpoint_cannot_be_stepped()
    {
        let r = regs([(0, 0), (0, 0)]);
        assert_eq!(successor(PC, 0x0010_0073, &r), Err(StepError::Breakpoint)); // ebreak
        assert_eq!(successor(PC, 0x9002, &r), Err(StepError::Breakpoint)); // c.ebreak
    }

    // Defect caught: a zero parcel or the reserved c.jr x0 decoded as an
    // instruction, so a debugger plants a breakpoint for code that faults.
    #[test]
    fn an_illegal_encoding_is_refused()
    {
        let r = regs([(0, 0), (0, 0)]);
        assert_eq!(successor(PC, 0x0000, &r), Err(StepError::Illegal));
        assert_eq!(successor(PC, 0x8002, &r), Err(StepError::Illegal)); // c.jr x0
        assert_eq!(successor(PC, 0x001F, &r), Err(StepError::TooLong));
    }

    // Defect caught: a jump to itself stepped by planting a breakpoint over
    // the instruction, which traps before it runs and never advances.
    #[test]
    fn a_jump_to_itself_is_refused()
    {
        let r = regs([(0, 0), (0, 0)]);
        assert_eq!(successor(PC, 0x0000_006F, &r), Err(StepError::SelfTarget)); // j .
        assert_eq!(successor(PC, 0xA001, &r), Err(StepError::SelfTarget)); // c.j 0
    }

    // Defect caught: a 4-byte jump or taken branch to its own second parcel
    // stepped by planting the breakpoint over that parcel, so the thread runs
    // an altered instruction instead of the stepped one.
    #[test]
    fn a_successor_inside_the_instruction_is_refused()
    {
        let r = regs([(5, PC + 2), (0, 0)]);
        // beq x0, x0, +2 (taken)
        assert_eq!(successor(PC, 0x0000_0163, &r), Err(StepError::SelfTarget));
        // jal x0, +2
        assert_eq!(successor(PC, 0x0020_006F, &r), Err(StepError::SelfTarget));
        // jalr x0, 0(t0), t0 = pc + 2
        assert_eq!(successor(PC, 0x0002_8067, &r), Err(StepError::SelfTarget));
        // c.j +2 lands just past the 2-byte instruction: steppable.
        assert_eq!(successor(PC, 0xA009, &r), Ok(PC + 2));
    }

    // Defect caught: x0 read through the register file instead of as zero,
    // which would misroute jalr x0-relative jumps and x0 comparisons.
    #[test]
    fn x0_reads_zero()
    {
        let r = regs([(0, 0x9999), (0, 0)]);
        // beq x0, x0, 16 is always taken.
        assert_eq!(successor(PC, 0x0000_0863, &r), Ok(PC + 16));
        // jalr x0, 0x100(x0) jumps to 0x100.
        assert_eq!(successor(PC, 0x1000_0067, &r), Ok(0x100));
    }
}
