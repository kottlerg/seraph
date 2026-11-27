// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/arch/riscv64/code_stub.rs

//! RISC-V machine-code encoders for the stubs `crate::unit::retype` and
//! `crate::integration::aspace_exit_notification` and
//! `crate::integration::aspace_hold` map executable in a fresh address space,
//! and `crate::bench::ipc`'s `aspace=` cases in a fresh one or ktest's own,
//! and run a child thread from. Each returns the stub's bytes.

use syscall_abi::{SYS_ASPACE_EXIT, SYS_CAP_DELETE};

/// `loop {}`: `jal x0, 0` (to itself).
const SPIN: u32 = 0x0000_006F;

/// Encode `loop {}`.
#[must_use]
pub fn spin() -> [u8; 4]
{
    SPIN.to_le_bytes()
}

/// Encode `cap_delete(handle); loop {}`.
#[must_use]
pub fn self_delete(handle: u64) -> [u8; 32]
{
    syscall1_then_spin(SYS_CAP_DELETE, handle)
}

/// Encode `SYS_ASPACE_EXIT(code); loop {}`. The syscall does not return; the
/// loop is never reached.
#[must_use]
pub fn aspace_exit(code: u64) -> [u8; 32]
{
    syscall1_then_spin(SYS_ASPACE_EXIT, code)
}

/// Encode the syscall program runner: entered with the address of a record
/// array in its first argument register, it makes the syscall each
/// eight-word record names in turn (word 0 the number,
/// words 1 to 6 the arguments) and stores its primary return value in the
/// record's word 7, until a record whose number is `u64::MAX`. It then
/// increments that record's word 1 forever, the progress count a test reads
/// to tell a running thread from a stopped one.
#[must_use]
pub fn syscall_program() -> [u8; 72]
{
    let words: [u32; 18] = [
        0x0005_0413, // addi s0, a0, 0
        0x0004_3883, // ld a7, 0(s0)
        0xFFF0_0293, // addi t0, zero, -1
        0x0258_8663, // beq a7, t0, done (+44)
        0x0084_3503, // ld a0, 8(s0)
        0x0104_3583, // ld a1, 16(s0)
        0x0184_3603, // ld a2, 24(s0)
        0x0204_3683, // ld a3, 32(s0)
        0x0284_3703, // ld a4, 40(s0)
        0x0304_3783, // ld a5, 48(s0)
        0x0000_0073, // ecall
        0x02A4_3C23, // sd a0, 56(s0)
        0x0404_0413, // addi s0, s0, 64
        0xFD1F_F06F, // jal zero, top (-48)
        0x0084_3283, // ld t0, 8(s0)
        0x0012_8293, // addi t0, t0, 1
        0x0054_3423, // sd t0, 8(s0)
        0xFF5F_F06F, // jal zero, done (-12)
    ];
    let mut out = [0u8; 72];
    let (slots, _) = out.as_chunks_mut::<4>();
    for (slot, word) in slots.iter_mut().zip(words)
    {
        *slot = word.to_le_bytes();
    }
    out
}

/// Encode the repeating syscall program runner: [`syscall_program`]'s
/// records, except that word 7 holds a repeat count on entry. The runner
/// makes a record's syscall that many times, stopping early at a negative
/// primary return, and stores in word 7 the calls not completed (0 when all
/// returned without error, the failed one counted otherwise) before it moves
/// to the next record. It ends at the `u64::MAX` record as
/// [`syscall_program`] does. Its loop state lives in `s0` and `s1`, which
/// no syscall writes.
#[must_use]
pub fn syscall_repeat() -> [u8; 96]
{
    let words: [u32; 24] = [
        0x0005_0413, // addi s0, a0, 0
        0x0004_3883, // ld a7, 0(s0)
        0xFFF0_0293, // addi t0, zero, -1
        0x0458_8263, // beq a7, t0, done (+68)
        0x0384_3483, // ld s1, 56(s0)
        0x0204_8863, // beq s1, zero, next (+48)
        0x0004_3883, // ld a7, 0(s0)
        0x0084_3503, // ld a0, 8(s0)
        0x0104_3583, // ld a1, 16(s0)
        0x0184_3603, // ld a2, 24(s0)
        0x0204_3683, // ld a3, 32(s0)
        0x0284_3703, // ld a4, 40(s0)
        0x0304_3783, // ld a5, 48(s0)
        0x0000_0073, // ecall
        0x0005_4663, // blt a0, zero, next (+12)
        0xFFF4_8493, // addi s1, s1, -1
        0xFD5F_F06F, // jal zero, again (-44)
        0x0294_3C23, // sd s1, 56(s0)
        0x0404_0413, // addi s0, s0, 64
        0xFB9F_F06F, // jal zero, top (-72)
        0x0084_3283, // ld t0, 8(s0)
        0x0012_8293, // addi t0, t0, 1
        0x0054_3423, // sd t0, 8(s0)
        0xFF5F_F06F, // jal zero, done (-12)
    ];
    let mut out = [0u8; 96];
    let (slots, _) = out.as_chunks_mut::<4>();
    for (slot, word) in slots.iter_mut().zip(words)
    {
        *slot = word.to_le_bytes();
    }
    out
}

/// Encode syscall `nr` with its first argument `arg`, then `loop {}`.
///
/// `arg` is stored as an 8-byte literal after the spin loop and loaded
/// PC-relative, since a capability handle fills all 64 bits (its generation
/// sits above the 32-bit index) and no short immediate sequence carries that.
/// The literal sits at offset 24, 8-byte aligned when the stub is placed on a
/// page.
fn syscall1_then_spin(nr: u64, arg: u64) -> [u8; 32]
{
    #[expect(
        clippy::cast_possible_truncation,
        reason = "syscall numbers fit 32 bits"
    )]
    let (lui, addi) = li32(17, nr as u32); // a7 = nr
    let words = [
        lui,
        addi,
        0x0000_0517, // auipc a0, 0 (a0 = stub + 8)
        0x0105_3503, // ld a0, 16(a0) (stub + 24)
        0x0000_0073, // ecall
        SPIN,
    ];
    let mut out = [0u8; 32];
    let (slots, _) = out.as_chunks_mut::<4>();
    for (slot, word) in slots.iter_mut().zip(words)
    {
        *slot = word.to_le_bytes();
    }
    // Six words end at offset 24, where a0's literal goes.
    out[24..].copy_from_slice(&arg.to_le_bytes());
    out
}

/// `lui rd, hi ; addi rd, rd, lo`: the two words that load the full 32-bit
/// immediate `value` into `rd`.
fn li32(rd: u32, value: u32) -> (u32, u32)
{
    let hi = value.wrapping_add(0x800) >> 12;
    let lo = value & 0xFFF;
    (
        (hi << 12) | (rd << 7) | 0x37,
        (lo << 20) | (rd << 15) | (rd << 7) | 0x13,
    )
}
