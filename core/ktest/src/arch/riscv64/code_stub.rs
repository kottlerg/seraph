// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/arch/riscv64/code_stub.rs

//! RISC-V machine-code encoders for the stubs `crate::unit::retype` maps
//! executable in a fresh address space and runs a child thread from. Each
//! returns the stub's bytes.

use syscall_abi::SYS_CAP_DELETE;

/// `loop {}`: `jal x0, 0` (to itself).
const SPIN: u32 = 0x0000_006F;

/// Encode `loop {}`.
#[must_use]
pub fn spin() -> [u8; 4]
{
    SPIN.to_le_bytes()
}

/// Encode `cap_delete(handle); loop {}`.
///
/// The handle is stored as an 8-byte literal after the spin loop and loaded
/// PC-relative, since it fills all 64 bits (its generation sits above the
/// 32-bit index) and no short immediate sequence carries that. The literal
/// sits at offset 24, 8-byte aligned when the stub is placed on a page.
#[must_use]
pub fn self_delete(handle: u64) -> [u8; 32]
{
    // cast_possible_truncation: syscall numbers fit 32 bits.
    #[allow(clippy::cast_possible_truncation)]
    let (lui, addi) = li32(17, SYS_CAP_DELETE as u32); // a7 = nr
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
    out[24..].copy_from_slice(&handle.to_le_bytes());
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
