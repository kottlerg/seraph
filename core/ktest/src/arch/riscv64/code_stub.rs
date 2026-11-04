// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/arch/riscv64/code_stub.rs

//! RISC-V machine-code encoders for the stubs `crate::unit::retype` maps
//! executable in a fresh address space and runs a child thread from.

use syscall_abi::SYS_CAP_DELETE;

/// Encode `loop {}` into `buf`; returns the byte count.
pub fn emit_spin(buf: &mut [u8]) -> usize
{
    // jal x0, 0 (to itself)
    buf[..4].copy_from_slice(&0x0000_006Fu32.to_le_bytes());
    4
}

/// Encode `cap_delete(handle); loop {}` into `buf`; returns the byte count.
///
/// The handle is stored as an 8-byte literal after the spin loop and loaded
/// PC-relative, since it fills all 64 bits (its generation sits above the
/// 32-bit index) and no short immediate sequence carries that. The literal
/// sits at offset 24, 8-byte aligned when `buf` is placed on a page.
pub fn emit_self_delete(buf: &mut [u8], handle: u64) -> usize
{
    // lui rd, hi ; addi rd, rd, lo — a full 32-bit immediate.
    fn li32(out: &mut [u8], rd: u32, value: u32)
    {
        let hi = value.wrapping_add(0x800) >> 12;
        let lo = value & 0xFFF;
        let lui = (hi << 12) | (rd << 7) | 0x37;
        let addi = (lo << 20) | (rd << 15) | (rd << 7) | 0x13;
        out[..4].copy_from_slice(&lui.to_le_bytes());
        out[4..8].copy_from_slice(&addi.to_le_bytes());
    }
    // cast_possible_truncation: syscall numbers fit 32 bits.
    #[allow(clippy::cast_possible_truncation)]
    li32(&mut buf[0..8], 17, SYS_CAP_DELETE as u32); // a7 = nr
    buf[8..12].copy_from_slice(&0x0000_0517u32.to_le_bytes()); // auipc a0, 0 (a0 = stub + 8)
    buf[12..16].copy_from_slice(&0x0105_3503u32.to_le_bytes()); // ld a0, 16(a0) (stub + 24)
    buf[16..20].copy_from_slice(&0x0000_0073u32.to_le_bytes()); // ecall
    let spin = emit_spin(&mut buf[20..]);
    debug_assert_eq!(
        spin, 4,
        "code_stub: the handle literal must sit at offset 24"
    );
    buf[24..32].copy_from_slice(&handle.to_le_bytes()); // a0's literal
    32
}
