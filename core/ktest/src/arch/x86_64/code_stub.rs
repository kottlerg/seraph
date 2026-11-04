// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/arch/x86_64/code_stub.rs

//! x86-64 machine-code encoders for the stubs `crate::unit::retype` maps
//! executable in a fresh address space and runs a child thread from.

use syscall_abi::SYS_CAP_DELETE;

/// Encode `loop {}` into `buf`; returns the byte count.
pub fn emit_spin(buf: &mut [u8]) -> usize
{
    // jmp rel8 -2 (to itself)
    buf[..2].copy_from_slice(&[0xEB, 0xFE]);
    2
}

/// Encode `cap_delete(handle); loop {}` into `buf`; returns the byte count.
pub fn emit_self_delete(buf: &mut [u8], handle: u64) -> usize
{
    // mov eax, SYS_CAP_DELETE ; movabs rdi, handle ; syscall ; jmp .
    // The handle takes the full 64-bit immediate: its generation sits above
    // the 32-bit index.
    // cast_possible_truncation: syscall numbers fit 32 bits.
    #[allow(clippy::cast_possible_truncation)]
    let nr = SYS_CAP_DELETE as u32;
    buf[0] = 0xB8;
    buf[1..5].copy_from_slice(&nr.to_le_bytes());
    buf[5..7].copy_from_slice(&[0x48, 0xBF]);
    buf[7..15].copy_from_slice(&handle.to_le_bytes());
    buf[15..17].copy_from_slice(&[0x0F, 0x05]);
    17 + emit_spin(&mut buf[17..])
}
