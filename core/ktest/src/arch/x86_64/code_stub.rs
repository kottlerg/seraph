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
pub fn emit_self_delete(buf: &mut [u8], handle: u32) -> usize
{
    // mov eax, SYS_CAP_DELETE ; mov edi, handle ; syscall ; jmp .
    // cast_possible_truncation: syscall numbers fit 32 bits.
    #[allow(clippy::cast_possible_truncation)]
    let nr = SYS_CAP_DELETE as u32;
    buf[0] = 0xB8;
    buf[1..5].copy_from_slice(&nr.to_le_bytes());
    buf[5] = 0xBF;
    buf[6..10].copy_from_slice(&handle.to_le_bytes());
    buf[10..12].copy_from_slice(&[0x0F, 0x05]);
    12 + emit_spin(&mut buf[12..])
}
