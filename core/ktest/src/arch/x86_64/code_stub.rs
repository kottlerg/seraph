// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/arch/x86_64/code_stub.rs

//! x86-64 machine-code encoders for the stubs `crate::unit::retype` maps
//! executable in a fresh address space and runs a child thread from. Each
//! returns the stub's bytes.

use syscall_abi::SYS_CAP_DELETE;

/// `loop {}`: `jmp rel8 -2` (to itself).
const SPIN: [u8; 2] = [0xEB, 0xFE];

/// Encode `loop {}`.
#[must_use]
pub fn spin() -> [u8; 2]
{
    SPIN
}

/// Encode `cap_delete(handle); loop {}`.
#[must_use]
pub fn self_delete(handle: u64) -> [u8; 19]
{
    // mov eax, SYS_CAP_DELETE ; movabs rdi, handle ; syscall ; jmp .
    // The handle takes the full 64-bit immediate: its generation sits above
    // the 32-bit index.
    #[expect(
        clippy::cast_possible_truncation,
        reason = "syscall numbers fit 32 bits"
    )]
    let [n0, n1, n2, n3] = (SYS_CAP_DELETE as u32).to_le_bytes();
    let [h0, h1, h2, h3, h4, h5, h6, h7] = handle.to_le_bytes();
    let [s0, s1] = SPIN;
    [
        0xB8, n0, n1, n2, n3, // mov eax, imm32
        0x48, 0xBF, h0, h1, h2, h3, h4, h5, h6, h7, // movabs rdi, imm64
        0x0F, 0x05, // syscall
        s0, s1, // jmp .
    ]
}
