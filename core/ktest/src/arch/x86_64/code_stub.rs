// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/arch/x86_64/code_stub.rs

//! x86-64 machine-code encoders for the stubs `crate::unit::retype` and
//! `crate::integration::aspace_exit_notification` map executable in a fresh
//! address space and run a child thread from. Each returns the stub's bytes.

use syscall_abi::{SYS_ASPACE_EXIT, SYS_CAP_DELETE};

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
    // The handle takes the full 64-bit immediate: its generation sits above
    // the 32-bit index.
    syscall1_then_spin(SYS_CAP_DELETE, handle)
}

/// Encode `SYS_ASPACE_EXIT(code); loop {}`. The syscall does not return; the
/// loop is never reached.
#[must_use]
pub fn aspace_exit(code: u64) -> [u8; 19]
{
    syscall1_then_spin(SYS_ASPACE_EXIT, code)
}

/// Encode syscall `nr` with its first argument `arg`, then `loop {}`.
fn syscall1_then_spin(nr: u64, arg: u64) -> [u8; 19]
{
    // mov eax, nr ; movabs rdi, arg ; syscall ; jmp .
    #[expect(
        clippy::cast_possible_truncation,
        reason = "syscall numbers fit 32 bits"
    )]
    let [n0, n1, n2, n3] = (nr as u32).to_le_bytes();
    let [h0, h1, h2, h3, h4, h5, h6, h7] = arg.to_le_bytes();
    let [s0, s1] = SPIN;
    [
        0xB8, n0, n1, n2, n3, // mov eax, imm32
        0x48, 0xBF, h0, h1, h2, h3, h4, h5, h6, h7, // movabs rdi, imm64
        0x0F, 0x05, // syscall
        s0, s1, // jmp .
    ]
}
