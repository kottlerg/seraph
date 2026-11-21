// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/arch/x86_64/code_stub.rs

//! x86-64 machine-code encoders for the stubs `crate::unit::retype` and
//! `crate::integration::aspace_exit_notification` and
//! `crate::integration::aspace_hold` map executable in a fresh address space
//! and run a child thread from. Each returns the stub's bytes.

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

/// Encode the syscall program runner: entered with the address of a record
/// array in its first argument register, it makes the syscall each
/// eight-word record names in turn (word 0 the number,
/// words 1 to 6 the arguments) and stores its primary return value in the
/// record's word 7, until a record whose number is `u64::MAX`. It then
/// increments that record's word 1 forever, the progress count a test reads
/// to tell a running thread from a stopped one.
#[must_use]
pub fn syscall_program() -> [u8; 54]
{
    [
        0x48, 0x89, 0xFB, // mov rbx, rdi (rbx survives the syscall)
        // top:
        0x48, 0x8B, 0x03, // mov rax, [rbx]
        0x48, 0x83, 0xF8, 0xFF, // cmp rax, -1
        0x74, 0x24, // je done
        0x48, 0x8B, 0x7B, 0x08, // mov rdi, [rbx + 8]
        0x48, 0x8B, 0x73, 0x10, // mov rsi, [rbx + 16]
        0x48, 0x8B, 0x53, 0x18, // mov rdx, [rbx + 24]
        0x4C, 0x8B, 0x53, 0x20, // mov r10, [rbx + 32]
        0x4C, 0x8B, 0x43, 0x28, // mov r8, [rbx + 40]
        0x4C, 0x8B, 0x4B, 0x30, // mov r9, [rbx + 48]
        0x0F, 0x05, // syscall
        0x48, 0x89, 0x43, 0x38, // mov [rbx + 56], rax
        0x48, 0x83, 0xC3, 0x40, // add rbx, 64
        0xEB, 0xD3, // jmp top
        // done:
        0x48, 0xFF, 0x43, 0x08, // inc qword [rbx + 8]
        0xEB, 0xFA, // jmp done
    ]
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
