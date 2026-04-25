// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// svcmgr/src/arch/x86_64/mod.rs

//! x86-64 architecture primitives used by svcmgr.

/// Halt the CPU until the next interrupt.
///
/// Invoked from unrecoverable failure paths. On x86-64 this is the real `hlt`
/// instruction; it is privileged, so from userspace it will fault into the
/// kernel, which is the intended escalation path when svcmgr cannot continue.
#[inline]
pub fn halt()
{
    // SAFETY: hlt halts the CPU until the next interrupt. Only legal at
    // CPL 0; invoking it from svcmgr (CPL 3) raises #GP, which is the
    // deliberate escalation signal for halt_loop() — the kernel terminates
    // the faulting thread.
    unsafe {
        core::arch::asm!("hlt", options(nomem, nostack));
    }
}
