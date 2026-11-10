// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/gdbstub/src/lib.rs

//! Host-testable logic of the GDB stub: the map between the kernel's
//! register file and GDB's register block ([`regs`]), the inserted
//! breakpoints ([`breakpoints`]), and the signal a stop reports
//! ([`stop_signal`]). The service (`main.rs`) holds the target's threads,
//! the debug port, and the fault receiver.

#![no_std]

pub mod breakpoints;
pub mod regs;

/// GDB's signal numbers a stop reply reports.
pub mod signal
{
    /// `SIGINT`: GDB interrupted the target.
    pub const INT: u8 = 2;
    /// `SIGILL`: an illegal instruction.
    pub const ILL: u8 = 4;
    /// `SIGTRAP`: a breakpoint, a step, or the stop of an attach.
    pub const TRAP: u8 = 5;
    /// `SIGBUS`: a misaligned access.
    pub const BUS: u8 = 7;
    /// `SIGFPE`: an arithmetic exception.
    pub const FPE: u8 = 8;
    /// `SIGSEGV`: a memory fault, or a page fault the pager forwarded.
    pub const SEGV: u8 = 11;
}

/// The signal a stop on a fault message of kind `kind` and, for an
/// exception, class `exception` (`FAULT_EXC_*`) reports.
#[must_use]
pub fn stop_signal(kind: u64, exception: u64) -> u8
{
    match (kind, exception)
    {
        (
            syscall_abi::FAULT_KIND_EXCEPTION,
            syscall_abi::FAULT_EXC_BREAKPOINT | syscall_abi::FAULT_EXC_DEBUG,
        ) => signal::TRAP,
        (syscall_abi::FAULT_KIND_EXCEPTION, syscall_abi::FAULT_EXC_ILLEGAL_INSTRUCTION) =>
        {
            signal::ILL
        }
        (syscall_abi::FAULT_KIND_EXCEPTION, syscall_abi::FAULT_EXC_ALIGNMENT) => signal::BUS,
        (
            syscall_abi::FAULT_KIND_EXCEPTION,
            syscall_abi::FAULT_EXC_DIVIDE
            | syscall_abi::FAULT_EXC_OVERFLOW
            | syscall_abi::FAULT_EXC_FP,
        ) => signal::FPE,
        (syscall_abi::FAULT_KIND_UPCALL, _) => signal::INT,
        _ => signal::SEGV,
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn breakpoints_and_steps_stop_with_sigtrap_and_faults_with_their_signal()
    {
        let exc = syscall_abi::FAULT_KIND_EXCEPTION;
        assert_eq!(
            stop_signal(exc, syscall_abi::FAULT_EXC_BREAKPOINT),
            signal::TRAP
        );
        assert_eq!(stop_signal(exc, syscall_abi::FAULT_EXC_DEBUG), signal::TRAP);
        assert_eq!(
            stop_signal(exc, syscall_abi::FAULT_EXC_ILLEGAL_INSTRUCTION),
            signal::ILL
        );
        assert_eq!(stop_signal(exc, syscall_abi::FAULT_EXC_DIVIDE), signal::FPE);
        assert_eq!(
            stop_signal(exc, syscall_abi::FAULT_EXC_ALIGNMENT),
            signal::BUS
        );
        assert_eq!(
            stop_signal(exc, syscall_abi::FAULT_EXC_PROTECTION),
            signal::SEGV
        );
        // A page fault the pager forwarded through the exception class.
        assert_eq!(stop_signal(syscall_abi::FAULT_KIND_VM, 0), signal::SEGV);
    }
}
