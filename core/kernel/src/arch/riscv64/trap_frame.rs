// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/arch/riscv64/trap_frame.rs

//! RISC-V 64-bit trap frame — full user-mode register snapshot.
//!
//! [`TrapFrame`] is saved/restored by the supervisor trap handler on every
//! U-mode → S-mode transition (ecall, exception, or timer interrupt).
//!
//! ## Layout (280 bytes)
//!
//! Registers x1–x31 (31 × 8 = 248 bytes) + sepc (8) + scause (8) + stval (8)
//! + sstatus (8) = 280 bytes. x0 (zero) is not stored.
//!
//! The layout exactly matches the push sequence in `trap_entry` in
//! `interrupts.rs` — do not reorder fields.
//!
//! ## RISC-V ecall argument mapping
//!
//! | Field | Role when used as ecall  |
//! |-------|--------------------------|
//! | `a7`  | Syscall number           |
//! | `a0`  | Argument 0; return value |
//! | `a1`  | Argument 1               |
//! | `a2`–`a5` | Arguments 2–5       |

/// Full user-mode register snapshot for RISC-V 64-bit.
///
/// `#[repr(C)]` with size 280 bytes and 8-byte alignment. Field offsets
/// must match the `trap_entry` store sequence; do not reorder fields.
#[repr(C)]
pub struct TrapFrame
{
    // ── General-purpose registers x1–x31 ────────────────────────────────────
    // x0 (zero) is not stored.
    pub ra: u64,  // x1
    pub sp: u64,  // x2
    pub gp: u64,  // x3
    pub tp: u64,  // x4
    pub t0: u64,  // x5
    pub t1: u64,  // x6
    pub t2: u64,  // x7
    pub s0: u64,  // x8
    pub s1: u64,  // x9
    pub a0: u64,  // x10 — arg0 / return value
    pub a1: u64,  // x11
    pub a2: u64,  // x12
    pub a3: u64,  // x13
    pub a4: u64,  // x14
    pub a5: u64,  // x15
    pub a6: u64,  // x16
    pub a7: u64,  // x17 — syscall number
    pub s2: u64,  // x18
    pub s3: u64,  // x19
    pub s4: u64,  // x20
    pub s5: u64,  // x21
    pub s6: u64,  // x22
    pub s7: u64,  // x23
    pub s8: u64,  // x24
    pub s9: u64,  // x25
    pub s10: u64, // x26
    pub s11: u64, // x27
    pub t3: u64,  // x28
    pub t4: u64,  // x29
    pub t5: u64,  // x30
    pub t6: u64,  // x31

    // ── Control/status registers ─────────────────────────────────────────────
    /// Supervisor exception PC — user-mode program counter at trap entry.
    /// Set to `entry_point` before `return_to_user`; advanced past ecall on return.
    pub sepc: u64,
    /// Supervisor cause register (scause at trap entry).
    pub scause: u64,
    /// Supervisor trap value (faulting address or instruction).
    pub stval: u64,
    /// Supervisor status register at trap entry.
    /// Saved so that SPP and SPIE are correctly restored after a context
    /// switch, which can change sstatus on the physical CPU.
    pub sstatus: u64,
}

// ── Syscall / IPC accessors ───────────────────────────────────────────────────

impl TrapFrame
{
    /// Syscall number (a7 on RISC-V).
    pub fn syscall_nr(&self) -> u64
    {
        self.a7
    }

    /// Write the primary syscall return value (a0).
    pub fn set_return(&mut self, val: i64)
    {
        // cast_sign_loss: intentional — negative error codes are sign-extended
        // in the i64 return value and must be reinterpreted as u64 by the caller.
        self.a0 = val.cast_unsigned();
    }

    /// Read syscall argument `n` (0-indexed).
    /// Mapping: 0=a0, 1=a1, 2=a2, 3=a3, 4=a4, 5=a5.
    pub fn arg(&self, n: usize) -> u64
    {
        match n
        {
            0 => self.a0,
            1 => self.a1,
            2 => self.a2,
            3 => self.a3,
            4 => self.a4,
            5 => self.a5,
            _ => 0,
        }
    }

    /// Write IPC return values: primary in a0, label in a1.
    pub fn set_ipc_return(&mut self, primary: u64, label: u64)
    {
        self.a0 = primary;
        self.a1 = label;
    }

    /// Write IPC return values with token: primary in a0, label in a1, token in a2.
    pub fn set_ipc_return_with_token(&mut self, primary: u64, label: u64, token: u64)
    {
        self.a0 = primary;
        self.a1 = label;
        self.a2 = token;
    }

    /// Write `SYS_IPC_CALL` return values: primary in a0, reply label in a1,
    /// reply data-word count in a2. Matches `shared/syscall::syscall5_ret3`.
    pub fn set_ipc_call_return(&mut self, primary: u64, reply_label: u64, reply_word_count: u64)
    {
        self.a0 = primary;
        self.a1 = reply_label;
        self.a2 = reply_word_count;
    }

    /// Write `SYS_IPC_RECV` return values: primary in a0, label in a1,
    /// token in a2, data-word count in a3. Matches `shared/syscall::syscall1_ret4`.
    pub fn set_ipc_recv_return(&mut self, primary: u64, label: u64, token: u64, word_count: u64)
    {
        self.a0 = primary;
        self.a1 = label;
        self.a2 = token;
        self.a3 = word_count;
    }

    /// Initialise the frame for first entry to user mode.
    ///
    /// Sets the supervisor exception PC (`sepc`, the user entry point) and
    /// user stack pointer (`sp` = x2). All other fields remain zero;
    /// `return_to_user` sets `sstatus` (SPP=0, SPIE=1) immediately before
    /// `sret`.
    pub fn init_user(&mut self, entry: u64, stack: u64)
    {
        self.sepc = entry;
        self.sp = stack; // x2 = user stack pointer
    }

    /// Set the first argument register (a0 = x10) in the frame.
    ///
    /// Used by `SYS_THREAD_CONFIGURE` to pass the initial argument value to
    /// the new thread when it first enters user mode.
    pub fn set_arg0(&mut self, val: u64)
    {
        self.a0 = val;
    }

    /// Set the thread-local-storage pointer (`tp`, x4) in the frame.
    ///
    /// `return_to_user` restores `tp` from this field on every U-mode entry,
    /// so this is the canonical per-thread TLS storage on RISC-V. Pass 0 for
    /// a thread that does not use TLS.
    pub fn set_tls_base(&mut self, tls_base: u64)
    {
        self.tp = tls_base;
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests
{
    use super::*;
    use core::mem::{offset_of, size_of};

    #[test]
    fn trap_frame_size_is_280()
    {
        assert_eq!(size_of::<TrapFrame>(), 280);
    }

    #[test]
    fn sepc_offset_is_248()
    {
        assert_eq!(offset_of!(TrapFrame, sepc), 248);
    }

    #[test]
    fn scause_offset_is_256()
    {
        assert_eq!(offset_of!(TrapFrame, scause), 256);
    }

    #[test]
    fn stval_offset_is_264()
    {
        assert_eq!(offset_of!(TrapFrame, stval), 264);
    }

    #[test]
    fn a7_offset_is_128()
    {
        // a7 = x17 is the 17th register stored (after x1-x16 = 16 regs)
        assert_eq!(offset_of!(TrapFrame, a7), 128);
    }

    #[test]
    fn a0_offset_is_72()
    {
        // a0 = x10 is the 10th register stored (after x1-x9 = 9 regs)
        assert_eq!(offset_of!(TrapFrame, a0), 72);
    }
}
