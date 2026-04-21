// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/arch/x86_64/trap_frame.rs

//! x86-64 trap/syscall frame — full user-mode register snapshot.
//!
//! [`TrapFrame`] is pushed onto the kernel stack by `syscall_entry` (for
//! `SYSCALL`-initiated entries) and by the CPU + IDT stubs (for exceptions
//! and hardware interrupts). The field order matches the push sequence in
//! `syscall_entry` — see that file for the exact assembly layout.
//!
//! ## Layout (168 bytes)
//!
//! ```text
//! offset   0: rax
//! offset   8: rbx
//! offset  16: rcx   (= user RIP after SYSCALL; not a true argument register)
//! offset  24: rdx
//! offset  32: rsi
//! offset  40: rdi
//! offset  48: rbp
//! offset  56: r8
//! offset  64: r9
//! offset  72: r10
//! offset  80: r11   (= user RFLAGS after SYSCALL)
//! offset  88: r12
//! offset  96: r13
//! offset 104: r14
//! offset 112: r15
//! offset 120: rip     (explicit user RIP; = rcx on SYSCALL entry)
//! offset 128: rflags  (explicit user RFLAGS; = r11 on SYSCALL entry)
//! offset 136: rsp     (user RSP saved before switching to kernel stack)
//! offset 144: cs      (user code segment selector)
//! offset 152: ss      (user stack segment selector)
//! offset 160: fs_base (user FS.base MSR — thread-local pointer)
//! ```
//!
//! The `syscall_entry` assembly pushes `fs_base` first (highest address) and
//! `rax` last (lowest address). After all pushes RSP points at `rax`, which
//! is the address passed to `syscall_dispatch` as the `TrapFrame` pointer.
//!
//! ## Syscall argument mapping (x86-64)
//!
//! | Field   | Role when used as syscall |
//! |---------|--------------------------|
//! | `rax`   | Syscall number           |
//! | `rdi`   | Argument 0               |
//! | `rsi`   | Argument 1               |
//! | `rdx`   | Argument 2               |
//! | `r10`   | Argument 3               |
//! | `r8`    | Argument 4               |
//! | `r9`    | Argument 5               |
//!
//! `rcx` and `r11` are clobbered by `SYSCALL`; they carry `rip`/`rflags`
//! and are stored in the dedicated `rip`/`rflags` fields rather than the
//! `rcx`/`r11` GPR slots. Userspace wrappers must not rely on `rcx`/`r11`
//! being preserved across a syscall.

// cast_sign_loss: i64→u64 register interpretation; sign semantics are intentional (SYSRET RIP).
// cast_lossless: u16→u64 segment register widening.
#![allow(clippy::cast_sign_loss, clippy::cast_lossless)]

/// Full user-mode register snapshot saved on the kernel stack at every
/// kernel entry (syscall, exception, or interrupt from ring-3).
///
/// `#[repr(C)]` with size 168 bytes and 8-byte alignment. Field offsets
/// must match the `syscall_entry` push order; do not reorder fields.
#[repr(C)]
pub struct TrapFrame
{
    // ── General-purpose registers ─────────────────────────────────────────
    // Pushed LAST in syscall_entry; lowest virtual addresses in the frame.
    /// rax — syscall number on entry; primary return value on exit.
    pub rax: u64,
    pub rbx: u64,
    /// rcx — clobbered by SYSCALL (holds user RIP). See `rip` field.
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    /// r11 — clobbered by SYSCALL (holds user RFLAGS). See `rflags` field.
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,

    // ── CPU-state fields ──────────────────────────────────────────────────
    // Pushed FIRST in syscall_entry; highest virtual addresses in the frame.
    /// User-mode instruction pointer (= rcx on SYSCALL entry; = RIP in interrupt frame).
    pub rip: u64,
    /// User-mode RFLAGS (= r11 on SYSCALL entry).
    pub rflags: u64,
    /// User-mode stack pointer (saved from a per-CPU scratch location).
    pub rsp: u64,
    /// User code segment selector (e.g. 0x23 = `USER_CS`, ring 3).
    pub cs: u64,
    /// User stack segment selector (e.g. 0x1B = `USER_DS`, ring 3).
    pub ss: u64,
    /// FS.base MSR value — user-mode thread-local-storage pointer.
    pub fs_base: u64,
}

// ── Syscall / IPC accessors ───────────────────────────────────────────────────

impl TrapFrame
{
    /// Syscall number (rax on x86-64).
    pub fn syscall_nr(&self) -> u64
    {
        self.rax
    }

    /// Write the primary syscall return value (rax).
    pub fn set_return(&mut self, val: i64)
    {
        self.rax = val as u64;
    }

    /// Read syscall argument `n` (0-indexed).
    /// Mapping: 0=rdi, 1=rsi, 2=rdx, 3=r10, 4=r8, 5=r9.
    pub fn arg(&self, n: usize) -> u64
    {
        match n
        {
            0 => self.rdi,
            1 => self.rsi,
            2 => self.rdx,
            3 => self.r10,
            4 => self.r8,
            5 => self.r9,
            _ => 0,
        }
    }

    /// Write IPC return values: primary in rax, label in rdx.
    pub fn set_ipc_return(&mut self, primary: u64, label: u64)
    {
        self.rax = primary;
        self.rdx = label;
    }

    /// Write IPC return values with token: primary in rax, label in rdx, token in rsi.
    pub fn set_ipc_return_with_token(&mut self, primary: u64, label: u64, token: u64)
    {
        self.rax = primary;
        self.rdx = label;
        self.rsi = token;
    }

    /// Initialise the frame for first entry to user mode.
    ///
    /// Sets the user entry point (`rip`), user stack (`rsp`), segment
    /// selectors (ring-3 CS/SS), and RFLAGS (IF=1). All other fields remain
    /// zero.
    pub fn init_user(&mut self, entry: u64, stack: u64)
    {
        self.rip = entry;
        self.rsp = stack;
        self.cs = super::gdt::USER_CS as u64;
        self.ss = super::gdt::USER_DS as u64;
        self.rflags = 0x202; // IF=1, reserved bit 1 set
    }

    /// Set the first argument register (rdi) in the frame.
    ///
    /// Used by `SYS_THREAD_CONFIGURE` to pass the initial argument value to
    /// the new thread when it first enters user mode.
    pub fn set_arg0(&mut self, val: u64)
    {
        self.rdi = val;
    }

    /// Set the thread-local-storage pointer (`fs_base` field, unused on x86-64).
    ///
    /// x86-64 carries the canonical TLS base in `SavedState.fs_base`, which
    /// the context switch rdmsr/wrmsrs around `IA32_FS_BASE`. This trap-frame
    /// field is retained for layout stability only. See
    /// [`crate::arch::x86_64::context::seed_tls_base`].
    pub fn set_tls_base(&mut self, tls_base: u64)
    {
        self.fs_base = tls_base;
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests
{
    use super::*;
    use core::mem::{offset_of, size_of};

    #[test]
    fn trap_frame_size_is_168()
    {
        assert_eq!(size_of::<TrapFrame>(), 168);
    }

    #[test]
    fn field_offsets()
    {
        assert_eq!(offset_of!(TrapFrame, rax), 0);
        assert_eq!(offset_of!(TrapFrame, rbx), 8);
        assert_eq!(offset_of!(TrapFrame, rcx), 16);
        assert_eq!(offset_of!(TrapFrame, rdx), 24);
        assert_eq!(offset_of!(TrapFrame, rsi), 32);
        assert_eq!(offset_of!(TrapFrame, rdi), 40);
        assert_eq!(offset_of!(TrapFrame, rbp), 48);
        assert_eq!(offset_of!(TrapFrame, r8), 56);
        assert_eq!(offset_of!(TrapFrame, r9), 64);
        assert_eq!(offset_of!(TrapFrame, r10), 72);
        assert_eq!(offset_of!(TrapFrame, r11), 80);
        assert_eq!(offset_of!(TrapFrame, r12), 88);
        assert_eq!(offset_of!(TrapFrame, r13), 96);
        assert_eq!(offset_of!(TrapFrame, r14), 104);
        assert_eq!(offset_of!(TrapFrame, r15), 112);
        assert_eq!(offset_of!(TrapFrame, rip), 120);
        assert_eq!(offset_of!(TrapFrame, rflags), 128);
        assert_eq!(offset_of!(TrapFrame, rsp), 136);
        assert_eq!(offset_of!(TrapFrame, cs), 144);
        assert_eq!(offset_of!(TrapFrame, ss), 152);
        assert_eq!(offset_of!(TrapFrame, fs_base), 160);
    }
}
