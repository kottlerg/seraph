// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/arch/riscv64/idt.rs

//! IDT stub for RISC-V.
//!
//! RISC-V has no IDT. The equivalent mechanism is the `stvec` CSR, which
//! holds the trap vector base address. `load()` reinstalls `stvec` on the
//! current hart — the RISC-V counterpart to `lidt` — and must be called on
//! every hart (BSP and each AP) during per-hart hardware init.

/// Install the kernel trap vector on the current hart.
///
/// Sets `stvec` to `trap_entry` (direct mode). Because `stvec` is a per-hart
/// CSR it is not shared: each hart must write it individually. The BSP writes
/// it in `interrupts::init()`; each AP calls this via `kernel_entry_ap`.
///
/// # Safety
/// Must execute in supervisor mode.
#[cfg(not(test))]
pub unsafe fn load()
{
    // SAFETY: install_trap_vector writes stvec; safe in S-mode.
    unsafe {
        super::interrupts::install_trap_vector();
    }
}

/// No-op stub for host tests (no hardware available).
#[cfg(test)]
pub unsafe fn load() {}
