// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// logd/src/arch/riscv64/mod.rs

//! RISC-V serial output via SBI legacy `console_putchar`.
//!
//! Real-logd uses the SBI ``console_putchar`` (EID `0x01`, FID `0x00`)
//! legacy extension rather than direct UART MMIO so it does not need
//! to map the UART aperture or duplicate init's MMIO-mapping
//! plumbing. The `SbiControl` cap (passed via bootstrap caps[3])
//! gates the syscall.

const SBI_LEGACY_CONSOLE_PUTCHAR: u64 = 0x01;
const SBI_LEGACY_FID: u64 = 0x00;

static SBI_CAP: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Install the caller-provided `SbiControl` cap for subsequent
/// [`serial_write_byte`] calls. `thread_cap` is unused on RISC-V
/// (SBI calls are not per-thread). Zero cap silently disables
/// serial output (logd then runs with received log lines buffered
/// in memory only).
pub fn serial_init(_thread_cap: u32, sbi_cap: u32)
{
    SBI_CAP.store(sbi_cap, core::sync::atomic::Ordering::Release);
}

/// Write one byte via SBI legacy `console_putchar`. Silently drops
/// when no `SbiControl` cap was installed.
pub fn serial_write_byte(byte: u8)
{
    let cap = SBI_CAP.load(core::sync::atomic::Ordering::Acquire);
    if cap == 0
    {
        return;
    }
    let _ = syscall::sbi_call(
        cap,
        SBI_LEGACY_CONSOLE_PUTCHAR,
        SBI_LEGACY_FID,
        u64::from(byte),
        0,
        0,
    );
}
