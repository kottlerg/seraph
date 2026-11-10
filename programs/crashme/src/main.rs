// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// programs/crashme/src/main.rs

//! Test fixture that dies on a fault on purpose, for the crash report its
//! death leaves in the system log.
//!
//! `crashme vm` writes to the null page, a page fault memmgr cannot back;
//! `crashme exception` executes an illegal instruction. Each first logs under
//! the log name `crashme`, so logd's reclaim line at its death names it, and
//! reaches the fault two calls deep, so the report's stack walk has frames to
//! find. See programs/crashme/README.md.

mod arch;

fn main()
{
    std::os::seraph::log::register_name(b"crashme");
    let mode = std::env::args().nth(1).unwrap_or_default();
    match mode.as_str()
    {
        "vm" | "exception" =>
        {
            std::os::seraph::log!("faulting ({mode})");
            println!("faulting ({mode})");
            outer(mode == "vm");
        }
        _ =>
        {
            println!("usage: crashme vm|exception");
            std::process::exit(2);
        }
    }
}

/// The first of the two calls the fault happens under.
#[inline(never)]
fn outer(vm: bool) -> !
{
    inner(std::hint::black_box(vm))
}

/// Fault: a null-page write for `vm`, else an illegal instruction.
#[inline(never)]
fn inner(vm: bool) -> !
{
    if vm
    {
        // SAFETY: deliberately invalid: the write faults, memmgr cannot back
        // the null page, and the thread dies before the write returns.
        unsafe {
            core::ptr::write_volatile(core::ptr::null_mut::<u64>(), 0x0BAD_C0DE);
        }
    }
    arch::current::illegal_instruction()
}
