// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// programs/relrofault/src/main.rs

//! RELRO write fixture for the `PT_GNU_RELRO` enforcement test.
//!
//! `MESSAGE` is an immutable static whose initializer carries a relocated
//! pointer, so it lives in `.data.rel.ro` — inside the region the loader
//! must map read-only once relocations are applied. The volatile write
//! must fault; the kernel terminates the thread with the architecture's
//! page-fault exit reason. A clean exit means RELRO was not enforced.
//!
//! Driven by `services/svctest`'s `relro_write_phase`, which spawns this
//! binary, waits for exit, and asserts the non-zero fault reason.

static MESSAGE: &str = "resident of .data.rel.ro";

fn main()
{
    // Force liveness so the static (and its relocation) survive
    // optimisation.
    std::hint::black_box(MESSAGE);
    let target = core::ptr::addr_of!(MESSAGE).cast_mut().cast::<u64>();
    std::os::seraph::log!("relrofault: writing to {target:p}");
    // SAFETY: deliberately invalid — the write targets the read-only
    // RELRO page and must fault. Nothing after it is expected to run.
    unsafe { target.write_volatile(0xDEAD) };
    std::os::seraph::log!("relrofault: WRITE SUCCEEDED (RELRO not enforced)");
}
