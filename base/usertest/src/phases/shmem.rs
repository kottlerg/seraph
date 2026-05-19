// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! Shared-memory primitive (kernel shmem objects).

use crate::bootstrap::Caps;
use crate::runner::Phase;

pub fn phases() -> &'static [Phase]
{
    &[Phase {
        name: "shmem",
        run: shmem_phase,
    }]
}

pub fn shmem_phase(_: &Caps)
{
    use shmem::{SpscHeader, SpscReader, SpscWriter};

    const CAP: usize = 64;
    #[repr(C, align(8))]
    struct Buf
    {
        header: SpscHeader,
        body: [u8; CAP],
    }
    #[allow(clippy::cast_possible_truncation)]
    let mut buf = Buf {
        header: SpscHeader {
            head: core::sync::atomic::AtomicU32::new(0),
            tail: core::sync::atomic::AtomicU32::new(0),
            capacity: CAP as u32,
            closed: core::sync::atomic::AtomicU32::new(0),
        },
        body: [0u8; CAP],
    };

    let region_vaddr = &raw mut buf as u64;
    // SAFETY: `buf` lives for the whole phase; header is pre-initialised by
    // the `Buf` literal above, so Init's job is already done.
    let (mut writer, mut reader): (SpscWriter<'_>, SpscReader<'_>) =
        unsafe { shmem::spsc_pair(region_vaddr) };

    let payload: [u8; 10] = [0xDE, 0xAD, 0xBE, 0xEF, 1, 2, 3, 4, 5, 6];
    let n = writer.write(&payload);
    assert_eq!(n, payload.len(), "writer.write full payload");

    let mut out = [0u8; 10];
    let m = reader.read(&mut out);
    assert_eq!(m, payload.len(), "reader.read full payload");
    assert_eq!(out, payload, "shmem round-trip mismatch");
    assert!(reader.is_empty(), "ring must be empty after full drain");

    let big = [0xAAu8; CAP + 8];
    let pushed = writer.write(&big);
    assert_eq!(pushed, CAP, "writer must cap at ring capacity");
    assert_eq!(writer.write(&[0x11]), 0, "writer must reject when full");

    let mut sink = [0u8; CAP];
    let drained = reader.read(&mut sink);
    assert_eq!(drained, CAP, "reader must drain capacity");
    assert!(sink.iter().all(|&b| b == 0xAA), "drained bytes mismatch");

    std::os::seraph::log!("shmem phase passed");
}
