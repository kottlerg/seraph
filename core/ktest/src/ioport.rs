// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// ktest/src/ioport.rs

//! Per-thread I/O port access for ktest (x86-64).
//!
//! Owns the kernel-minted root [`CapType::IoPort`] cap and derives
//! narrow sub-range caps via `ioport_split` as consumers (`serial`,
//! `acpi_shutdown`) request specific ports. This keeps each grant
//! confined to the ports the consumer actually drives instead of
//! binding the full 64K I/O port space at startup.
//!
//! Once `ioport_bind` succeeds for a thread, the IOPB grant for those
//! ports is per-thread state that outlives the cap itself (see
//! `core/kernel/src/sched/thread.rs::TCB::iopb`), so narrow caps
//! produced here may be freely consumed afterwards (e.g. by Tier-1
//! unit tests that exercise `ioport_split`) without disturbing the
//! established permission.

use init_protocol::{CapType, InitInfo};

/// Widest live `IoPort` cap, plus the port range it covers.
#[derive(Clone, Copy)]
struct WideCap
{
    /// `CSpace` slot of the cap. 0 means uninitialised or exhausted.
    slot: u32,
    /// First port covered by the cap.
    base: u32,
    /// One past the last port covered by the cap.
    end: u32,
}

// SAFETY: ktest is single-threaded on every path that touches this.
static mut WIDE: WideCap = WideCap {
    slot: 0,
    base: 0,
    end: 0,
};

/// Seed the wide cap from the root `IoPort` descriptor in `InitInfo`.
///
/// Called once from `main::run` before any `bind_port_range` consumer.
/// A second call would overwrite the residual-cap slot tracked here
/// without recovering any carve products already produced.
pub fn init(info: &InitInfo)
{
    let Some((slot, base, end)) = find_root(info)
    else
    {
        return;
    };
    // SAFETY: ktest is single-threaded on this initialisation path.
    unsafe {
        WIDE = WideCap { slot, base, end };
    }
}

/// Bind `[port, port + count)` to `thread_cap`. Returns `true` on
/// success.
///
/// Splits the wide cap to carve out exactly the requested sub-range,
/// binds the carved cap, and stores the residual (if any) as the new
/// wide cap. A request whose range falls outside the residual wide
/// cap fails.
pub fn bind_port_range(thread_cap: u32, port: u16, count: u16) -> bool
{
    if count == 0
    {
        return false;
    }
    let port_start = u32::from(port);
    let port_end = port_start + u32::from(count);
    // SAFETY: ktest is single-threaded.
    let WideCap {
        mut slot,
        base,
        end,
    } = unsafe { WIDE };
    if slot == 0 || port_start < base || port_end > end
    {
        return false;
    }

    if port_start > base
    {
        // port_start <= 0xFFFF because the caller supplied a u16; safe cast.
        #[allow(clippy::cast_possible_truncation)]
        let Ok((prefix, rest)) = syscall::ioport_split(slot, port_start as u16)
        else
        {
            return false;
        };
        // ktest itself never drives the prefix range [base, port_start),
        // but the carved-off prefix cap is left alive in the cspace so
        // that any consumer (test harness, future module, debug probe)
        // that wants to claim those ports can find an IoPort
        // covering them. See `core/ktest/src/unit/hw.rs::ioport_split`
        // for the test that relies on this for coverage of the
        // `ioport_split` syscall.
        let _ = prefix;
        slot = rest;
    }

    if port_end < end
    {
        // port_end < end <= 0x10000 and we took this branch because
        // port_end != end, so port_end <= 0xFFFF; safe cast.
        #[allow(clippy::cast_possible_truncation)]
        let Ok((target, residual)) = syscall::ioport_split(slot, port_end as u16)
        else
        {
            return false;
        };
        // SAFETY: ktest is single-threaded.
        unsafe {
            WIDE = WideCap {
                slot: residual,
                base: port_end,
                end,
            };
        }
        return syscall::ioport_bind(thread_cap, target).is_ok();
    }

    // port_end == end: bind what's left and exhaust the wide cap.
    // SAFETY: ktest is single-threaded.
    unsafe {
        WIDE = WideCap {
            slot: 0,
            base: 0,
            end: 0,
        };
    }
    syscall::ioport_bind(thread_cap, slot).is_ok()
}

/// Locate the root `IoPort` descriptor in `InitInfo`.
fn find_root(info: &InitInfo) -> Option<(u32, u32, u32)>
{
    let base = core::ptr::from_ref::<InitInfo>(info).cast::<u8>();
    // SAFETY: cap_descriptors_offset and _count are set by the kernel.
    #[allow(clippy::cast_ptr_alignment)]
    let descs = unsafe {
        core::slice::from_raw_parts(
            base.add(info.cap_descriptors_offset as usize)
                .cast::<init_protocol::CapDescriptor>(),
            info.cap_descriptor_count as usize,
        )
    };
    for d in descs
    {
        if d.cap_type == CapType::IoPort
        {
            // aux0 = base port, aux1 = size in ports. The kernel emits
            // aux1 = 0x10000 directly for the full 64K root cap
            // (`core/kernel/src/cap/mod.rs`); the aux1 == 0 branch is
            // defensive against a future change that adopts the in-object
            // `IoPortObject.size == 0` encoding at this surface.
            #[allow(clippy::cast_possible_truncation)]
            let base_u32 = d.aux0 as u32;
            #[allow(clippy::cast_possible_truncation)]
            let size_u32 = if d.aux1 == 0 { 0x10000 } else { d.aux1 as u32 };
            return Some((d.slot, base_u32, base_u32 + size_u32));
        }
    }
    None
}
