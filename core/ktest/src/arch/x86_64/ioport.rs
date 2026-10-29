// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/arch/x86_64/ioport.rs

//! Per-thread I/O port access for ktest (x86-64).
//!
//! Owns the kernel-minted root [`CapType::IoPort`] cap and derives
//! narrow sub-range caps via `ioport_split` as consumers (`serial`,
//! `acpi_shutdown`) request specific ports. This keeps each grant
//! confined to the ports the consumer actually drives instead of
//! binding the full 64K I/O port space at startup.
//!
//! Once `ioport_bind` succeeds for a thread, the grant lasts as long as the
//! carved cap it was made through: deleting that cap, consuming it with a
//! split, or revoking an ancestor of it withdraws it
//! ([capability-model.md](../../../../../docs/capability-model.md) § `IoPort` (x86-64 only)).
//! The carved caps a consumer binds therefore stay in ktest's `CSpace`; the
//! prefix caps left beside them are the ones other tests may consume.

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
/// Carves exactly the requested sub-range ([`carve_port_range`]) and binds
/// the carved cap, which stays in ktest's `CSpace` so the binding lasts.
pub fn bind_port_range(thread_cap: u32, port: u16, count: u16) -> bool
{
    carve_port_range(port, count).is_some_and(|cap| syscall::ioport_bind(thread_cap, cap).is_ok())
}

/// Carve an `IoPort` cap covering exactly `[port, port + count)` out of the
/// wide cap, store the residual (if any) as the new wide cap, and return the
/// carved cap: a lineage root of its own, split from the wide cap.
///
/// Returns `None` when `count` is 0, when the range falls outside the residual
/// wide cap, or when an `ioport_split` fails. When `port` is above the wide
/// cap's base, a failure at the second split (the one at `port + count`) comes
/// after the first has consumed the old wide cap: the prefix cap for
/// `[base, port)` stays in the `CSpace` and the wide cap is left narrowed to
/// `[port, end)`.
pub fn carve_port_range(port: u16, count: u16) -> Option<u32>
{
    if count == 0
    {
        return None;
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
        return None;
    }

    if port_start > base
    {
        // port_start <= 0xFFFF because the caller supplied a u16; safe cast.
        #[allow(clippy::cast_possible_truncation)]
        let (prefix, rest) = syscall::ioport_split(slot, port_start as u16).ok()?;
        // ktest itself never drives the prefix range [base, port_start),
        // but the carved-off prefix cap is left alive in the cspace so
        // that any consumer (test harness, future module, debug probe)
        // that wants to claim those ports can find an IoPort
        // covering them. See `ioport_syscalls::split` (this directory)
        // for the test that relies on this for coverage of the
        // `ioport_split` syscall.
        let _ = prefix;
        slot = rest;
        // The split consumed the old wide cap: record `rest` now, so a failed
        // second split below leaves a wide cap that still resolves.
        // SAFETY: ktest is single-threaded.
        unsafe {
            WIDE = WideCap {
                slot,
                base: port_start,
                end,
            };
        }
    }

    if port_end < end
    {
        // port_end < end <= 0x10000 and we took this branch because
        // port_end != end, so port_end <= 0xFFFF; safe cast.
        #[allow(clippy::cast_possible_truncation)]
        let (target, residual) = syscall::ioport_split(slot, port_end as u16).ok()?;
        // SAFETY: ktest is single-threaded.
        unsafe {
            WIDE = WideCap {
                slot: residual,
                base: port_end,
                end,
            };
        }
        return Some(target);
    }

    // port_end == end: hand out what's left and exhaust the wide cap.
    // SAFETY: ktest is single-threaded.
    unsafe {
        WIDE = WideCap {
            slot: 0,
            base: 0,
            end: 0,
        };
    }
    Some(slot)
}

/// Locate the root `IoPort` descriptor in `InitInfo`.
fn find_root(info: &InitInfo) -> Option<(u32, u32, u32)>
{
    for d in crate::init_info::descriptors(info)
    {
        if d.cap_type == CapType::IoPort
        {
            // aux0 = base port, aux1 = size in ports. The kernel emits
            // aux1 = 0x10000 directly for the full 64K root cap
            // (`core/kernel/src/cap/mod.rs`); the aux1 == 0 branch is
            // defensive against a future change that adopts the in-object
            // `IoPortObject.size == 0` encoding at this surface.
            // cast_possible_truncation: aux0 of an IoPort descriptor is a port
            // base, at most 0xFFFF.
            #[allow(clippy::cast_possible_truncation)]
            let base_u32 = d.aux0 as u32;
            // cast_possible_truncation: aux1 of an IoPort descriptor is a port
            // count, at most 0x10000.
            #[allow(clippy::cast_possible_truncation)]
            let size_u32 = if d.aux1 == 0 { 0x10000 } else { d.aux1 as u32 };
            return Some((d.slot, base_u32, base_u32 + size_u32));
        }
    }
    None
}
