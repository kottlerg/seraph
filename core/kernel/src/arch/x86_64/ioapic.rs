// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/arch/x86_64/ioapic.rs

//! I/O APIC driver for x86-64.
//!
//! Programs interrupt redirection entries so device IRQs (GSIs) are delivered
//! to the CPU as IDT vectors. Supports up to [`boot_protocol::MAX_IOAPICS`]
//! per system; per-IOAPIC bases and `gsi_base` are read from
//! `BootInfo.kernel_mmio.ioapics[..]` (cached at boot via
//! [`crate::platform::capture_kernel_mmio`]) with a single-IOAPIC fallback at
//! [`super::platform`]'s default.
//!
//! # Hardware interface
//! Each I/O APIC is memory-mapped at its `phys_base`, accessible via the
//! kernel direct map. Two 32-bit registers control access:
//! - `IOREGSEL` (offset 0x00): index of the register to read/write.
//! - `IOWIN`    (offset 0x10): data window for the selected register.
//!
//! Redirection entries are 64-bit values spanning two 32-bit registers:
//! - Low  dword at index `0x10 + 2 * pin`
//! - High dword at index `0x11 + 2 * pin`
//!
//! `pin` is the intra-IOAPIC pin number; the global GSI is `gsi_base + pin`.
//!
//! # Locking
//! Every register access is an `IOREGSEL` store followed by an `IOWIN` access,
//! and [`mask`] and [`unmask`] read-modify-write an entry. [`route`], [`mask`]
//! and [`unmask`] run on any CPU (`SYS_IRQ_REGISTER`, `SYS_IRQ_ACK`, the
//! device-IRQ dispatch in interrupt context, and the Interrupt and Notification
//! dealloc paths, which mask a line), so each holds `IOAPIC_LOCK`, a
//! leaf lock taken with interrupts disabled, across its whole access sequence;
//! otherwise another CPU's select could land between a select and its window
//! access and redirect the value to another entry. [`init`] runs single-threaded
//! before any IRQ is routed and takes no lock.
//!
//! # Vector assignment
//! Each CPU has its own device vectors, `DEVICE_VECTOR_BASE..=DEVICE_VECTOR_LAST` (33-249,
//! between the timer vector and the IPI vectors), held in its row of a per-CPU slab
//! ([`init_vector_storage`]): entry `v - DEVICE_VECTOR_BASE` of CPU `c`'s row holds the
//! source the vector is assigned to on `c`, plus one, or 0 when it is free. A source is a
//! GSI routed through an I/O APIC ([`assign_vector`], from `interrupts::route_device_irq`)
//! or a message-signaled target (`irq::MESSAGE_ID_BASE` and up, from
//! `interrupts::alloc_message_target`), and releases its vector when its route is cleared
//! or the target freed ([`release_vector`]). `idt::init` installs a generated stub on every
//! device vector, and `idt::irq_dispatch` maps the vector back to its source through the
//! executing CPU's row ([`source_for_vector`]). Each CPU routes up to
//! [`DEVICE_VECTOR_COUNT`] sources at once; a route or mint that finds no CPU with a free
//! vector is refused (`irq::RouteError::Exhausted`). A row is written only by the route
//! changes, which `irq` serialises under its routing lock, and read lock-free by the
//! dispatch on its own CPU.
//!
//! # Destination
//! Each route names one destination CPU, chosen at route time by `irq::next_target_cpu`
//! among the CPUs whose APIC id the 8-bit physical destination field of a redirection
//! entry can name: below [`BROADCAST_APIC_ID`] (`0xFF`, which delivers to every CPU;
//! `interrupts::route_device_irq`). An I/O APIC cannot name a CPU with a wider x2APIC id
//! without interrupt remapping, which the kernel does not program.
//!
//! # Trigger and polarity
//!
//! A redirection entry takes its trigger mode (bit 15, set for level) and pin polarity
//! (bit 13, set for active-low) from the mode its line's first `SYS_IRQ_REGISTER` passed
//! ([`redirection_low`]); the kernel reads no MADT interrupt-source override itself. A
//! level-triggered entry's Remote IRR, set at delivery, is cleared by the local APIC's EOI,
//! which the local APIC broadcasts to the I/O APICs (the kernel clears the SVR's EOI-broadcast
//! suppression bit on every CPU, `interrupts::init` and `init_ap`). A device IRQ masks its entry
//! before that EOI (`irq::dispatch_device_irq`), so an assertion still held at the unmask is
//! delivered again. A delivery a CPU accepted while its line was being released leaves Remote
//! IRR set, which stays set when the line is routed again, on another vector, before that
//! delivery's EOI; [`route`] clears it before it programs the entry again
//! ([`remote_irr_clear`]).
//!
//! # Modification notes
//! - Every GSI is routed by `interrupts::route_device_irq` (from `SYS_IRQ_REGISTER`, through
//!   `irq::register`), released by `interrupts::unroute_device_irq`, and unmasked by
//!   `interrupts::unmask` (from `SYS_IRQ_ACK`).

// cast_possible_truncation: u64→usize APIC MMIO address arithmetic; bounded by APIC layout.
// cast_lossless: u8→u32 vector widening casts.
#![allow(clippy::cast_possible_truncation, clippy::cast_lossless)]

use core::sync::atomic::{AtomicU32, Ordering};

use boot_protocol::{IoApicEntry, MAX_IOAPICS};

// ── Hardware constants ────────────────────────────────────────────────────────

/// Register select offset (write GSI index here).
const IOREGSEL: usize = 0x00;
/// Data window offset (read/write data here after selecting register).
const IOWIN: usize = 0x10;

/// I/O APIC identification register.
const IOAPICID: u32 = 0x00;
/// I/O APIC version register (bits [23:16] = max redirection entry index).
const IOAPICVER: u32 = 0x01;

/// First IDT vector assigned to device IRQs, the one after the timer vector.
pub const DEVICE_VECTOR_BASE: u8 = 33;

/// Last IDT vector assigned to device IRQs, the one below the IPI vectors (250 and 251;
/// the spurious vector is 255).
pub const DEVICE_VECTOR_LAST: u8 = 249;

/// Number of device vectors of each CPU, and so the number of sources (routed GSIs and
/// message-signaled targets) that CPU takes at once: 217.
pub const DEVICE_VECTOR_COUNT: usize = (DEVICE_VECTOR_LAST - DEVICE_VECTOR_BASE) as usize + 1;

/// Pins an I/O APIC can have: its version register reports the last redirection entry in
/// an 8-bit field.
pub const IOAPIC_MAX_PINS: u32 = 256;

/// The physical-mode destination id that delivers to every local APIC (all ones in the
/// 8-bit field); no single CPU can be named by it.
// dead_code: host test builds compile out its reader (`interrupts::route_device_irq`).
#[cfg_attr(test, allow(dead_code))]
pub const BROADCAST_APIC_ID: u32 = 0xFF;

/// One CPU's device vectors: the source each is assigned to, plus one (0 when free), at
/// index `v - DEVICE_VECTOR_BASE` for vector `v`, and where the next search for a free
/// vector starts: one past the vector last assigned, moved past a released vector the
/// search would otherwise reach before any other free one ([`release_vector_in`]). The
/// search moves through the vectors in turn, so a released vector is taken again only once
/// the search comes round to it, not by the next route while other vectors are free
/// (`interrupts::unroute_device_irq`). The zeroed row is all free, its search starting at
/// the first vector.
// dead_code: host test builds compile out the readers of its fields (`vector_row` and
// its callers); the host tests drive the same helpers over a bare table.
#[cfg_attr(test, allow(dead_code))]
#[repr(C)]
struct VectorRow
{
    owner: [AtomicU32; DEVICE_VECTOR_COUNT],
    cursor: AtomicU32,
}

// docs/limits.md states the slab's per-CPU cost from this size: 217 owner entries and the
// cursor, 4 bytes each.
const _: () = assert!(core::mem::size_of::<VectorRow>() == 872);

/// The device-vector slab: one [`VectorRow`] per CPU.
const VECTOR_ROW_SLAB: crate::sched::PerCpuSlab =
    crate::sched::PerCpuSlab::of::<VectorRow>("DEVICE_VECTOR_ROWS");
const _: () = assert!(
    VECTOR_ROW_SLAB.sized_at_every_width(),
    "DEVICE_VECTOR_ROWS slab overflows"
);

/// Base of the device-vector slab, one [`VectorRow`] per boot CPU; set by
/// [`init_vector_storage`].
#[cfg(not(test))]
static VECTOR_ROWS: core::sync::atomic::AtomicPtr<VectorRow> =
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());

/// Allocate the per-CPU device-vector rows for `cpu_count` CPUs, zero-filled (every
/// vector free). Called from `init_ap_percpu_storage` (Phase 4), before any source is
/// routed.
#[cfg(not(test))]
pub fn init_vector_storage(cpu_count: usize, allocator: &mut crate::mm::BuddyAllocator)
{
    let base = crate::sched::alloc_per_cpu_slab::<VectorRow>(VECTOR_ROW_SLAB, cpu_count, allocator);
    VECTOR_ROWS.store(base, Ordering::Release);
}

/// CPU `cpu`'s device-vector row, or `None` when `cpu` is past the boot CPU count or the
/// rows are not yet allocated.
#[cfg(not(test))]
fn vector_row(cpu: usize) -> Option<&'static VectorRow>
{
    let cpu_count = crate::sched::CPU_COUNT.load(Ordering::Relaxed) as usize;
    let base = VECTOR_ROWS.load(Ordering::Acquire);
    if cpu >= cpu_count || base.is_null()
    {
        return None;
    }
    // SAFETY: the slab holds a zero-initialised VectorRow (all atomics, for which zero is
    // a valid value) for each boot CPU, and `cpu` is below their count; the slab is never
    // freed.
    Some(unsafe { &*base.add(cpu) })
}

/// The device vector at `index` of a vector table.
fn vector_at(index: usize) -> Option<u8>
{
    u8::try_from(index)
        .ok()
        .and_then(|offset| DEVICE_VECTOR_BASE.checked_add(offset))
}

/// The vector `table` assigns to `source`, if any.
fn find_vector(table: &[AtomicU32], source: u32) -> Option<u8>
{
    let tag = source.checked_add(1)?;
    let index = table
        .iter()
        .position(|entry| entry.load(Ordering::Relaxed) == tag)?;
    vector_at(index)
}

/// The index of the first free vector of `table` at or after index `start`, wrapping
/// round; `None` when every vector is assigned. The one search [`assign_vector_in`] takes
/// and [`release_vector_in`] predicts.
fn first_free_from(table: &[AtomicU32], start: usize) -> Option<usize>
{
    (0..table.len())
        .map(|offset| (start + offset) % table.len())
        .find(|&index| table[index].load(Ordering::Relaxed) == 0)
}

/// The vector `table` assigns to `source` and the index the next search starts at: its
/// existing vector, else the first free vector at or after index `start` (wrapping), now
/// assigned to it. `None` when every vector is assigned (or `source` is `u32::MAX`, which
/// names no source).
fn assign_vector_in(table: &[AtomicU32], source: u32, start: usize) -> Option<(u8, usize)>
{
    if let Some(vector) = find_vector(table, source)
    {
        return Some((vector, start));
    }
    let tag = source.checked_add(1)?;
    let index = first_free_from(table, start)?;
    // Release: a dispatch that reads the tag (Acquire) once the redirection entry or the
    // message that names this vector fires sees a complete assignment.
    table[index].store(tag, Ordering::Release);
    Some((vector_at(index)?, (index + 1) % table.len()))
}

/// Free every vector `table` assigns to `source`, and return the search cursor `cursor`
/// moved past each freed index a search from it would reach before any other free vector,
/// so the next search does not take a vector just released while another is free.
fn release_vector_in(table: &[AtomicU32], source: u32, cursor: usize) -> usize
{
    let Some(tag) = source.checked_add(1)
    else
    {
        return cursor;
    };
    let mut cursor = cursor;
    for (index, entry) in table.iter().enumerate()
    {
        if entry.load(Ordering::Relaxed) == tag
        {
            entry.store(0, Ordering::Release);
            if first_free_from(table, cursor) == Some(index)
            {
                cursor = (index + 1) % table.len();
            }
        }
    }
    cursor
}

/// Whether CPU `cpu` has a free device vector.
#[cfg(not(test))]
#[must_use]
pub fn has_free_vector(cpu: usize) -> bool
{
    vector_row(cpu).is_some_and(|row| first_free_from(&row.owner, 0).is_some())
}

/// Assign `source` a device vector of CPU `cpu`: the next free one in turn of that CPU's
/// row. `None` when every device vector of `cpu` is assigned, or `cpu` has no row. Called
/// under `irq`'s routing lock, from `route_device_irq` for a line's first binding and from
/// `alloc_message_target`; the source's release frees the vector, so `source` holds none
/// when this runs, and returning an existing vector instead is defensive.
#[cfg(not(test))]
#[must_use]
pub fn assign_vector(cpu: usize, source: u32) -> Option<u8>
{
    let row = vector_row(cpu)?;
    let start = row.cursor.load(Ordering::Relaxed) as usize;
    let (vector, next) = assign_vector_in(&row.owner, source, start)?;
    // `next` is below DEVICE_VECTOR_COUNT (217), which fits u32.
    #[allow(clippy::cast_possible_truncation)]
    row.cursor.store(next as u32, Ordering::Relaxed);
    Some(vector)
}

/// Free `source`'s device vector on CPU `cpu`. Called under `irq`'s routing lock, after
/// the redirection entry is masked (a line) or once the target is no longer bound (a
/// message target).
#[cfg(not(test))]
pub fn release_vector(cpu: usize, source: u32)
{
    let Some(row) = vector_row(cpu)
    else
    {
        return;
    };
    let cursor = row.cursor.load(Ordering::Relaxed) as usize;
    let cursor = release_vector_in(&row.owner, source, cursor);
    // The cursor is below DEVICE_VECTOR_COUNT (217), which fits u32.
    #[allow(clippy::cast_possible_truncation)]
    row.cursor.store(cursor as u32, Ordering::Relaxed);
}

/// The source device vector `vector` is assigned to on the executing CPU, or `None` for a
/// free vector or one outside the device range. Read in interrupt context
/// (`idt::irq_dispatch`): an interrupt latched before its vector was released finds `None`
/// and is dropped, unless the vector was reassigned before it was serviced, when it
/// reaches the new owner as one spurious delivery (`interrupts::unroute_device_irq`).
#[cfg(not(test))]
#[must_use]
pub fn source_for_vector(vector: u8) -> Option<u32>
{
    let index = vector.checked_sub(DEVICE_VECTOR_BASE)? as usize;
    let row = vector_row(super::cpu::current_cpu() as usize)?;
    let tag = row.owner.get(index)?.load(Ordering::Acquire);
    tag.checked_sub(1)
}

/// Mask bit in the low dword of a redirection entry (bit 16).
const REDIR_MASK: u32 = 1 << 16;

/// Fixed delivery mode (000), physical destination, vector in [7:0].
/// Logical destination mode would be bit 11; we leave it clear (physical).
const REDIR_FIXED: u32 = 0x0000_0000;

/// Trigger-mode bit in the low dword of a redirection entry (bit 15): set for a
/// level-triggered line.
const REDIR_LEVEL: u32 = 1 << 15;

/// Pin-polarity bit in the low dword of a redirection entry (bit 13): set for an
/// active-low line.
const REDIR_ACTIVE_LOW: u32 = 1 << 13;

/// Remote IRR bit in the low dword of a redirection entry (bit 14, read-only):
/// set while a level-triggered delivery awaits the EOI of the entry's vector.
const REDIR_REMOTE_IRR: u32 = 1 << 14;

/// The low dword [`route`] writes first, before the entry it programs, when the
/// entry it replaces is `current`: when `current`'s Remote IRR is set, the same
/// entry masked and edge-triggered, which clears Remote IRR, and `None`
/// otherwise.
///
/// A level delivery a CPU accepted while the line was being released leaves
/// Remote IRR set. When the line is routed again, on another vector, before
/// that delivery's EOI, the EOI of the old vector matches the entry no more,
/// and a level entry whose Remote IRR stays set delivers nothing more. Writing
/// the trigger mode edge clears Remote IRR (the 82093AA, QEMU's and KVM's I/O
/// APICs alike); only the mask and trigger bits change, as Linux's
/// `__eoi_ioapic_pin` does.
const fn remote_irr_clear(current: u32) -> Option<u32>
{
    if current & REDIR_REMOTE_IRR == 0
    {
        None
    }
    else
    {
        Some((current | REDIR_MASK) & !REDIR_LEVEL & !REDIR_REMOTE_IRR)
    }
}

/// The low dword of a masked redirection entry delivering `vector` in fixed mode
/// to a physical destination, with `mode`'s trigger and polarity
/// (`IRQ_MODE_LEVEL`, `IRQ_MODE_ACTIVE_LOW` in `abi/syscall`; bits outside them are
/// ignored, since the syscall refuses them).
const fn redirection_low(vector: u8, mode: u32) -> u32
{
    let mut low = REDIR_MASK | REDIR_FIXED | (vector as u32);
    if mode as u64 & syscall::IRQ_MODE_LEVEL != 0
    {
        low |= REDIR_LEVEL;
    }
    if mode as u64 & syscall::IRQ_MODE_ACTIVE_LOW != 0
    {
        low |= REDIR_ACTIVE_LOW;
    }
    low
}

// ── Per-IOAPIC state ──────────────────────────────────────────────────────────

#[derive(Copy, Clone)]
struct IoApicState
{
    phys_base: u64,
    gsi_base: u32,
    pin_count: u32,
}

const EMPTY_STATE: IoApicState = IoApicState {
    phys_base: 0,
    gsi_base: 0,
    pin_count: 0,
};

/// Discovered I/O APICs, populated once by [`init`] from
/// `kernel_mmio.ioapics[..]` (with a single-entry fallback when the bootloader
/// reports none).
///
/// Written exactly once during Phase 5 `init`, single-threaded;
/// subsequent reads happen from IRQ paths after SMP is active and observe a
/// fully-written value because the write precedes SMP bring-up.
static mut IOAPICS: [IoApicState; MAX_IOAPICS] = [EMPTY_STATE; MAX_IOAPICS];
static mut IOAPIC_COUNT: usize = 0;

/// Serialises the `IOREGSEL`/`IOWIN` access sequences of [`route`], [`mask`]
/// and [`unmask`] across CPUs (module doc § Locking). A leaf lock: nothing is
/// acquired while it is held.
static IOAPIC_LOCK: crate::sync::Spinlock = crate::sync::Spinlock::new();

/// One past the highest GSI the I/O APICs in `states` cover, capped at `ceiling`: the
/// routing table's line count.
fn gsi_limit_of(states: &[IoApicState], ceiling: u32) -> u32
{
    states
        .iter()
        .map(|s| s.gsi_base.saturating_add(s.pin_count))
        .max()
        .unwrap_or(0)
        .min(ceiling)
}

/// One past the highest GSI the discovered I/O APICs cover, capped at the Interrupt id
/// space (`super::ROOT_IRQ_COUNT`): the number of lines the routing table needs. Zero
/// before [`init`].
#[cfg(not(test))]
#[must_use]
pub fn gsi_limit() -> u32
{
    // SAFETY: IOAPIC_COUNT and IOAPICS are written exactly once during init,
    // before any reader; entries [0..count) are initialized.
    let states = unsafe {
        core::slice::from_raw_parts(
            core::ptr::addr_of!(IOAPICS).cast::<IoApicState>(),
            IOAPIC_COUNT,
        )
    };
    gsi_limit_of(states, super::ROOT_IRQ_COUNT)
}

/// Whether a discovered I/O APIC implements `gsi`.
#[cfg(not(test))]
#[must_use]
pub fn owns(gsi: u32) -> bool
{
    lookup_ioapic_for_gsi(gsi).is_some()
}

/// Locate the IOAPIC owning `gsi`. Returns `(phys_base, intra_ioapic_pin)`.
fn lookup_ioapic_for_gsi(gsi: u32) -> Option<(u64, u32)>
{
    // SAFETY: IOAPIC_COUNT and IOAPICS are written exactly once during init,
    // before any IRQ delivery; reads observe the fully-written value.
    let count = unsafe { IOAPIC_COUNT };
    let base = core::ptr::addr_of!(IOAPICS).cast::<IoApicState>();
    for i in 0..count
    {
        // SAFETY: i < count ≤ MAX_IOAPICS; entries [0..count) are initialized.
        let s = unsafe { *base.add(i) };
        if gsi >= s.gsi_base && gsi - s.gsi_base < s.pin_count
        {
            return Some((s.phys_base, gsi - s.gsi_base));
        }
    }
    None
}

// ── Register access ───────────────────────────────────────────────────────────

/// Write `val` to register `reg` of the IOAPIC at `phys_base`.
///
/// # Safety
/// Must only be called after Phase 3 (direct map active) with a valid IOAPIC
/// physical base, either from single-threaded [`init`] or with `IOAPIC_LOCK`
/// held across the caller's whole access sequence.
unsafe fn ioapic_write(phys_base: u64, reg: u32, val: u32)
{
    let base = (super::paging::direct_map_base() + phys_base) as usize;
    // SAFETY: phys_base is a valid IOAPIC MMIO base mapped through the direct
    // map; IOREGSEL/IOWIN offsets are within IOAPIC register range; volatile
    // ensures proper ordering of register select and data writes.
    unsafe {
        core::ptr::write_volatile((base + IOREGSEL) as *mut u32, reg);
        core::ptr::write_volatile((base + IOWIN) as *mut u32, val);
    }
}

/// Read register `reg` of the IOAPIC at `phys_base`.
///
/// # Safety
/// Same as [`ioapic_write`].
unsafe fn ioapic_read(phys_base: u64, reg: u32) -> u32
{
    let base = (super::paging::direct_map_base() + phys_base) as usize;
    // SAFETY: see ioapic_write.
    unsafe {
        core::ptr::write_volatile((base + IOREGSEL) as *mut u32, reg);
        core::ptr::read_volatile((base + IOWIN) as *const u32)
    }
}

// ── Public interface ──────────────────────────────────────────────────────────

/// Initialise every I/O APIC reported by the bootloader: read its pin count
/// from the version register, mask all entries.
///
/// # Safety
/// Must be called from a single-threaded context after Phase 3 completes and
/// after `kernel_mmio` has been captured.
#[cfg(not(test))]
pub unsafe fn init()
{
    let mut buf = [IoApicEntry::default(); MAX_IOAPICS];
    let entries = super::platform::ioapics_into(&mut buf);

    let count = entries.len().min(MAX_IOAPICS);
    for (i, entry) in entries.iter().take(count).enumerate()
    {
        // SAFETY: single-threaded init phase after Phase 3; direct map active.
        let ver = unsafe { ioapic_read(entry.phys_base, IOAPICVER) };
        let max_entry = (ver >> 16) & 0xFF;
        let pin_count = max_entry + 1;

        // SAFETY: single-threaded init phase; reading IOAPICID register.
        let ioapic_id = unsafe { ioapic_read(entry.phys_base, IOAPICID) };

        // SAFETY: single-threaded init phase; pre-SMP write.
        unsafe {
            IOAPICS[i] = IoApicState {
                phys_base: entry.phys_base,
                gsi_base: entry.gsi_base,
                pin_count,
            };
        }

        crate::kprintln!(
            "ioapic[{}]: base={:#x} id={:#x} gsi_base={} pins={}",
            i,
            entry.phys_base,
            ioapic_id,
            entry.gsi_base,
            pin_count
        );
        if entry.gsi_base.saturating_add(pin_count) > super::ROOT_IRQ_COUNT
        {
            crate::kprintln!(
                "ioapic[{}]: GSIs from {} lie past the Interrupt id space ({}); not routable",
                i,
                super::ROOT_IRQ_COUNT.max(entry.gsi_base),
                super::ROOT_IRQ_COUNT
            );
        }

        // Mask all entries on this IOAPIC (bit 16 = interrupt mask = 1).
        for pin in 0..pin_count
        {
            // SAFETY: single-threaded init phase; programming redirection
            // entries to masked state; no concurrent access or IRQ delivery.
            unsafe {
                ioapic_write(entry.phys_base, 0x10 + 2 * pin, REDIR_MASK);
                ioapic_write(entry.phys_base, 0x11 + 2 * pin, 0);
            }
        }
    }

    // SAFETY: single-threaded init phase; pre-SMP write.
    unsafe {
        IOAPIC_COUNT = count;
    }
}

/// Program a redirection entry for `gsi` to deliver `vector` to the local APIC
/// with id `destination` (physical destination mode, so at most `0xFF`).
///
/// The entry is programmed masked; call [`unmask`] when ready to receive.
/// Uses fixed delivery, with the trigger mode and polarity `mode` names
/// ([`redirection_low`]). An entry whose Remote IRR a stale level delivery left
/// set is first rewritten masked and edge-triggered, which clears it
/// ([`remote_irr_clear`]). A GSI no discovered I/O APIC owns is left alone
/// (`interrupts::route_device_irq` checks [`owns`] first).
///
/// # Safety
/// Must only be called after [`init`].
#[cfg(not(test))]
pub unsafe fn route(gsi: u32, vector: u8, destination: u8, mode: u32)
{
    let Some((base, pin)) = lookup_ioapic_for_gsi(gsi)
    else
    {
        return;
    };
    // Low dword: vector | fixed delivery | trigger and polarity | masked.
    // High dword: destination APIC id in bits [31:24] (entry bits [63:56]).
    let low = redirection_low(vector, mode);
    let high = u32::from(destination) << 24;

    // SAFETY: caller ensures init() has completed; entry remains masked
    // until unmask(). IOAPIC_LOCK covers every select/window pair below.
    unsafe {
        let saved = IOAPIC_LOCK.lock_raw();
        if let Some(clear) = remote_irr_clear(ioapic_read(base, 0x10 + 2 * pin))
        {
            ioapic_write(base, 0x10 + 2 * pin, clear);
        }
        ioapic_write(base, 0x10 + 2 * pin, low);
        ioapic_write(base, 0x11 + 2 * pin, high);
        IOAPIC_LOCK.unlock_raw(saved);
    }
}

/// Mask (suppress delivery of) the redirection entry for `gsi`.
///
/// # Safety
/// Must only be called after [`init`].
#[cfg(not(test))]
pub unsafe fn mask(gsi: u32)
{
    let Some((base, pin)) = lookup_ioapic_for_gsi(gsi)
    else
    {
        return;
    };
    let reg = 0x10 + 2 * pin;
    // SAFETY: caller ensures init() has completed; setting the mask bit is
    // architecture-defined. IOAPIC_LOCK covers the whole read-modify-write.
    unsafe {
        let saved = IOAPIC_LOCK.lock_raw();
        let current = ioapic_read(base, reg);
        ioapic_write(base, reg, current | REDIR_MASK);
        IOAPIC_LOCK.unlock_raw(saved);
    }
}

/// Unmask (enable delivery of) the redirection entry for `gsi`.
///
/// # Safety
/// Must only be called after [`init`] and after [`route`] has programmed the entry.
#[cfg(not(test))]
pub unsafe fn unmask(gsi: u32)
{
    let Some((base, pin)) = lookup_ioapic_for_gsi(gsi)
    else
    {
        return;
    };
    let reg = 0x10 + 2 * pin;
    // SAFETY: caller ensures init() and route() have completed; clearing the
    // mask bit enables IRQ delivery for a registered handler. IOAPIC_LOCK
    // covers the whole read-modify-write.
    unsafe {
        let saved = IOAPIC_LOCK.lock_raw();
        let current = ioapic_read(base, reg);
        ioapic_write(base, reg, current & !REDIR_MASK);
        IOAPIC_LOCK.unlock_raw(saved);
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests
{
    use super::*;

    fn table() -> [AtomicU32; DEVICE_VECTOR_COUNT]
    {
        [const { AtomicU32::new(0) }; DEVICE_VECTOR_COUNT]
    }

    /// Assign from the start of the table, as a fresh boot's first route does.
    fn assign(t: &[AtomicU32], gsi: u32) -> Option<u8>
    {
        assign_vector_in(t, gsi, 0).map(|(vector, _)| vector)
    }

    #[test]
    fn a_released_vector_is_not_the_next_assigned()
    {
        // Defect caught: a vector freed while an interrupt is latched on it being
        // handed straight to the next GSI, which would take that interrupt.
        let t = table();
        let (first, next) = assign_vector_in(&t, 3, 0).expect("vector");
        let next = release_vector_in(&t, 3, next);
        let (second, _) = assign_vector_in(&t, 4, next).expect("vector");
        assert_ne!(first, second);
    }

    #[test]
    fn a_release_at_the_cursor_moves_the_cursor_past_it()
    {
        // GSI 9 keeps vector index 5 while another GSI's route moves the cursor
        // onto index 5; releasing GSI 9 must not leave the next search starting there.
        let t = table();
        let (_, _) = assign_vector_in(&t, 9, 5).expect("vector");
        let cursor = release_vector_in(&t, 9, 5);
        assert_eq!(cursor, 6);
        let (vector, _) = assign_vector_in(&t, 4, cursor).expect("vector");
        assert_ne!(vector, DEVICE_VECTOR_BASE + 5);
    }

    #[test]
    fn a_release_behind_occupied_vectors_moves_the_cursor_past_it()
    {
        // Indices 0-10 held, the cursor back at 0 after a wrap, and the rest free:
        // releasing index 10 must not leave it the first free vector a search
        // from the cursor reaches.
        let t = table();
        for gsi in 0..=10
        {
            assign_vector_in(&t, gsi, gsi as usize).expect("vector");
        }
        let cursor = release_vector_in(&t, 10, 0);
        let (vector, _) = assign_vector_in(&t, 4000, cursor).expect("vector");
        assert_ne!(vector, DEVICE_VECTOR_BASE + 10);
    }

    #[test]
    fn the_search_wraps_to_a_vector_freed_below_the_cursor()
    {
        // Every vector but index 1 assigned, and the search starting past index 1:
        // it must wrap round the end of the table to find index 1.
        let t = table();
        for gsi in 0..DEVICE_VECTOR_COUNT as u32
        {
            assign_vector_in(&t, gsi, gsi as usize).expect("vector");
        }
        release_vector_in(&t, 1, 100);
        let (vector, _) = assign_vector_in(&t, 5000, 100).expect("vector");
        assert_eq!(vector, DEVICE_VECTOR_BASE + 1);
    }

    #[test]
    fn mode_zero_programs_an_edge_triggered_active_high_masked_entry()
    {
        let low = redirection_low(0x40, 0);
        assert_eq!(low, REDIR_MASK | 0x40);
    }

    #[test]
    fn the_mode_bits_set_the_trigger_and_polarity_bits()
    {
        let level = syscall::IRQ_MODE_LEVEL as u32;
        let active_low = syscall::IRQ_MODE_ACTIVE_LOW as u32;
        assert_eq!(
            redirection_low(0x41, level),
            REDIR_MASK | REDIR_LEVEL | 0x41
        );
        assert_eq!(
            redirection_low(0x42, active_low),
            REDIR_MASK | REDIR_ACTIVE_LOW | 0x42
        );
        assert_eq!(
            redirection_low(0x43, level | active_low),
            REDIR_MASK | REDIR_LEVEL | REDIR_ACTIVE_LOW | 0x43
        );
    }

    #[test]
    fn an_entry_with_remote_irr_set_is_first_rewritten_masked_and_edge()
    {
        let stale = REDIR_LEVEL | REDIR_REMOTE_IRR | 0x45;
        assert_eq!(remote_irr_clear(stale), Some(REDIR_MASK | 0x45));
        // The polarity bit is kept.
        let stale = REDIR_LEVEL | REDIR_ACTIVE_LOW | REDIR_REMOTE_IRR | 0x45;
        assert_eq!(
            remote_irr_clear(stale),
            Some(REDIR_MASK | REDIR_ACTIVE_LOW | 0x45)
        );
    }

    #[test]
    fn an_entry_with_remote_irr_clear_is_programmed_directly()
    {
        assert_eq!(remote_irr_clear(REDIR_LEVEL | REDIR_MASK | 0x45), None);
        assert_eq!(remote_irr_clear(REDIR_MASK), None);
    }

    #[test]
    fn routed_gsis_get_distinct_device_vectors()
    {
        // GSIs past the old 23-gate range (a second I/O APIC's) are assigned too.
        let t = table();
        let a = assign(&t, 2).expect("vector");
        let b = assign(&t, 40).expect("vector");
        assert_ne!(a, b);
        assert_eq!(find_vector(&t, 40), Some(b));
    }

    #[test]
    fn a_gsi_routed_again_keeps_its_vector()
    {
        let t = table();
        let first = assign(&t, 7).expect("vector");
        assert_eq!(assign(&t, 7), Some(first));
    }

    #[test]
    fn exhausted_vectors_refuse_a_new_gsi_until_one_is_released()
    {
        let t = table();
        for gsi in 0..DEVICE_VECTOR_COUNT as u32
        {
            assert!(assign(&t, gsi).is_some());
        }
        assert_eq!(assign(&t, 1000), None);
        release_vector_in(&t, 5, 0);
        assert_eq!(find_vector(&t, 5), None);
        assert!(assign(&t, 1000).is_some());
    }

    #[test]
    fn a_message_target_and_a_gsi_share_one_row()
    {
        // A message-signaled target's source id sits above every GSI
        // (irq::MESSAGE_ID_BASE); it takes a vector of the same row and is found and
        // released by that id without touching the GSI's vector.
        let t = table();
        let line = assign(&t, 9).expect("vector");
        let message = assign(&t, 32_768).expect("vector");
        assert_ne!(line, message);
        assert_eq!(find_vector(&t, 32_768), Some(message));
        release_vector_in(&t, 32_768, 0);
        assert_eq!(find_vector(&t, 32_768), None);
        assert_eq!(find_vector(&t, 9), Some(line));
    }

    #[test]
    fn gsi_zero_is_assignable()
    {
        // The table marks a free vector with 0, so GSI 0 must not read as free.
        let t = table();
        let v = assign(&t, 0).expect("vector");
        assert_eq!(find_vector(&t, 0), Some(v));
        assert_ne!(assign(&t, 1), Some(v));
    }

    #[test]
    fn device_vectors_avoid_the_exception_timer_ipi_and_spurious_vectors()
    {
        use crate::arch::current::interrupts::{IPI_VECTOR_TLB_SHOOTDOWN, IPI_VECTOR_WAKEUP};
        use crate::arch::current::timer::TIMER_VECTOR;

        /// The spurious-interrupt vector `idt::init` installs.
        const SPURIOUS_VECTOR: u8 = 255;

        let t = table();
        for gsi in 0..DEVICE_VECTOR_COUNT as u32
        {
            let vector = assign(&t, gsi).expect("vector");
            assert!(vector > 31, "GSI {gsi} assigned exception vector {vector}");
            for reserved in [
                TIMER_VECTOR,
                IPI_VECTOR_TLB_SHOOTDOWN,
                IPI_VECTOR_WAKEUP,
                SPURIOUS_VECTOR,
            ]
            {
                assert_ne!(vector, reserved, "GSI {gsi} assigned a reserved vector");
            }
        }
    }

    #[test]
    fn gsi_limit_covers_every_ioapic_and_stops_at_the_id_space()
    {
        let states = [
            IoApicState {
                phys_base: 0xFEC0_0000,
                gsi_base: 0,
                pin_count: 24,
            },
            IoApicState {
                phys_base: 0xFEC0_1000,
                gsi_base: 24,
                pin_count: 32,
            },
        ];
        assert_eq!(gsi_limit_of(&states, 2048), 56);
        assert_eq!(gsi_limit_of(&states, 40), 40);
        assert_eq!(gsi_limit_of(&[], 2048), 0);
    }
}
