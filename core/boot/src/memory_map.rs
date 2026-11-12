// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/boot/src/memory_map.rs

//! Memory map translation helpers.
//!
//! Converts the UEFI memory descriptor list into the boot protocol's
//! `MemoryMapEntry` format and sorts the result by physical base address.

use crate::bprintln;
use crate::uefi::{
    EFI_ACPI_MEMORY_NVS, EFI_ACPI_RECLAIM_MEMORY, EFI_BOOT_SERVICES_CODE, EFI_BOOT_SERVICES_DATA,
    EFI_CONVENTIONAL_MEMORY, EFI_LOADER_CODE, EFI_LOADER_DATA, EFI_MEMORY_MAPPED_IO,
    EFI_MEMORY_MAPPED_IO_PORT_SPACE, EFI_PERSISTENT_MEMORY, EFI_RUNTIME_SERVICES_CODE,
    EFI_RUNTIME_SERVICES_DATA, EfiMemoryDescriptor,
};
use boot_protocol::{MemoryMapEntry, MemoryType, MmioAperture};

// ── Raw descriptor iteration ─────────────────────────────────────────────────

/// Iterator over the descriptors of a raw UEFI memory map, yielding each
/// descriptor by value.
///
/// Invariant (the contract of [`RawDescriptors::new`]): the map's buffer holds
/// valid descriptors covering `map_size` bytes at `descriptor_size` strides for
/// the iterator's lifetime.
#[derive(Clone)]
struct RawDescriptors<'a>
{
    map: &'a crate::uefi::MemoryMapResult,
    offset: usize,
}

impl<'a> RawDescriptors<'a>
{
    /// # Safety
    /// `map.buffer_phys` must hold valid `EfiMemoryDescriptor`s covering
    /// `map.map_size` bytes at `map.descriptor_size` strides, readable for `'a`.
    unsafe fn new(map: &'a crate::uefi::MemoryMapResult) -> Self
    {
        Self { map, offset: 0 }
    }
}

impl Iterator for RawDescriptors<'_>
{
    type Item = EfiMemoryDescriptor;

    fn next(&mut self) -> Option<EfiMemoryDescriptor>
    {
        // A stride below the descriptor would read past it and, at the last
        // stride, past `map_size`. `uefi::check_descriptor_size` rejects one at
        // every read of the firmware's map (the step 6 count query, the step 7
        // fill, and the `ExitBootServices` retry), and the guard reads nothing
        // from a map that carries one, a zero stride included.
        // The firmware reports `map_size`; the buffer bounds it, so a map no
        // reader is sized for is never read past the buffer.
        let end = self.map.map_size.min(self.map.buffer_size);
        let next_offset = self.offset.checked_add(self.map.descriptor_size)?;
        if self.map.descriptor_size < core::mem::size_of::<EfiMemoryDescriptor>()
            || next_offset > end
        {
            return None;
        }
        // cast_possible_truncation: buffer_phys is a UEFI physical address;
        // on all supported UEFI targets (x86_64, riscv64) usize == u64.
        #[allow(clippy::cast_possible_truncation)]
        let ptr =
            (self.map.buffer_phys as usize).checked_add(self.offset)? as *const EfiMemoryDescriptor;
        self.offset = next_offset;
        // SAFETY: the type invariant (`new`'s contract) puts a valid descriptor
        // at every stride below `map_size`; `read_unaligned` makes no alignment
        // demand on a firmware-chosen stride.
        Some(unsafe { core::ptr::read_unaligned(ptr) })
    }
}

// ── Memory map translation ───────────────────────────────────────────────────

/// Translate a UEFI memory map into the boot protocol's `MemoryMapEntry` format.
///
/// Iterates the descriptors of `uefi_map` (none when the descriptor size is
/// below `EFI_MEMORY_DESCRIPTOR`'s, and none past `uefi_map.buffer_size`),
/// converts each UEFI memory type to a [`MemoryType`], and returns the number
/// of entries written. A `max_entries` of at least
/// `uefi::map_buffer_descriptor_reach(uefi_map.buffer_size)` holds every
/// descriptor; the write stops at `max_entries` regardless, and the
/// bootloader's step 7 check makes that bound unreachable
/// (`core/boot/docs/memory-map.md` § Sizing the Entry Array).
///
/// # Safety
/// `out` must point to an allocation of at least `max_entries * size_of::<MemoryMapEntry>()`
/// bytes. `uefi_map.buffer_phys` must be the UEFI raw map buffer from the most
/// recent `GetMemoryMap` call, holding valid descriptors covering
/// `uefi_map.map_size` bytes at `uefi_map.descriptor_size` strides (the contract
/// of `RawDescriptors::new`).
pub unsafe fn translate_memory_map(
    uefi_map: &crate::uefi::MemoryMapResult,
    out: *mut MemoryMapEntry,
    max_entries: usize,
) -> usize
{
    let mut count: usize = 0;

    // SAFETY: this function's `# Safety` contract is `RawDescriptors::new`'s.
    for desc in unsafe { RawDescriptors::new(uefi_map) }
    {
        if count >= max_entries
        {
            break;
        }
        let memory_type = translate_memory_type(desc.memory_type);
        // A page count whose byte size overflows `u64` is no real region: skip it.
        let Some(size_bytes) = desc.number_of_pages.checked_mul(4096)
        else
        {
            continue;
        };

        // SAFETY: count < max_entries; out[count] is within the allocated array.
        unsafe {
            core::ptr::write(
                out.add(count),
                MemoryMapEntry {
                    physical_base: desc.physical_start,
                    size: size_bytes,
                    memory_type,
                },
            );
        }
        // `count` is below `max_entries`, so it is far below `usize::MAX`.
        count = count.saturating_add(1);
    }

    count
}

/// Translate a UEFI `EFI_MEMORY_TYPE` value to the boot protocol's [`MemoryType`].
///
/// The mapping is defined in `core/boot/docs/memory-map.md`
/// § UEFI Memory Type → `MemoryType`.
fn translate_memory_type(uefi_type: u32) -> MemoryType
{
    match uefi_type
    {
        EFI_CONVENTIONAL_MEMORY | EFI_BOOT_SERVICES_CODE | EFI_BOOT_SERVICES_DATA =>
        {
            MemoryType::Usable
        }

        EFI_LOADER_CODE | EFI_LOADER_DATA => MemoryType::Loaded,

        EFI_ACPI_RECLAIM_MEMORY => MemoryType::AcpiReclaimable,

        EFI_PERSISTENT_MEMORY => MemoryType::Persistent,

        // Every other type is Reserved, per core/boot/docs/memory-map.md
        // § UEFI Memory Type → `MemoryType`.
        _ => MemoryType::Reserved,
    }
}

// ── MMIO aperture derivation ─────────────────────────────────────────────────

/// Whether a UEFI memory type is subtracted from every named aperture seed: RAM
/// (`EfiConventionalMemory`, `EfiBootServices*`, `EfiLoader*`,
/// `EfiACPIReclaimMemory`, `EfiPersistentMemory`) and firmware-exclusive state
/// (`EfiRuntimeServices*`, `EfiACPIMemoryNVS`), per
/// `core/boot/docs/firmware-parsing.md` § Firmware exclusion.
/// `EfiReservedMemoryType` is kept in a named seed: firmware reports the GOP
/// framebuffer and some interrupt-controller and ECAM windows as Reserved.
fn excluded_from_apertures(uefi_type: u32) -> bool
{
    matches!(
        uefi_type,
        EFI_CONVENTIONAL_MEMORY
            | EFI_BOOT_SERVICES_CODE
            | EFI_BOOT_SERVICES_DATA
            | EFI_LOADER_CODE
            | EFI_LOADER_DATA
            | EFI_ACPI_RECLAIM_MEMORY
            | EFI_PERSISTENT_MEMORY
            | EFI_RUNTIME_SERVICES_CODE
            | EFI_RUNTIME_SERVICES_DATA
            | EFI_ACPI_MEMORY_NVS
    )
}

/// Emit the parts of `seed` that no `excluded` range covers, in ascending
/// order. `excluded` yields half-open `(start, end)` ranges in any order; they
/// may overlap one another.
///
/// Sweeps a cursor up from the seed's base: the lowest-starting excluded range
/// that overlaps the rest of the seed bounds the next gap, and the cursor moves
/// past that range's end, so every pass either emits the final gap or advances.
fn subtract_excluded<I>(seed: MmioAperture, excluded: &I, mut emit: impl FnMut(MmioAperture))
where
    I: Iterator<Item = (u64, u64)> + Clone,
{
    let end = seed.phys_base.saturating_add(seed.size);
    let mut cur = seed.phys_base;
    while cur < end
    {
        let next = excluded
            .clone()
            .filter(|&(start, stop)| start < end && stop > cur)
            .min_by_key(|&(start, _)| start);
        let Some((start, stop)) = next
        else
        {
            emit(MmioAperture {
                phys_base: cur,
                // `cur` is below `end`, so the difference is exact.
                size: end.saturating_sub(cur),
            });
            return;
        };
        if start > cur
        {
            emit(MmioAperture {
                phys_base: cur,
                // `start` is above `cur`, so the difference is exact.
                size: start.saturating_sub(cur),
            });
        }
        cur = stop;
    }
}

/// Whether a UEFI memory type marks device space: `EfiMemoryMappedIO` or
/// `EfiMemoryMappedIOPortSpace`.
fn is_mmio(uefi_type: u32) -> bool
{
    uefi_type == EFI_MEMORY_MAPPED_IO || uefi_type == EFI_MEMORY_MAPPED_IO_PORT_SPACE
}

/// The half-open physical range `[start, end)` a descriptor covers.
fn descriptor_range(d: &EfiMemoryDescriptor) -> (u64, u64)
{
    (
        d.physical_start,
        d.physical_start
            .saturating_add(d.number_of_pages.saturating_mul(4096)),
    )
}

/// Apertures [`derive_mmio_apertures`] can derive from a map of at most
/// `descriptors` descriptors and `seeds` seeds of both classes, which sizes
/// the aperture array at step 6.
///
/// Every derived aperture is a maximal run of the merged pieces, so it starts
/// where some piece starts: an MMIO descriptor's base, a seed's base, or the
/// end of a descriptor clipped out of a seed. That is at most `descriptors`
/// descriptor bases, `seeds` seed bases, and `descriptors` descriptor ends.
#[must_use]
pub const fn aperture_capacity(descriptors: usize, seeds: usize) -> usize
{
    descriptors.saturating_mul(2).saturating_add(seeds)
}

/// Derive the coarse MMIO aperture array from the raw UEFI memory map and
/// the caller-supplied seeds, following `core/boot/docs/firmware-parsing.md`
/// § `mmio_apertures` construction. Two seed classes are clipped
/// differently before the merge:
///
/// - `seed` holds windows the firmware or the framebuffer names (interrupt
///   controllers, UARTs, ECAM, DTB nodes, the GOP framebuffer), or that the
///   arch defaults fix at a platform-defined register address
///   (`crate::arch::current::default_mmio_apertures`): every
///   RAM-class and firmware-exclusive range of the map
///   ([`excluded_from_apertures`]) is subtracted, and `EfiReservedMemoryType`
///   is kept, since firmware reports such windows as Reserved.
/// - `heuristic` holds layout-heuristic PCI windows no firmware table names:
///   every range the map describes, except MMIO, is subtracted, so only the
///   map's holes and MMIO descriptors remain and firmware-reserved DRAM
///   inside such a window is left out.
///
/// No aperture therefore covers RAM. Each piece is merged into `out` as it
/// arrives ([`insert_merged`]), so `out` holds the sorted, merged apertures at
/// every step and no scratch buffer bounds the input. When more than
/// `out.len()` pieces are disjoint at once, which a later piece bridging
/// them could still undo, `out` is rebuilt by [`sweep_merged`], which takes the
/// pieces in ascending order and so keeps exactly the lowest `out.len()`
/// apertures of the full merge. Returns the number of apertures in `out`; when
/// the full merge holds more than `out.len()`, the highest are dropped with
/// a diagnostic.
///
/// Apertures are coarse by design; see `docs/device-management.md`
/// § Raw Firmware Passthrough for where device-level discovery happens.
///
/// # Safety
/// `uefi_map.buffer_phys` must be the UEFI raw map buffer from the most
/// recent `GetMemoryMap` call, with valid descriptors covering
/// `uefi_map.map_size` bytes. `seed` and `heuristic` are caller-owned slices
/// of already validated apertures.
pub unsafe fn derive_mmio_apertures(
    uefi_map: &crate::uefi::MemoryMapResult,
    seed: &[MmioAperture],
    heuristic: &[MmioAperture],
    out: &mut [MmioAperture],
) -> usize
{
    // SAFETY: the caller's contract is `RawDescriptors::new`'s.
    let descriptors = unsafe { RawDescriptors::new(uefi_map) };

    let mut n: usize = 0;
    let mut full = false;
    for_each_piece(&descriptors, seed, heuristic, &mut |ap| {
        if !full && !insert_merged(out, &mut n, ap)
        {
            full = true;
        }
    });
    if !full
    {
        return n;
    }
    let (n, dropped) = sweep_merged(out, |emit| {
        for_each_piece(&descriptors, seed, heuristic, emit);
    });
    if dropped
    {
        bprintln!(
            "[--------] boot: MMIO apertures: more disjoint than the array holds; the \
             highest dropped"
        );
    }
    n
}

/// Emit every aperture piece `derive_mmio_apertures` merges: the map's MMIO
/// descriptors, then each named seed clipped to the gaps the map's RAM-class
/// and firmware-exclusive ranges leave, then each heuristic window clipped to
/// the map's holes and MMIO descriptors. Empty pieces are emitted too; the
/// mergers skip them.
fn for_each_piece(
    descriptors: &RawDescriptors<'_>,
    seed: &[MmioAperture],
    heuristic: &[MmioAperture],
    emit: &mut dyn FnMut(MmioAperture),
)
{
    for desc in descriptors.clone()
    {
        if is_mmio(desc.memory_type)
        {
            emit(MmioAperture {
                phys_base: desc.physical_start,
                size: desc.number_of_pages.saturating_mul(4096),
            });
        }
    }

    let excluded = descriptors
        .clone()
        .filter(|d| excluded_from_apertures(d.memory_type))
        .map(|d| descriptor_range(&d));
    for s in seed
    {
        if s.size != 0
        {
            subtract_excluded(*s, &excluded, &mut *emit);
        }
    }

    let described = descriptors
        .clone()
        .filter(|d| !is_mmio(d.memory_type))
        .map(|d| descriptor_range(&d));
    for s in heuristic
    {
        if s.size != 0
        {
            subtract_excluded(*s, &described, &mut *emit);
        }
    }
}

/// Merge the pieces `pieces` emits into `out` by taking them in ascending
/// `phys_base` order: each pass over the pieces finds the lowest base above
/// the last one taken and the furthest end among the pieces at that base,
/// which either extends the last aperture (it overlaps or abuts it) or starts
/// the next. Taken in order, a piece can never bridge apertures already
/// written, so the result is the lowest `out.len()` apertures of the full
/// merge. Returns their number and whether a further aperture was dropped.
///
/// One pass per distinct base: quadratic in the piece count, and only run when
/// the incremental merge filled `out`.
fn sweep_merged(
    out: &mut [MmioAperture],
    pieces: impl Fn(&mut dyn FnMut(MmioAperture)),
) -> (usize, bool)
{
    let mut n: usize = 0;
    let mut last_base: Option<u64> = None;
    loop
    {
        let mut next: Option<(u64, u64)> = None;
        pieces(&mut |ap| {
            if ap.size == 0 || last_base.is_some_and(|b| ap.phys_base <= b)
            {
                return;
            }
            let end = ap.phys_base.saturating_add(ap.size);
            next = match next
            {
                Some((b, e)) if b < ap.phys_base || (b == ap.phys_base && e >= end) => Some((b, e)),
                _ => Some((ap.phys_base, end)),
            };
        });
        let Some((base, end)) = next
        else
        {
            return (n, false);
        };
        last_base = Some(base);
        let last = n
            .checked_sub(1)
            .and_then(|k| out.get_mut(k))
            .filter(|l| base <= l.phys_base.saturating_add(l.size));
        if let Some(last) = last
        {
            let top = last.phys_base.saturating_add(last.size);
            if end > top
            {
                // `end` is above `top`, which is at least `last.phys_base`.
                last.size = end.saturating_sub(last.phys_base);
            }
        }
        else if let Some(slot) = out.get_mut(n)
        {
            *slot = MmioAperture {
                phys_base: base,
                // `end` is at least `base`: it is `base` plus a size, saturated.
                size: end.saturating_sub(base),
            };
            // `n` indexed a slot of `out`, so it is far below `usize::MAX`.
            n = n.saturating_add(1);
        }
        else
        {
            // Every piece still to come starts above this one, so none can
            // join the apertures already written.
            return (n, true);
        }
    }
}

/// Merge `ap` into the sorted, disjoint, non-adjacent apertures `set[..*len]`,
/// keeping them so: `ap` joins every entry it overlaps or abuts.
///
/// Returns `false`, changing nothing, when `ap` stays disjoint from every entry
/// and `set` is full. An empty `ap` changes nothing.
fn insert_merged(set: &mut [MmioAperture], len: &mut usize, ap: MmioAperture) -> bool
{
    if ap.size == 0
    {
        return true;
    }
    let mut base = ap.phys_base;
    let mut end = base.saturating_add(ap.size);
    // Entries wholly below `ap`, not even abutting it, stay as they are.
    let live = set.get(..*len).unwrap_or(&[]);
    let i = live
        .iter()
        .take_while(|e| e.phys_base.saturating_add(e.size) < base)
        .count();
    // Entries from `i` that start at or before `ap`'s end merge into it.
    let mut j = i;
    while let Some(e) = live.get(j)
    {
        if e.phys_base > end
        {
            break;
        }
        base = base.min(e.phys_base);
        end = end.max(e.phys_base.saturating_add(e.size));
        // `j` indexed an entry of `live`, so it is far below `usize::MAX`.
        j = j.saturating_add(1);
    }
    if j == i
    {
        if *len == set.len()
        {
            return false;
        }
        // `i` is at most `*len`, which is below `set.len()` here.
        set.copy_within(i..*len, i.saturating_add(1));
        *len = len.saturating_add(1);
    }
    else
    {
        // `j` is above `i` and at most `*len`.
        set.copy_within(j..*len, i.saturating_add(1));
        *len = len.saturating_sub(j.saturating_sub(i).saturating_sub(1));
    }
    // `i` is below `*len` after the shift above, so the slot exists.
    let Some(slot) = set.get_mut(i)
    else
    {
        return false;
    };
    *slot = MmioAperture {
        phys_base: base,
        // `end` is at least `base`: it starts at `base` and only grows.
        size: end.saturating_sub(base),
    };
    true
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests
{
    use core::mem::size_of;

    use super::{
        aperture_capacity, derive_mmio_apertures, insertion_sort_memory_map, subtract_excluded,
        translate_memory_map, translate_memory_type,
    };
    use crate::uefi::{
        EFI_ACPI_MEMORY_NVS, EFI_ACPI_RECLAIM_MEMORY, EFI_BOOT_SERVICES_CODE,
        EFI_BOOT_SERVICES_DATA, EFI_CONVENTIONAL_MEMORY, EFI_LOADER_CODE, EFI_LOADER_DATA,
        EFI_MEMORY_MAPPED_IO, EFI_MEMORY_MAPPED_IO_PORT_SPACE, EFI_PERSISTENT_MEMORY,
        EFI_RUNTIME_SERVICES_CODE, EFI_RUNTIME_SERVICES_DATA, EfiMemoryDescriptor, MemoryMapResult,
    };
    use boot_protocol::{MemoryMapEntry, MemoryType, MmioAperture};

    /// Aperture array size the cap tests derive into.
    const MAX_APERTURES: usize = 256;
    /// Seeds per class the capacity test fills.
    const SEEDS_PER_CLASS: usize = 256;

    // ── translate_memory_type ─────────────────────────────────────────────────

    #[test]
    fn conventional_memory_maps_to_usable()
    {
        assert_eq!(
            translate_memory_type(EFI_CONVENTIONAL_MEMORY),
            MemoryType::Usable
        );
    }

    #[test]
    fn boot_services_code_maps_to_usable()
    {
        assert_eq!(
            translate_memory_type(EFI_BOOT_SERVICES_CODE),
            MemoryType::Usable
        );
    }

    #[test]
    fn boot_services_data_maps_to_usable()
    {
        assert_eq!(
            translate_memory_type(EFI_BOOT_SERVICES_DATA),
            MemoryType::Usable
        );
    }

    #[test]
    fn loader_code_maps_to_loaded()
    {
        assert_eq!(translate_memory_type(EFI_LOADER_CODE), MemoryType::Loaded);
    }

    #[test]
    fn loader_data_maps_to_loaded()
    {
        assert_eq!(translate_memory_type(EFI_LOADER_DATA), MemoryType::Loaded);
    }

    #[test]
    fn acpi_reclaim_maps_to_acpi_reclaimable()
    {
        assert_eq!(
            translate_memory_type(EFI_ACPI_RECLAIM_MEMORY),
            MemoryType::AcpiReclaimable
        );
    }

    #[test]
    fn persistent_memory_maps_to_persistent()
    {
        assert_eq!(
            translate_memory_type(EFI_PERSISTENT_MEMORY),
            MemoryType::Persistent
        );
    }

    #[test]
    fn runtime_services_code_maps_to_reserved()
    {
        assert_eq!(
            translate_memory_type(EFI_RUNTIME_SERVICES_CODE),
            MemoryType::Reserved
        );
    }

    #[test]
    fn runtime_services_data_maps_to_reserved()
    {
        assert_eq!(
            translate_memory_type(EFI_RUNTIME_SERVICES_DATA),
            MemoryType::Reserved
        );
    }

    #[test]
    fn acpi_nvs_maps_to_reserved()
    {
        assert_eq!(
            translate_memory_type(EFI_ACPI_MEMORY_NVS),
            MemoryType::Reserved
        );
    }

    #[test]
    fn mmio_maps_to_reserved()
    {
        assert_eq!(
            translate_memory_type(EFI_MEMORY_MAPPED_IO),
            MemoryType::Reserved
        );
    }

    #[test]
    fn mmio_port_space_maps_to_reserved()
    {
        assert_eq!(
            translate_memory_type(EFI_MEMORY_MAPPED_IO_PORT_SPACE),
            MemoryType::Reserved
        );
    }

    #[test]
    fn unknown_type_maps_to_reserved()
    {
        assert_eq!(translate_memory_type(0xFF), MemoryType::Reserved);
    }

    // ── insertion_sort_memory_map ─────────────────────────────────────────────

    /// Build a `MemoryMapEntry` with the given physical base; other fields are
    /// irrelevant for sort order tests.
    fn make_entry(physical_base: u64) -> MemoryMapEntry
    {
        MemoryMapEntry {
            physical_base,
            size: 0x1000,
            memory_type: MemoryType::Usable,
        }
    }

    #[test]
    fn already_sorted_input_unchanged()
    {
        let mut entries = vec![make_entry(0x1000), make_entry(0x2000), make_entry(0x3000)];
        unsafe { insertion_sort_memory_map(entries.as_mut_ptr(), entries.len()) };
        assert_eq!(entries[0].physical_base, 0x1000);
        assert_eq!(entries[1].physical_base, 0x2000);
        assert_eq!(entries[2].physical_base, 0x3000);
    }

    #[test]
    fn reverse_sorted_input_is_sorted()
    {
        let mut entries = vec![make_entry(0x3000), make_entry(0x2000), make_entry(0x1000)];
        unsafe { insertion_sort_memory_map(entries.as_mut_ptr(), entries.len()) };
        assert_eq!(entries[0].physical_base, 0x1000);
        assert_eq!(entries[1].physical_base, 0x2000);
        assert_eq!(entries[2].physical_base, 0x3000);
    }

    #[test]
    fn empty_input_does_not_panic()
    {
        let mut entries: Vec<MemoryMapEntry> = Vec::new();
        // count=0: the loop body never runs; nothing is read or written.
        unsafe { insertion_sort_memory_map(entries.as_mut_ptr(), 0) };
    }

    #[test]
    fn single_element_input_unchanged()
    {
        let mut entries = vec![make_entry(0xABCD)];
        unsafe { insertion_sort_memory_map(entries.as_mut_ptr(), 1) };
        assert_eq!(entries[0].physical_base, 0xABCD);
    }

    #[test]
    fn duplicate_bases_do_not_panic()
    {
        let mut entries = vec![
            make_entry(0x2000),
            make_entry(0x1000),
            make_entry(0x1000),
            make_entry(0x3000),
        ];
        // Must not crash; exact ordering of duplicates is unspecified.
        unsafe { insertion_sort_memory_map(entries.as_mut_ptr(), entries.len()) };
        // First element must be one of the 0x1000 entries.
        assert_eq!(entries[0].physical_base, 0x1000);
        assert_eq!(entries[3].physical_base, 0x3000);
    }

    // ── translate_memory_map ──────────────────────────────────────────────────

    /// Construct a UEFI memory map buffer from `descs`, run
    /// `translate_memory_map`, and return the translated entries.
    fn run_translate(descs: &[EfiMemoryDescriptor], max_entries: usize) -> Vec<MemoryMapEntry>
    {
        let stride = size_of::<EfiMemoryDescriptor>();
        let uefi_map = MemoryMapResult {
            buffer_phys: descs.as_ptr() as u64,
            buffer_size: descs.len() * stride,
            map_size: descs.len() * stride,
            map_key: 0,
            descriptor_size: stride,
        };
        let dummy = MemoryMapEntry {
            physical_base: 0,
            size: 0,
            memory_type: MemoryType::Reserved,
        };
        let mut out = vec![dummy; max_entries];
        let count = unsafe { translate_memory_map(&uefi_map, out.as_mut_ptr(), max_entries) };
        out.truncate(count);
        out
    }

    #[test]
    fn single_descriptor_translates_correctly()
    {
        let descs = [EfiMemoryDescriptor {
            memory_type: EFI_CONVENTIONAL_MEMORY,
            physical_start: 0x10_0000,
            virtual_start: 0,
            number_of_pages: 8,
            attribute: 0,
        }];
        let entries = run_translate(&descs, 8);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].physical_base, 0x10_0000);
        assert_eq!(entries[0].size, 8 * 4096);
        assert_eq!(entries[0].memory_type, MemoryType::Usable);
    }

    // Defect caught: a page count whose byte size overflows `u64` wraps (or
    // panics) and writes a bogus entry instead of being skipped.
    #[test]
    fn a_descriptor_whose_byte_size_overflows_is_skipped()
    {
        let descs = [
            EfiMemoryDescriptor {
                memory_type: EFI_CONVENTIONAL_MEMORY,
                physical_start: 0,
                virtual_start: 0,
                number_of_pages: u64::MAX,
                attribute: 0,
            },
            EfiMemoryDescriptor {
                memory_type: EFI_CONVENTIONAL_MEMORY,
                physical_start: 0x1000,
                virtual_start: 0,
                number_of_pages: 1,
                attribute: 0,
            },
        ];
        let entries = run_translate(&descs, 4);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].physical_base, 0x1000);
        assert_eq!(entries[0].size, 4096);
    }

    #[test]
    fn multiple_descriptors_translated()
    {
        let descs = [
            EfiMemoryDescriptor {
                memory_type: EFI_CONVENTIONAL_MEMORY,
                physical_start: 0x0000,
                virtual_start: 0,
                number_of_pages: 1,
                attribute: 0,
            },
            EfiMemoryDescriptor {
                memory_type: EFI_LOADER_DATA,
                physical_start: 0x1000,
                virtual_start: 0,
                number_of_pages: 2,
                attribute: 0,
            },
        ];
        let entries = run_translate(&descs, 8);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].memory_type, MemoryType::Usable);
        assert_eq!(entries[1].memory_type, MemoryType::Loaded);
        assert_eq!(entries[1].size, 2 * 4096);
    }

    #[test]
    fn max_entries_cap_limits_output()
    {
        let descs = [
            EfiMemoryDescriptor {
                memory_type: EFI_CONVENTIONAL_MEMORY,
                physical_start: 0x0000,
                virtual_start: 0,
                number_of_pages: 1,
                attribute: 0,
            },
            EfiMemoryDescriptor {
                memory_type: EFI_CONVENTIONAL_MEMORY,
                physical_start: 0x1000,
                virtual_start: 0,
                number_of_pages: 1,
                attribute: 0,
            },
        ];
        // max_entries=1 must cap output even though there are 2 descriptors.
        let entries = run_translate(&descs, 1);
        assert_eq!(entries.len(), 1);
    }

    // Defect caught: a map size the firmware reports past its buffer read
    // beyond the buffer, so translation reads memory that holds no descriptor
    // and the entry array's bound (sized from the buffer) no longer holds.
    #[test]
    fn a_map_size_past_the_buffer_reads_only_the_buffer()
    {
        let d = |physical_start| EfiMemoryDescriptor {
            memory_type: EFI_CONVENTIONAL_MEMORY,
            physical_start,
            virtual_start: 0,
            number_of_pages: 1,
            attribute: 0,
        };
        let descs = [d(0x0000), d(0x1000), d(0x2000)];
        let stride = size_of::<EfiMemoryDescriptor>();
        let uefi_map = MemoryMapResult {
            buffer_phys: descs.as_ptr() as u64,
            buffer_size: 2 * stride,
            map_size: 3 * stride,
            map_key: 0,
            descriptor_size: stride,
        };
        let dummy = MemoryMapEntry {
            physical_base: 0,
            size: 0,
            memory_type: MemoryType::Reserved,
        };
        let mut out = vec![dummy; 3];
        let count = unsafe { translate_memory_map(&uefi_map, out.as_mut_ptr(), 3) };
        assert_eq!(count, 2);
        assert_eq!(out[1].physical_base, 0x1000);
    }

    // Defect caught: a translation loop that never advances on a zero
    // descriptor stride and hangs the boot, or that reads a descriptor past
    // the map at a stride shorter than the descriptor.
    #[test]
    fn a_descriptor_size_below_the_descriptor_translates_nothing()
    {
        let descs = [EfiMemoryDescriptor {
            memory_type: EFI_CONVENTIONAL_MEMORY,
            physical_start: 0,
            virtual_start: 0,
            number_of_pages: 1,
            attribute: 0,
        }];
        let uefi_map = MemoryMapResult {
            buffer_phys: descs.as_ptr() as u64,
            buffer_size: size_of::<EfiMemoryDescriptor>(),
            map_size: size_of::<EfiMemoryDescriptor>(),
            map_key: 0,
            descriptor_size: 0,
        };
        let dummy = MemoryMapEntry {
            physical_base: 0,
            size: 0,
            memory_type: MemoryType::Reserved,
        };
        let mut out = vec![dummy; 1];
        for stride in [0, 8, size_of::<EfiMemoryDescriptor>() - 1]
        {
            let map = MemoryMapResult {
                descriptor_size: stride,
                ..uefi_map
            };
            let count = unsafe { translate_memory_map(&map, out.as_mut_ptr(), 1) };
            assert_eq!(count, 0, "stride {stride}");
        }
    }

    #[test]
    fn zero_length_map_returns_zero_entries()
    {
        let descs: &[EfiMemoryDescriptor] = &[];
        let entries = run_translate(descs, 8);
        assert_eq!(entries.len(), 0);
    }

    #[test]
    fn padded_descriptor_size_handled_correctly()
    {
        // Simulate UEFI returning descriptors with 8 bytes of trailing padding
        // (descriptor_size > size_of::<EfiMemoryDescriptor>()).
        let stride = size_of::<EfiMemoryDescriptor>() + 8;
        // Allocate one stride-sized slot, zeroed, then write the descriptor at
        // the start of that slot. The trailing 8 bytes remain zero (padding).
        // `u64` storage gives the buffer the descriptor's 8-byte alignment.
        let mut buf = vec![0u64; stride / 8];
        let desc = EfiMemoryDescriptor {
            memory_type: EFI_PERSISTENT_MEMORY,
            physical_start: 0x4000,
            virtual_start: 0,
            number_of_pages: 4,
            attribute: 0,
        };
        // SAFETY: buf holds stride >= size_of::<EfiMemoryDescriptor>() bytes and,
        // as `u64` storage, is 8-byte aligned, which EfiMemoryDescriptor needs.
        unsafe { core::ptr::write(buf.as_mut_ptr().cast::<EfiMemoryDescriptor>(), desc) };
        let uefi_map = MemoryMapResult {
            buffer_phys: buf.as_ptr() as u64,
            buffer_size: stride,
            map_size: stride,
            map_key: 0,
            descriptor_size: stride,
        };
        let dummy = MemoryMapEntry {
            physical_base: 0,
            size: 0,
            memory_type: MemoryType::Reserved,
        };
        let mut out = vec![dummy; 4];
        let count = unsafe { translate_memory_map(&uefi_map, out.as_mut_ptr(), 4) };
        assert_eq!(count, 1);
        assert_eq!(out[0].memory_type, MemoryType::Persistent);
        assert_eq!(out[0].physical_base, 0x4000);
        assert_eq!(out[0].size, 4 * 4096);
    }

    // ── derive_mmio_apertures ─────────────────────────────────────────────────

    fn mmio_desc(physical_start: u64, number_of_pages: u64) -> EfiMemoryDescriptor
    {
        EfiMemoryDescriptor {
            memory_type: EFI_MEMORY_MAPPED_IO,
            physical_start,
            virtual_start: 0,
            number_of_pages,
            attribute: 0,
        }
    }

    /// Run `derive_mmio_apertures` over `descs` and `seed`; return the output.
    fn run_derive(descs: &[EfiMemoryDescriptor], seed: &[MmioAperture]) -> Vec<MmioAperture>
    {
        run_derive_with(descs, size_of::<EfiMemoryDescriptor>(), seed, &[])
    }

    /// Run `derive_mmio_apertures` over `descs` at `stride`, the named
    /// `seed`, and the `heuristic` windows; return the output.
    fn run_derive_with(
        descs: &[EfiMemoryDescriptor],
        stride: usize,
        seed: &[MmioAperture],
        heuristic: &[MmioAperture],
    ) -> Vec<MmioAperture>
    {
        let uefi_map = MemoryMapResult {
            buffer_phys: descs.as_ptr() as u64,
            buffer_size: descs.len() * size_of::<EfiMemoryDescriptor>(),
            map_size: descs.len() * size_of::<EfiMemoryDescriptor>(),
            map_key: 0,
            descriptor_size: stride,
        };
        let mut out = vec![
            MmioAperture {
                phys_base: 0,
                size: 0,
            };
            MAX_APERTURES
        ];
        // SAFETY: `descs` is a live, aligned descriptor array covering
        // `map_size`; a zero stride reads nothing.
        let n = unsafe { derive_mmio_apertures(&uefi_map, seed, heuristic, &mut out) };
        out[..n].to_vec()
    }

    #[test]
    fn overlapping_and_adjacent_apertures_merge()
    {
        let descs = [mmio_desc(0x1000_0000, 1), mmio_desc(0x1000_1000, 1)];
        let seed = [MmioAperture {
            phys_base: 0x1000_0800,
            size: 0x1000,
        }];
        let out = run_derive(&descs, &seed);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].phys_base, 0x1000_0000);
        assert_eq!(out[0].size, 0x2000);
    }

    // Defect caught: a bounded scratch buffer that drops pieces before the
    // merge, losing apertures a fragmented map describes in many pieces.
    #[test]
    fn many_abutting_pieces_merge_into_one_aperture_without_a_drop()
    {
        // Far more pieces than MAX_APERTURES, out of order, all abutting.
        let descs: Vec<_> = (0..(MAX_APERTURES as u64 * 8))
            .rev()
            .map(|i| mmio_desc(0x4000_0000 + i * 0x1000, 1))
            .collect();
        let out = run_derive(&descs, &[]);
        assert_eq!(
            pairs(&out),
            vec![(0x4000_0000, MAX_APERTURES as u64 * 8 * 0x1000)]
        );
    }

    // Defect caught: an insertion that merges only its first neighbour,
    // leaving overlapping apertures when one piece bridges several.
    #[test]
    fn a_piece_bridging_several_apertures_merges_them_all()
    {
        let descs = [
            mmio_desc(0x1000_0000, 1),
            mmio_desc(0x1000_2000, 1),
            mmio_desc(0x1000_4000, 1),
            mmio_desc(0x2000_0000, 1),
        ];
        let seed = [MmioAperture {
            phys_base: 0x1000_0800,
            size: 0x4000,
        }];
        let out = run_derive(&descs, &seed);
        assert_eq!(
            pairs(&out),
            vec![(0x1000_0000, 0x5000), (0x2000_0000, 0x1000)]
        );
    }

    // Defect caught: a full list that drops a piece arriving above every
    // aperture, or keeps it past the cap.
    #[test]
    fn surplus_arriving_highest_last_is_the_one_dropped()
    {
        let descs: Vec<_> = (0..=MAX_APERTURES as u64)
            .map(|i| mmio_desc(0x1000_0000 + i * 0x10_0000, 1))
            .collect();
        let out = run_derive(&descs, &[]);
        assert_eq!(out.len(), MAX_APERTURES);
        assert_eq!(out[0].phys_base, 0x1000_0000);
        assert_eq!(
            out[MAX_APERTURES - 1].phys_base,
            0x1000_0000 + (MAX_APERTURES as u64 - 1) * 0x10_0000
        );
    }

    // Defect caught: a cap applied while pieces arrive, which loses an
    // aperture once a later piece bridges several and the full merge fits.
    #[test]
    fn a_full_list_a_later_seed_bridges_keeps_every_aperture()
    {
        // MAX_APERTURES disjoint pieces 2 MiB apart, plus one between the
        // first two: the list overflows while pieces arrive.
        let mut descs: Vec<_> = (0..MAX_APERTURES as u64)
            .map(|i| mmio_desc(0x1000_0000 + i * 0x20_0000, 1))
            .collect();
        descs.push(mmio_desc(0x1010_0000, 1));
        // A seed over the first eleven pieces and the extra one merges twelve
        // pieces into one aperture.
        let seed = [MmioAperture {
            phys_base: 0x1000_0000,
            size: 10 * 0x20_0000 + 0x1000,
        }];
        let out = run_derive(&descs, &seed);
        assert_eq!(out.len(), MAX_APERTURES - 10);
        assert_eq!(out[0].phys_base, 0x1000_0000);
        assert_eq!(out[0].size, 10 * 0x20_0000 + 0x1000);
        assert_eq!(
            out[MAX_APERTURES - 11].phys_base,
            0x1000_0000 + (MAX_APERTURES as u64 - 1) * 0x20_0000
        );
    }

    // Defect caught: a sweep that lets a later, shorter piece at the same base
    // replace a longer one, or that does not extend the last aperture with a
    // piece at a higher base reaching past its end.
    #[test]
    fn the_sweep_keeps_the_longest_piece_at_a_base_and_extends_across_pieces()
    {
        // Overflow the list so the sweep runs: MAX_APERTURES disjoint pieces
        // 2 MiB apart, plus one more above them.
        let mut descs: Vec<_> = (0..=MAX_APERTURES as u64)
            .map(|i| mmio_desc(0x1000_0000 + i * 0x20_0000, 1))
            .collect();
        // At the first piece's base: a longer piece listed before the
        // one-page one, and a piece at a higher base reaching past it.
        descs.insert(0, mmio_desc(0x1000_0000, 4));
        descs.push(mmio_desc(0x1000_2000, 4));
        let out = run_derive(&descs, &[]);
        assert_eq!(out.len(), MAX_APERTURES);
        assert_eq!(pairs(&out[..1]), vec![(0x1000_0000, 0x6000)]);
    }

    // Defect caught: an aperture array sized below what the map and full seed
    // buffers can yield, so apertures are dropped on a map the array was sized
    // for.
    #[test]
    fn the_aperture_capacity_holds_the_worst_case_derivation()
    {
        // Disjoint MMIO descriptors, each one aperture, and full seed buffers of
        // disjoint three-page windows, each cut in two by a one-page RAM
        // descriptor in its middle, so half the seed-derived apertures start at
        // the end of a clipped descriptor.
        let mut descs = Vec::new();
        for i in 0..40u64
        {
            descs.push(mmio_desc(0x1_0000_0000 + i * 0x20_0000, 1));
        }
        let mut seeds = Vec::new();
        let mut heuristic = Vec::new();
        for i in 0..SEEDS_PER_CLASS as u64
        {
            let named = 0x2_0000_0000 + i * 0x10_0000;
            seeds.push(ap(named, 0x3000));
            descs.push(desc(EFI_CONVENTIONAL_MEMORY, named + 0x1000, 1));
            let window = 0x3_0000_0000 + i * 0x10_0000;
            heuristic.push(ap(window, 0x3000));
            descs.push(desc(EFI_CONVENTIONAL_MEMORY, window + 0x1000, 1));
        }
        let capacity = aperture_capacity(descs.len(), 2 * SEEDS_PER_CLASS);
        let uefi_map = MemoryMapResult {
            buffer_phys: descs.as_ptr() as u64,
            buffer_size: descs.len() * size_of::<EfiMemoryDescriptor>(),
            map_size: descs.len() * size_of::<EfiMemoryDescriptor>(),
            map_key: 0,
            descriptor_size: size_of::<EfiMemoryDescriptor>(),
        };
        let mut out = vec![ap(0, 0); capacity];
        // SAFETY: `descs` is a live, aligned descriptor array covering `map_size`.
        let n = unsafe { derive_mmio_apertures(&uefi_map, &seeds, &heuristic, &mut out) };
        assert_eq!(n, 40 + 4 * SEEDS_PER_CLASS);
        assert!(n <= capacity);
        let derived = pairs(&out[..n]);
        assert!(derived.contains(&(0x2_0000_0000, 0x1000)));
        assert!(derived.contains(&(0x2_0000_2000, 0x1000)));
        assert!(derived.contains(&(0x3_0000_2000, 0x1000)));
    }

    #[test]
    fn zero_size_seed_is_ignored()
    {
        let seed = [MmioAperture {
            phys_base: 0x2000_0000,
            size: 0,
        }];
        assert!(run_derive(&[], &seed).is_empty());
    }

    #[test]
    fn exactly_max_apertures_disjoint_are_all_kept()
    {
        let descs: Vec<_> = (0..MAX_APERTURES as u64)
            .map(|i| mmio_desc(0x1000_0000 + i * 0x10_0000, 1))
            .collect();
        let out = run_derive(&descs, &[]);
        assert_eq!(out.len(), MAX_APERTURES);
    }

    #[test]
    fn surplus_over_max_apertures_keeps_the_lowest_bases()
    {
        // Listed highest first, so the cap must apply after the sort.
        let descs: Vec<_> = (0..=MAX_APERTURES as u64)
            .rev()
            .map(|i| mmio_desc(0x1000_0000 + i * 0x10_0000, 1))
            .collect();
        let out = run_derive(&descs, &[]);
        assert_eq!(out.len(), MAX_APERTURES);
        assert_eq!(out[0].phys_base, 0x1000_0000);
        assert_eq!(
            out[MAX_APERTURES - 1].phys_base,
            0x1000_0000 + (MAX_APERTURES as u64 - 1) * 0x10_0000
        );
    }

    // ── RAM subtraction ───────────────────────────────────────────────────────

    fn desc(memory_type: u32, physical_start: u64, number_of_pages: u64) -> EfiMemoryDescriptor
    {
        EfiMemoryDescriptor {
            memory_type,
            physical_start,
            virtual_start: 0,
            number_of_pages,
            attribute: 0,
        }
    }

    fn ap(phys_base: u64, size: u64) -> MmioAperture
    {
        MmioAperture { phys_base, size }
    }

    fn pairs(out: &[MmioAperture]) -> Vec<(u64, u64)>
    {
        out.iter().map(|a| (a.phys_base, a.size)).collect()
    }

    #[test]
    fn seed_overlapping_ram_is_trimmed_to_its_gaps()
    {
        // RAM [0x1000_2000, 0x1000_4000) inside the seed [0x1000_0000, 0x1000_6000).
        let descs = [desc(EFI_CONVENTIONAL_MEMORY, 0x1000_2000, 2)];
        let out = run_derive(&descs, &[ap(0x1000_0000, 0x6000)]);
        assert_eq!(
            pairs(&out),
            vec![(0x1000_0000, 0x2000), (0x1000_4000, 0x2000)]
        );
    }

    #[test]
    fn seed_wholly_inside_ram_vanishes()
    {
        let descs = [desc(EFI_BOOT_SERVICES_DATA, 0x4000_0000, 0x100)];
        assert!(run_derive(&descs, &[ap(0x4001_0000, 0x1000)]).is_empty());
    }

    #[test]
    fn reserved_and_mmio_ranges_do_not_clip_a_seed()
    {
        // The GOP framebuffer and interrupt-controller windows are often
        // Reserved; an MMIO descriptor merges with the seed instead.
        let descs = [
            desc(0 /* EfiReservedMemoryType */, 0x8000_0000, 0x10),
            desc(EFI_MEMORY_MAPPED_IO, 0x8001_0000, 0x10),
        ];
        let out = run_derive(&descs, &[ap(0x8000_0000, 0x2_0000)]);
        assert_eq!(pairs(&out), vec![(0x8000_0000, 0x2_0000)]);
    }

    #[test]
    fn every_ram_class_and_firmware_exclusive_type_clips_a_seed()
    {
        let excluded = [
            EFI_CONVENTIONAL_MEMORY,
            EFI_BOOT_SERVICES_CODE,
            EFI_BOOT_SERVICES_DATA,
            EFI_LOADER_CODE,
            EFI_LOADER_DATA,
            EFI_ACPI_RECLAIM_MEMORY,
            EFI_PERSISTENT_MEMORY,
            EFI_RUNTIME_SERVICES_CODE,
            EFI_RUNTIME_SERVICES_DATA,
            EFI_ACPI_MEMORY_NVS,
        ];
        for ty in excluded
        {
            let descs = [desc(ty, 0x2000_0000, 1)];
            let out = run_derive(&descs, &[ap(0x2000_0000, 0x2000)]);
            assert_eq!(pairs(&out), vec![(0x2000_1000, 0x1000)], "type {ty}");
        }
    }

    #[test]
    fn q35_lowmem_ram_clips_the_32bit_pci_window()
    {
        // q35 with 2.5 GiB: lowmem RAM [0, 0xA000_0000); the MCFG heuristic's
        // 32-bit window is [0x8000_0000, 0xB000_0000).
        let descs = [desc(EFI_CONVENTIONAL_MEMORY, 0, 0xA000_0000 / 4096)];
        let out = run_derive_with(
            &descs,
            size_of::<EfiMemoryDescriptor>(),
            &[],
            &[ap(0x8000_0000, 0x3000_0000)],
        );
        assert_eq!(pairs(&out), vec![(0xA000_0000, 0x1000_0000)]);
    }

    #[test]
    fn ram_above_4gib_clips_the_64bit_pci_window()
    {
        // High RAM [4 GiB, 5 GiB); the q35 64-bit window is [4 GiB, 1 << 46).
        let descs = [desc(EFI_CONVENTIONAL_MEMORY, 1 << 32, (1 << 30) / 4096)];
        let window = ap(1 << 32, (1u64 << 46) - (1 << 32));
        let out = run_derive_with(&descs, size_of::<EfiMemoryDescriptor>(), &[], &[window]);
        assert_eq!(
            pairs(&out),
            vec![(0x1_4000_0000, (1u64 << 46) - 0x1_4000_0000)]
        );
    }

    #[test]
    fn unsorted_overlapping_excluded_ranges_leave_only_the_true_gaps()
    {
        let excluded = [(0x5000, 0x8000), (0x1000, 0x3000), (0x2000, 0x4000)];
        let mut got = Vec::new();
        subtract_excluded(ap(0, 0xA000), &excluded.iter().copied(), |a| got.push(a));
        assert_eq!(
            pairs(&got),
            vec![(0, 0x1000), (0x4000, 0x1000), (0x8000, 0x2000)]
        );
    }

    #[test]
    fn reserved_memory_clips_a_heuristic_window_but_not_a_named_seed()
    {
        // Firmware-reserved DRAM (TSEG-like) inside the q35 32-bit window, and
        // an MMIO descriptor beside it.
        let descs = [
            desc(0 /* EfiReservedMemoryType */, 0x9000_0000, 0x10),
            desc(EFI_MEMORY_MAPPED_IO, 0x9001_0000, 0x10),
        ];
        let window = ap(0x9000_0000, 0x10_0000);
        let stride = size_of::<EfiMemoryDescriptor>();

        let heuristic = run_derive_with(&descs, stride, &[], &[window]);
        assert_eq!(pairs(&heuristic), vec![(0x9001_0000, 0xF_0000)]);

        let named = run_derive_with(&descs, stride, &[window], &[]);
        assert_eq!(pairs(&named), vec![(0x9000_0000, 0x10_0000)]);
    }

    #[test]
    fn zero_descriptor_stride_reads_no_descriptor_and_keeps_the_seeds()
    {
        // A RAM descriptor that would clip the seed, behind a zero stride.
        let descs = [desc(EFI_CONVENTIONAL_MEMORY, 0x2000_0000, 1)];
        let out = run_derive_with(&descs, 0, &[ap(0x2000_0000, 0x2000)], &[]);
        assert_eq!(pairs(&out), vec![(0x2000_0000, 0x2000)]);
    }
}

/// Sort `MemoryMapEntry` elements in `[0..count)` by `physical_base` ascending.
///
/// Uses an in-place insertion sort; see `core/boot/docs/memory-map.md`
/// § Sort Algorithm for why the algorithm class is acceptable.
///
/// # Safety
/// `entries` must point to an allocation of at least `count` valid, initialised
/// `MemoryMapEntry` elements.
pub unsafe fn insertion_sort_memory_map(entries: *mut MemoryMapEntry, count: usize)
{
    for i in 1..count
    {
        // SAFETY: i < count; entries[i] is a valid initialised MemoryMapEntry.
        let key = unsafe { core::ptr::read(entries.add(i)) };
        let mut j = i;

        while let Some(prev) = j.checked_sub(1)
        {
            // SAFETY: prev < i < count; entries[prev] is initialised.
            let prev_base = unsafe { (*entries.add(prev)).physical_base };
            if prev_base <= key.physical_base
            {
                break;
            }
            // SAFETY: j and j-1 are both < count and within the allocation.
            unsafe { core::ptr::copy_nonoverlapping(entries.add(prev), entries.add(j), 1) };
            j = prev;
        }

        // SAFETY: j < count; entries[j] is within the allocation.
        unsafe { core::ptr::write(entries.add(j), key) };
    }
}
