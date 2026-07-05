// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/mm/init_reloc.rs

//! `RELATIVE` relocation application for a PIE init image (#39).
//!
//! The bootloader pre-locates init's `.rela.dyn` table
//! (`InitImage.rela_phys` / `rela_size`); Phase 9 draws the load bias and
//! calls [`apply`] before mapping the biased segments. Each record's target
//! is resolved through the original (unbiased) segment table and written
//! through the direct physical map. Anything unresolvable — a
//! non-`RELATIVE` record, a target outside every writable segment — is a
//! fatal boot error: an unrelocated init is corrupt, not degraded.

use boot_protocol::{InitSegment, SegmentFlags};

/// Resolve a relocation target (unbiased link VA) to its physical address
/// through the loaded segments. The whole 8-byte target must lie inside a
/// `ReadWrite` segment — `RELATIVE` targets live in data; a text or rodata
/// target means a malformed or hostile image.
fn resolve_target(segments: &[InitSegment], offset: u64) -> Option<u64>
{
    let end = offset.checked_add(8)?;
    segments
        .iter()
        .filter(|seg| matches!(seg.flags, SegmentFlags::ReadWrite))
        .find(|seg| offset >= seg.virt_addr && end <= seg.virt_addr + seg.size)
        .map(|seg| seg.phys_addr + (offset - seg.virt_addr))
}

/// Apply init's `RELATIVE` relocations: for each record, write
/// `bias + addend` at the resolved physical target via the direct map.
/// Returns the number applied.
///
/// # Errors
///
/// A static description of the failure for the caller's `fatal`.
#[cfg(not(test))]
pub fn apply(
    segments: &[InitSegment],
    bias: u64,
    rela_phys: u64,
    rela_size: u64,
) -> Result<u64, &'static str>
{
    if rela_size == 0
    {
        return Ok(0);
    }
    if rela_phys == 0
        || !rela_size.is_multiple_of(elf::RELA_ENTRY_SIZE as u64)
        || rela_size > elf::MAX_RELA_TABLE_SIZE
    {
        return Err("Phase 9: init .rela.dyn table malformed");
    }
    // cast_possible_truncation: rela_size ≤ MAX_RELA_TABLE_SIZE (4 MiB),
    // checked above; 64-bit targets only.
    #[allow(clippy::cast_possible_truncation)]
    let table_len = rela_size as usize;
    // SAFETY: rela_phys/rela_size describe bootloader-loaded file bytes
    // inside an init segment (resolved by the bootloader through the
    // containing LOAD); the direct map covers all RAM since Phase 3.
    let table = unsafe {
        core::slice::from_raw_parts(
            crate::mm::paging::phys_to_virt(rela_phys) as *const u8,
            table_len,
        )
    };
    let iter = elf::relative_relocs(table, crate::arch::current::EXPECTED_ELF_MACHINE)
        .map_err(|_| "Phase 9: init .rela.dyn table malformed")?;
    let mut applied = 0u64;
    for record in iter
    {
        let rela = record.map_err(|_| "Phase 9: init image carries a non-RELATIVE relocation")?;
        let phys = resolve_target(segments, rela.offset)
            .ok_or("Phase 9: init relocation target outside writable segments")?;
        let value = bias.wrapping_add(rela.addend.cast_unsigned());
        // SAFETY: resolve_target bounds the 8-byte write inside a loaded RW
        // segment; the direct map covers it; single-threaded Phase 9. The
        // target need not be 8-aligned in principle, hence write_unaligned.
        unsafe {
            core::ptr::write_unaligned(crate::mm::paging::phys_to_virt(phys) as *mut u64, value);
        }
        applied += 1;
    }
    Ok(applied)
}

#[cfg(test)]
mod tests
{
    use super::*;

    fn seg(virt: u64, phys: u64, size: u64, flags: SegmentFlags) -> InitSegment
    {
        InitSegment {
            phys_addr: phys,
            virt_addr: virt,
            size,
            flags,
        }
    }

    #[test]
    fn resolves_rw_target_with_in_page_offset()
    {
        let segs = [
            seg(0x1000, 0x10_0100, 0x2000, SegmentFlags::ReadExecute),
            seg(0x3100, 0x20_0100, 0x1000, SegmentFlags::ReadWrite),
        ];
        // Target 0x3208 → 0x108 into the RW segment; the segment's in-page
        // phys offset (0x100) is preserved by the linear displacement.
        assert_eq!(resolve_target(&segs, 0x3208), Some(0x20_0208));
    }

    #[test]
    fn rejects_target_in_non_writable_segment()
    {
        let segs = [
            seg(0x1000, 0x10_0000, 0x2000, SegmentFlags::ReadExecute),
            seg(0x3000, 0x20_0000, 0x1000, SegmentFlags::Read),
        ];
        assert_eq!(resolve_target(&segs, 0x1100), None);
        assert_eq!(resolve_target(&segs, 0x3100), None);
    }

    #[test]
    fn rejects_target_straddling_segment_end()
    {
        let segs = [seg(0x3000, 0x20_0000, 0x1000, SegmentFlags::ReadWrite)];
        // Last fully-contained 8-byte target starts at 0x3FF8.
        assert_eq!(resolve_target(&segs, 0x3FF8), Some(0x20_0FF8));
        assert_eq!(resolve_target(&segs, 0x3FF9), None);
    }

    #[test]
    fn rejects_target_in_gap()
    {
        let segs = [
            seg(0x1000, 0x10_0000, 0x1000, SegmentFlags::ReadWrite),
            seg(0x4000, 0x20_0000, 0x1000, SegmentFlags::ReadWrite),
        ];
        assert_eq!(resolve_target(&segs, 0x2800), None);
    }
}
