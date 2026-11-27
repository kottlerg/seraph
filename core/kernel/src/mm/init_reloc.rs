// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/mm/init_reloc.rs

//! PIE init image fix-ups (#39): `RELATIVE` relocation application and
//! `PT_GNU_RELRO` sealing.
//!
//! The bootloader pre-locates init's `.rela.dyn` table
//! (`InitImage.rela_phys` / `rela_size`); Phase 9 draws the load bias and
//! calls [`apply`] before mapping the biased segments. Each record's target
//! is resolved through the original (unbiased) segment table and written
//! through the direct physical map; [`apply_relro`] then flips the
//! relro-covered writable segments to read-only. The relocation and RELRO
//! rules are defined in docs/userspace-memory-model.md § Image Placement,
//! and the Phase 9 sequence, including the fatal handling of an
//! unresolvable record, in core/kernel/docs/initialization.md § Phase 9:
//! Init Creation and Scheduler Entry.

use boot_protocol::{INIT_MAX_SEGMENTS, InitSegment, SegmentFlags};

/// Apply `PT_GNU_RELRO` to the (already biased) segment table: writable
/// segments fully covered by the biased, page-rounded RELRO range become
/// read-only; a segment the range ends inside is split at the range end
/// into a read-only head and a writable tail. RELRO is a prefix of the
/// writable image region by link order, so a range starting mid-segment is
/// skipped (no enforcement) rather than misapplied.
///
/// # Errors
///
/// A static description when the biased RELRO range, a segment end, or a
/// split tail's physical address overflows `u64`, or when `count` or a split
/// would exceed `INIT_MAX_SEGMENTS`.
pub fn apply_relro(
    segments: &mut [InitSegment; INIT_MAX_SEGMENTS],
    count: &mut u32,
    bias: u64,
    relro_vaddr: u64,
    relro_size: u64,
) -> Result<(), &'static str>
{
    if relro_size == 0
    {
        return Ok(());
    }
    let overflow = "Phase 9: RELRO range overflow";
    let ro_start = relro_vaddr.checked_add(bias).ok_or(overflow)? & !0xFFF;
    let ro_end = relro_vaddr
        .checked_add(bias)
        .and_then(|v| v.checked_add(relro_size))
        .and_then(|v| v.checked_add(0xFFF))
        .ok_or(overflow)?
        & !0xFFF;
    // The live segments, and the free slots a split's tail takes in order.
    let (live, free) = segments
        .split_at_mut_checked(*count as usize)
        .ok_or("Phase 9: init segment count exceeds INIT_MAX_SEGMENTS")?;
    let mut free = free.iter_mut();
    for slot in live
    {
        let seg = *slot;
        if !matches!(seg.flags, SegmentFlags::ReadWrite)
        {
            continue;
        }
        let seg_end = seg.virt_addr.checked_add(seg.size).ok_or(overflow)?;
        if ro_start > seg.virt_addr || seg.virt_addr >= ro_end
        {
            continue;
        }
        if seg_end <= ro_end
        {
            slot.flags = SegmentFlags::Read;
        }
        else
        {
            // The segment table is the boot protocol's fixed
            // `[InitSegment; INIT_MAX_SEGMENTS]`, so a split past it is a clean error.
            let Some(tail) = free.next()
            else
            {
                return Err("Phase 9: RELRO split exceeds INIT_MAX_SEGMENTS");
            };
            // Split at the page-aligned range end: in-page offsets stay
            // preserved because head_size shifts phys and virt equally.
            // seg.virt_addr < ro_end < seg_end held above, so neither
            // difference wraps.
            let head_size = ro_end.wrapping_sub(seg.virt_addr);
            *tail = InitSegment {
                phys_addr: seg.phys_addr.checked_add(head_size).ok_or(overflow)?,
                virt_addr: ro_end,
                size: seg.size.wrapping_sub(head_size),
                flags: SegmentFlags::ReadWrite,
            };
            slot.size = head_size;
            slot.flags = SegmentFlags::Read;
            // A tail took a free slot, so the count stays within
            // INIT_MAX_SEGMENTS.
            *count = count.saturating_add(1);
        }
    }
    Ok(())
}

/// Resolve a relocation target (unbiased link VA) to its physical address
/// through the loaded segments. The whole 8-byte target must lie inside a
/// `ReadWrite` segment (rule in docs/userspace-memory-model.md § Image
/// Placement).
fn resolve_target(segments: &[InitSegment], offset: u64) -> Option<u64>
{
    let end = offset.checked_add(8)?;
    segments
        .iter()
        .filter(|seg| matches!(seg.flags, SegmentFlags::ReadWrite))
        .find(|seg| {
            offset >= seg.virt_addr
                && seg
                    .virt_addr
                    .checked_add(seg.size)
                    .is_some_and(|seg_end| end <= seg_end)
        })
        .and_then(|seg| {
            offset
                .checked_sub(seg.virt_addr)
                .and_then(|d| seg.phys_addr.checked_add(d))
        })
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
    #[expect(
        clippy::cast_possible_truncation,
        reason = "rela_size ≤ MAX_RELA_TABLE_SIZE (4 MiB), checked above; 64-bit targets only"
    )]
    let table_len = rela_size as usize;
    // SAFETY: rela_phys/rela_size describe bootloader-loaded file bytes
    // inside an init segment (resolved by the bootloader through the
    // containing LOAD); the direct map covers all RAM since Phase 3 but the
    // kernel-stack guard pages (`mm::stack_guard`), none of them in a
    // segment.
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
        // segment; the direct map covers it; the boot thread is the only writer of
        // init's frames (APs idle from Phase 8 and never touch Phase-9 state, per
        // core/kernel/docs/initialization.md § Phase 8). The target need not be
        // 8-aligned in principle, hence write_unaligned.
        unsafe {
            core::ptr::write_unaligned(crate::mm::paging::phys_to_virt(phys) as *mut u64, value);
        }
        // At most the table's records, far below the saturation point.
        applied = applied.saturating_add(1);
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

    // ── apply_relro ──────────────────────────────────────────────────────────

    fn seg_table(entries: &[InitSegment]) -> ([InitSegment; INIT_MAX_SEGMENTS], u32)
    {
        let mut table = [seg(0, 0, 0, SegmentFlags::Read); INIT_MAX_SEGMENTS];
        table[..entries.len()].copy_from_slice(entries);
        #[expect(
            clippy::cast_possible_truncation,
            reason = "entries.len() ≤ INIT_MAX_SEGMENTS = 8 in every test below"
        )]
        let count = entries.len() as u32;
        (table, count)
    }

    #[test]
    fn relro_flips_fully_covered_segment()
    {
        // Biased layout mirroring lld output: RX, RW-relro (page-aligned
        // end), RW. Bias 0x1000; relro link span [0x20c8, 0x3000).
        let (mut segs, mut count) = seg_table(&[
            seg(0x1000, 0x10_0000, 0x1000, SegmentFlags::ReadExecute),
            seg(0x30c8, 0x20_00c8, 0xf38, SegmentFlags::ReadWrite),
            seg(0x4c20, 0x30_0c20, 0x9c0, SegmentFlags::ReadWrite),
        ]);
        apply_relro(&mut segs, &mut count, 0x1000, 0x20c8, 0xf38).unwrap();
        assert_eq!(count, 3);
        assert!(matches!(segs[1].flags, SegmentFlags::Read));
        assert!(matches!(segs[2].flags, SegmentFlags::ReadWrite));
        assert!(matches!(segs[0].flags, SegmentFlags::ReadExecute));
    }

    #[test]
    fn relro_splits_segment_at_range_end()
    {
        // One RW segment [0x3000, 0x6000); relro covers its first page only.
        let (mut segs, mut count) =
            seg_table(&[seg(0x3000, 0x20_0000, 0x3000, SegmentFlags::ReadWrite)]);
        apply_relro(&mut segs, &mut count, 0, 0x3000, 0x800).unwrap();
        assert_eq!(count, 2);
        assert!(matches!(segs[0].flags, SegmentFlags::Read));
        assert_eq!(segs[0].virt_addr, 0x3000);
        assert_eq!(segs[0].size, 0x1000);
        assert!(matches!(segs[1].flags, SegmentFlags::ReadWrite));
        assert_eq!(segs[1].virt_addr, 0x4000);
        assert_eq!(segs[1].phys_addr, 0x20_1000);
        assert_eq!(segs[1].size, 0x2000);
    }

    #[test]
    fn relro_absent_and_non_prefix_are_no_ops()
    {
        let (mut segs, mut count) =
            seg_table(&[seg(0x3000, 0x20_0000, 0x2000, SegmentFlags::ReadWrite)]);
        apply_relro(&mut segs, &mut count, 0, 0, 0).unwrap();
        assert!(matches!(segs[0].flags, SegmentFlags::ReadWrite));
        // Range starting mid-segment (not a prefix) is skipped.
        apply_relro(&mut segs, &mut count, 0, 0x4000, 0x1000).unwrap();
        assert!(matches!(segs[0].flags, SegmentFlags::ReadWrite));
        assert_eq!(count, 1);
    }

    // Defect caught: a split written past the table, or a count past the
    // table read as segments, instead of a clean error.
    #[test]
    fn relro_refuses_a_full_table_and_a_count_past_it()
    {
        let full = [seg(0x3000, 0x20_0000, 0x3000, SegmentFlags::ReadWrite); INIT_MAX_SEGMENTS];
        let (mut segs, mut count) = seg_table(&full);
        assert!(apply_relro(&mut segs, &mut count, 0, 0x3000, 0x800).is_err());
        let (mut segs, _) = seg_table(&full);
        let mut past = u32::try_from(INIT_MAX_SEGMENTS).unwrap() + 1;
        assert!(apply_relro(&mut segs, &mut past, 0, 0x3000, 0x800).is_err());
    }

    // Defect caught: a target whose segment's physical end passes the address
    // space, resolved to a wrapped physical address.
    #[test]
    fn rejects_target_whose_physical_address_wraps()
    {
        let segs = [seg(
            0x2000,
            u64::MAX - 0xFFF,
            0x2000,
            SegmentFlags::ReadWrite,
        )];
        assert_eq!(resolve_target(&segs, 0x3000), None);
    }
}

/// Bounded proofs of the relocation target and RELRO arithmetic
/// (docs/testing.md § Bounded verification). Every segment's addresses,
/// size and flags, the target, the bias and the RELRO range are symbolic over
/// every value.
#[cfg(kani)]
mod proofs
{
    use boot_protocol::{INIT_MAX_SEGMENTS, InitSegment, SegmentFlags};

    use super::{apply_relro, resolve_target};

    /// Segments the relocation harness gives `resolve_target`.
    const LIVE: usize = 3;

    /// Any segment.
    fn any_segment() -> InitSegment
    {
        let flags = match kani::any::<u8>()
        {
            0 => SegmentFlags::Read,
            1 => SegmentFlags::ReadWrite,
            _ => SegmentFlags::ReadExecute,
        };
        InitSegment {
            phys_addr: kani::any(),
            virt_addr: kani::any(),
            size: kani::any(),
            flags,
        }
    }

    /// Whether `seg` maps the byte at `virt`, in exact arithmetic.
    fn maps(seg: &InitSegment, virt: u64) -> bool
    {
        seg.virt_addr <= virt && u128::from(virt) < u128::from(seg.virt_addr) + u128::from(seg.size)
    }

    /// Every relocation `apply` writes goes to the physical address
    /// `resolve_target` returns, so its whole 8-byte write lands inside one
    /// `ReadWrite` segment, at the target's offset within it, for any segment
    /// table and any target (the class of #282). The table's walk judges each
    /// segment alone, so `LIVE` segments of any values cover every step: one
    /// not writable, one that does not hold the target, and one that does, in
    /// any order. The walks are the
    /// code's and the harness's, each over `LIVE` segments, so an unwind
    /// bound of `LIVE + 1` covers them.
    #[kani::proof]
    #[kani::unwind(4)]
    fn a_resolved_relocation_lands_inside_one_writable_segment()
    {
        let segments = [any_segment(), any_segment(), any_segment()];
        let offset: u64 = kani::any();
        let Some(phys) = resolve_target(&segments, offset)
        else
        {
            return;
        };
        let lands = |seg: &InitSegment| {
            let last = u128::from(offset) + 7;
            matches!(seg.flags, SegmentFlags::ReadWrite)
                && maps(seg, offset)
                && last < u128::from(seg.virt_addr) + u128::from(seg.size)
                && u128::from(phys)
                    == u128::from(seg.phys_addr) + u128::from(offset - seg.virt_addr)
        };
        assert!(segments.iter().any(lands));
    }

    /// RELRO sealing keeps every byte of a segment mapped at the physical
    /// address it had and only ever takes write away: a byte of the live
    /// segment lies, after it, in exactly one segment, which translates it to
    /// the same physical address with the same flags or, from `ReadWrite`,
    /// `Read`, and every segment after it lies inside the live segment, so
    /// no byte outside it is mapped.
    ///
    /// The walk judges each live segment alone against the range, reading and
    /// writing only that segment and, for a split, the next free slot, so one
    /// live segment of any values covers every step a longer table repeats:
    /// the segment lies outside the range, inside it, or across its end, where
    /// the split cuts it. The walks are the code's over the one live segment
    /// and the harness's over the at most two segments after it, so an unwind
    /// bound of 3 covers them.
    #[kani::proof]
    #[kani::unwind(3)]
    fn relro_sealing_keeps_each_byte_at_its_address_and_only_drops_write()
    {
        let old = any_segment();
        kani::assume(old.virt_addr.checked_add(old.size).is_some());
        let mut segments = [old; INIT_MAX_SEGMENTS];
        let mut count = 1;
        let sealed = apply_relro(
            &mut segments,
            &mut count,
            kani::any(),
            kani::any(),
            kani::any(),
        );
        if sealed.is_err()
        {
            return;
        }
        assert!(count == 1 || count == 2);

        let virt: u64 = kani::any();
        kani::assume(maps(&old, virt));
        let mut found = 0usize;
        for seg in segments
            .iter()
            .take(count as usize)
            .filter(|seg| maps(seg, virt))
        {
            found += 1;
            assert_eq!(
                u128::from(seg.phys_addr) + u128::from(virt - seg.virt_addr),
                u128::from(old.phys_addr) + u128::from(virt - old.virt_addr)
            );
            assert!(
                seg.flags == old.flags
                    || (old.flags == SegmentFlags::ReadWrite && seg.flags == SegmentFlags::Read)
            );
        }
        assert_eq!(found, 1);

        // Nothing outside the segment is mapped after it: the head and the
        // tail of a split are both inside it.
        for seg in segments.iter().take(count as usize)
        {
            assert!(seg.virt_addr >= old.virt_addr);
            assert!(
                u128::from(seg.virt_addr) + u128::from(seg.size)
                    <= u128::from(old.virt_addr) + u128::from(old.size)
            );
        }
    }
}
