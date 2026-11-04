// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/arch/riscv64/encoding.rs

//! RISC-V register-map and instruction-encoding arithmetic: the PLIC context
//! layout, the PLIC source-count clamp, the SBI hart-mask window, page
//! rounding, and the F/D/V opcode decode the lazy extended-state trap uses.
//!
//! Pure functions of their arguments with no dependency on the rest of the
//! arch module. `arch/mod.rs` also compiles this file into host test builds
//! of the other architectures, so `cargo xtask test` (run on an `x86_64`
//! host) runs its tests.

/// Largest PLIC source id the RISC-V PLIC specification allows (sources 1..=1023;
/// source 0 is reserved).
pub(super) const PLIC_MAX_SOURCES: u32 = 1023;

/// Default PLIC MMIO window size when the bootloader did not report one: the
/// 64 MiB register map of the RISC-V PLIC specification, whose threshold and
/// claim/complete blocks hold all 15 872 contexts. A hardware spec value, so a
/// firmware hart id whose S-mode context the specification admits is never
/// refused for want of a reported size.
pub(super) const DEFAULT_PLIC_SIZE: u64 = 0x0400_0000;

/// PLIC S-mode context of the hart with hardware id `hart`.
///
/// Assumes the context layout of the targeted platforms (QEMU `virt`,
/// SiFive-style PLICs): M-mode = `hart*2`, S-mode = `hart*2+1`. The PLIC
/// specification leaves the mapping to the platform (`interrupts` module doc).
const fn plic_s_context(hart: u32) -> u64
{
    hart as u64 * 2 + 1
}

/// PLIC S-mode enable-bits base for the hart with hardware id `hart`:
/// 0x2000 + context * 0x80.
pub(super) const fn plic_enable_base_for(hart: u32) -> u64
{
    0x2000 + plic_s_context(hart) * 0x80
}

/// PLIC S-mode threshold register offset for the hart with hardware id `hart`:
/// `0x20_0000 + context * 0x1000`. The claim/complete register follows at +4.
pub(super) const fn plic_threshold_offset_for(hart: u32) -> u64
{
    0x0020_0000 + plic_s_context(hart) * 0x1000
}

/// Number of 32-bit enable words a context needs for sources `0..=ndev`.
pub(super) const fn enable_words(ndev: u32) -> u32
{
    (ndev + 1).div_ceil(32)
}

/// Whether the S-mode context registers of the hart with hardware id `hart`
/// (its enable words and its threshold and claim/complete pair) lie inside the
/// PLIC window of `window` bytes.
///
/// Hart ids come from firmware and can be sparse or large; a context past the
/// window would turn a `plic_write` into a store to arbitrary physical memory
/// through the direct map.
pub(super) const fn plic_context_in_window(hart: u32, window: u64) -> bool
{
    // With the standard register map the claim register always ends past the
    // enable words, so the enable-word test is defensive: it keeps the bound
    // correct should the enable span ever grow past the context block.
    let enable_end = plic_enable_base_for(hart) + enable_words(PLIC_MAX_SOURCES) as u64 * 4;
    let claim_end = plic_threshold_offset_for(hart) + 8;
    enable_end <= window && claim_end <= window
}

/// The PLIC source count to program for a reported `riscv,ndev` of `reported`: the report
/// when it lies in `1..=PLIC_MAX_SOURCES`, else the specification's [`PLIC_MAX_SOURCES`].
/// An unreported count (0) programs every source the specification allows, which is
/// harmless for the ones the PLIC lacks (their priority and enable bits read as zero); a
/// report past the specification is clamped.
pub(super) fn ndev_for(reported: u64) -> u32
{
    match u32::try_from(reported)
    {
        Ok(n) if (1..=PLIC_MAX_SOURCES).contains(&n) => n,
        _ => PLIC_MAX_SOURCES,
    }
}

/// Split a hart ID into the SBI `(hart_mask, hart_mask_base)` pair.
///
/// The SBI hart-mask convention addresses a 64-hart window: `hart_mask_base`
/// is the first hart ID of the window and `hart_mask` is a bitmask relative
/// to that base, so any hart ID up to the platform limit is reachable.
pub(super) fn sbi_hart_mask(target_hart_id: u32) -> (u64, u64)
{
    let base = u64::from(target_hart_id) & !63;
    let mask = 1u64 << (u64::from(target_hart_id) & 63);
    (mask, base)
}

/// `n` rounded up to a whole 4 KiB page.
pub(super) const fn page_round_up(n: u64) -> u64
{
    (n + 0xFFF) & !0xFFF
}

/// Return `true` if `insn` (a RISC-V instruction encoding from `stval` on an
/// illegal-instruction trap) is an F, D, or V instruction — i.e. the trap was
/// caused by FS=Off or VS=Off and is a candidate for lazy enable.
///
/// The lazy mechanism re-arms the trap on every switch-out, so the trapping
/// instruction is the *first* F/D/V op a thread executes after switch-in. To
/// avoid spuriously killing the thread, every encoding that can be that first
/// op must be recognised here. That is three classes, not just FP/V
/// arithmetic:
///
/// * 32-bit FP/V arith / load / store / fused-multiply (major opcodes below).
/// * 32-bit FP/V **CSR** accesses (`csrr`/`csrw` of `fcsr`/`fflags`/`frm` or
///   `vstart`/`vxsat`/`vxrm`/`vcsr`/`vl`/`vtype`/`vlenb`) — these are SYSTEM
///   opcode `0x73` and also trap while FS/VS=Off (autovectorised `memcpy`
///   reads `vlenb`, for example).
/// * Compressed F/D load/store (`c.fld`/`c.fsd`/`c.fldsp`/`c.fsdsp`); RV64 has
///   no `c.flw`/`c.fsw` and there are no compressed vector encodings.
///
/// 32-bit major opcodes (bits [6:0]):
/// - `0x07` LOAD-FP, `0x27` STORE-FP (scalar + vector load/store)
/// - `0x43`/`0x47`/`0x4B`/`0x4F` FMADD/FMSUB/FNMSUB/FNMADD
/// - `0x53` OP-FP, `0x57` OP-V (incl. `vsetvl[i]`)
///
/// Returns `false` if `insn == 0`, which some implementations write to
/// `stval` instead of the trapping encoding — the caller must then treat
/// the trap as a non-FP/V illegal instruction.
pub(super) fn is_fp_or_v_opcode(insn: u64) -> bool
{
    if insn == 0
    {
        return false;
    }
    // bits[1:0] == 0b11 marks a 32-bit instruction; anything else is a 16-bit
    // compressed encoding.
    if insn & 0x3 == 0x3
    {
        let major = (insn & 0x7F) as u8;
        if matches!(major, 0x07 | 0x27 | 0x43 | 0x47 | 0x4B | 0x4F | 0x53 | 0x57)
        {
            return true;
        }
        // SYSTEM opcode with a non-zero funct3 is a CSR op (funct3 == 0 is
        // ecall/ebreak/xret). Match the F/D and V CSR addresses (bits[31:20]).
        if major == 0x73 && (insn >> 12) & 0x7 != 0
        {
            let csr = (insn >> 20) & 0xFFF;
            return matches!(
                csr,
                0x001 | 0x002 | 0x003           // fflags, frm, fcsr
                    | 0x008 | 0x009 | 0x00A     // vstart, vxsat, vxrm
                    | 0x00F                     // vcsr
                    | 0xC20 | 0xC21 | 0xC22 // vl, vtype, vlenb
            );
        }
        return false;
    }
    // Compressed F/D load/store: quadrant C0 (`c.fld`/`c.fsd`) and C2
    // (`c.fldsp`/`c.fsdsp`) both use funct3 (bits[15:13]) ∈ {0b001, 0b101},
    // which are FP-only in those quadrants on RV64.
    matches!(insn & 0x3, 0b00 | 0b10) && matches!((insn >> 13) & 0x7, 0b001 | 0b101)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn plic_context_registers_follow_the_hart_id()
    {
        // Hart 0: S-mode context 1.
        assert_eq!(plic_enable_base_for(0), 0x2080);
        assert_eq!(plic_threshold_offset_for(0), 0x0020_1000);
        // Hart 3: S-mode context 7, so a boot hart other than 0 gets its own
        // registers rather than hart 0's.
        assert_eq!(plic_enable_base_for(3), 0x2000 + 7 * 0x80);
        assert_eq!(plic_threshold_offset_for(3), 0x0020_0000 + 7 * 0x1000);
    }

    // Defect caught: a firmware hart id whose context lies past the PLIC window
    // being accepted, which would turn the context writes into stores outside it.
    #[test]
    fn plic_context_outside_the_window_is_refused()
    {
        // A 4 MiB window holds 512 contexts after the 2 MiB of priority, pending
        // and enable registers: the S-mode contexts of harts 0..=255 (context
        // 511's claim register ends at 0x3F_F008); hart 256's is context 513.
        assert!(plic_context_in_window(0, 0x40_0000));
        assert!(plic_context_in_window(255, 0x40_0000));
        assert!(!plic_context_in_window(256, 0x40_0000));
        assert!(!plic_context_in_window(u32::MAX, 0x40_0000));
    }

    // Defect caught: a default window too small for the hart ids the PLIC
    // specification admits, so a platform reporting no PLIC size halts the boot
    // on a hart id at or above 256.
    #[test]
    fn default_plic_window_holds_every_context_the_specification_admits()
    {
        // Context 15871, the specification's last, is hart 7935's S-mode context.
        assert!(plic_context_in_window(256, DEFAULT_PLIC_SIZE));
        assert!(plic_context_in_window(7935, DEFAULT_PLIC_SIZE));
        assert!(!plic_context_in_window(7936, DEFAULT_PLIC_SIZE));
    }

    #[test]
    fn sbi_hart_mask_windows()
    {
        assert_eq!(sbi_hart_mask(0), (1, 0));
        assert_eq!(sbi_hart_mask(63), (1 << 63, 0));
        assert_eq!(sbi_hart_mask(64), (1, 64));
        assert_eq!(sbi_hart_mask(65), (1 << 1, 64));
        assert_eq!(sbi_hart_mask(127), (1 << 63, 64));
        assert_eq!(sbi_hart_mask(128), (1, 128));
        assert_eq!(sbi_hart_mask(511), (1 << 63, 448));
    }

    #[test]
    fn page_round_up_aligns()
    {
        assert_eq!(page_round_up(1), 0x1000);
        assert_eq!(page_round_up(0x1000), 0x1000);
        assert_eq!(page_round_up(0x1001), 0x2000);
    }

    // Defect caught: a reported source count trusted past the PLIC specification (the
    // enable and priority loops would write past the source registers), or an unreported
    // count leaving every source unprogrammed.
    #[test]
    fn plic_ndev_takes_the_report_within_the_specification()
    {
        assert_eq!(ndev_for(95), 95);
        assert_eq!(ndev_for(1023), 1023);
        assert_eq!(ndev_for(1024), 1023);
        assert_eq!(ndev_for(u64::MAX), 1023);
        assert_eq!(ndev_for(0), 1023);
    }

    #[test]
    fn zero_stval_is_not_fp_v()
    {
        // Some implementations write 0 to stval instead of the encoding.
        assert!(!is_fp_or_v_opcode(0));
    }

    #[test]
    fn fp_v_arith_load_store_opcodes()
    {
        assert!(is_fp_or_v_opcode(0x0000_3007)); // fld f0, 0(x0)   (LOAD-FP)
        assert!(is_fp_or_v_opcode(0x0000_30a7)); // fsd f0, 1(x0)   (STORE-FP)
        assert!(is_fp_or_v_opcode(0x0000_70d7)); // OP-V (vsetvl[i]/arith)
    }

    #[test]
    fn vector_csr_reads_are_fp_v()
    {
        // `csrr a1, vlenb`, as emitted by autovectorised userspace `memcpy`.
        assert!(is_fp_or_v_opcode(0xc220_25f3));
        // csrr x0, vl / vtype.
        assert!(is_fp_or_v_opcode(0xc200_2073)); // vl    (0xC20)
        assert!(is_fp_or_v_opcode(0xc210_2073)); // vtype (0xC21)
        // FP CSR (fcsr) read also traps while FS=Off.
        assert!(is_fp_or_v_opcode(0x0030_2073)); // csrr x0, fcsr (0x003)
    }

    #[test]
    fn system_non_csr_and_integer_ops_are_not_fp_v()
    {
        assert!(!is_fp_or_v_opcode(0x0000_0073)); // ecall (funct3 == 0)
        assert!(!is_fp_or_v_opcode(0x0010_0073)); // ebreak
        assert!(!is_fp_or_v_opcode(0x0000_0013)); // addi x0, x0, 0
        assert!(!is_fp_or_v_opcode(0xc000_2073)); // csrr x0, cycle (non-FP/V CSR)
    }

    #[test]
    fn compressed_fp_load_store_is_fp_v()
    {
        assert!(is_fp_or_v_opcode(0x2000)); // C0 funct3=001 (c.fld)
        assert!(is_fp_or_v_opcode(0xa000)); // C0 funct3=101 (c.fsd)
        assert!(is_fp_or_v_opcode(0x2002)); // C2 funct3=001 (c.fldsp)
        assert!(is_fp_or_v_opcode(0xa002)); // C2 funct3=101 (c.fsdsp)
    }

    #[test]
    fn compressed_integer_ops_are_not_fp_v()
    {
        assert!(!is_fp_or_v_opcode(0x0001)); // c.nop / c.addi (C1)
        assert!(!is_fp_or_v_opcode(0x4000)); // C0 funct3=010 (c.lw)
        assert!(!is_fp_or_v_opcode(0x4002)); // C2 funct3=010 (c.lwsp)
    }
}
