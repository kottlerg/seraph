// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/arch/riscv64/encoding.rs

//! RISC-V register-map and instruction-encoding arithmetic: the SBI hart-mask
//! window, page rounding, the timer's tick and microsecond conversions, the
//! F/D/V opcode decode and the `sstatus` test the extended-state first-use
//! trap uses, the Zkr `seed` CSR's
//! status decode and the word the hardware RNG builds from its samples, the
//! `sstateen0` and `senvcfg` values and the check of their read back, the PTE
//! permission bits and their test in the kernel's spurious-fault retry, and the
//! user leaf's grant bits and the permission change they bound.
//!
//! Pure functions of their arguments with no dependency on the rest of the
//! arch module.

use crate::mm::paging::{LeafGrant, PagingError};

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

/// `n` rounded up to a whole 4 KiB page, or `None` when that passes the end of
/// the address space.
pub(super) const fn page_round_up(n: u64) -> Option<u64>
{
    match n.checked_add(0xFFF)
    {
        Some(end) => Some(end & !0xFFF),
        None => None,
    }
}

/// Ticks of a `freq` Hz counter in a period of `period_us` microseconds,
/// saturating at `u64::MAX`.
// The product is computed in u128, where two u64 factors cannot overflow; the
// quotient fits u64 for every freq ≤ u32::MAX (enforced by `timer::init`) and
// sane period.
pub(super) fn ticks_for_period(freq: u64, period_us: u64) -> u64
{
    let ticks = u128::from(freq).saturating_mul(u128::from(period_us)) / 1_000_000;
    u64::try_from(ticks).unwrap_or(u64::MAX)
}

/// Convert `ticks` of a `freq` Hz counter to whole microseconds, saturating at
/// `u64::MAX`.
///
/// Exact for arbitrary frequencies via a div/mod split: the remainder
/// product `(ticks % freq) * 1_000_000` cannot overflow because `timer::init`
/// bounds `freq` to `u32::MAX` (< 2^32 · 2^20 = 2^52). Returns 0 when
/// `freq` is zero (timer not initialised).
pub(super) fn ticks_to_us(ticks: u64, freq: u64) -> u64
{
    let Some(freq) = core::num::NonZeroU64::new(freq)
    else
    {
        return 0;
    };
    (ticks / freq)
        .saturating_mul(1_000_000)
        .saturating_add((ticks % freq).saturating_mul(1_000_000) / freq)
}

/// Return `true` if `insn` (a RISC-V instruction encoding from `stval` on an
/// illegal-instruction trap) is an F, D, or V instruction — i.e. the trap was
/// caused by FS=Off or VS=Off and is a candidate for the first-use trap.
///
/// A thread runs with the units Off until its first F/D/V op, so the trapping
/// instruction is the *first* F/D/V op a thread executes. To avoid spuriously
/// killing the thread, every encoding that can be that first op must be
/// recognised here. That is three classes, not just FP/V
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
fn is_fp_or_v_opcode(insn: u64) -> bool
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

/// `sstatus.FS` (bits 14:13), the F/D unit's state: 00 Off, 01 Initial,
/// 10 Clean, 11 Dirty.
pub(super) const SSTATUS_FS_MASK: u64 = 0x3 << 13;

/// `sstatus.VS` (bits 10:9), the V unit's state, in `FS`'s encoding.
pub(super) const SSTATUS_VS_MASK: u64 = 0x3 << 9;

/// Whether a U-mode illegal-instruction trap is the extended-state first-use
/// trap, which turns the F/D and V units on and makes the thread's state live:
/// the thread ran with `sstatus.FS` Off (`sstatus`, the value the trap saved),
/// and the trapping instruction (`stval`) is one [`is_fp_or_v_opcode`]
/// matches. The kernel sets `FS` and `VS` in a thread's frame together
/// (`fpu::switch_in_restore`, `fpu::first_use_trap`, `fpu::switch_out_save`),
/// so `FS` Off is the state of both units.
///
/// An F/D/V instruction that traps with the units on was refused for a
/// reason of its own: a reserved rounding mode, in the instruction or in
/// `frm`, a vector instruction that depends on `vtype` while `vtype.vill`
/// is set, or an extension the hart lacks. That trap is the thread's
/// illegal-instruction fault; treating it as the first-use trap would instead
/// re-execute the instruction for ever.
pub(super) fn is_first_use_trap(sstatus: u64, stval: u64) -> bool
{
    sstatus & SSTATUS_FS_MASK == 0 && is_fp_or_v_opcode(stval)
}

// ── The Zkr `seed` CSR ────────────────────────────────────────────────────────

/// What one read of the Zkr `seed` CSR reports, by its `OPST` field (bits
/// \[31:30\]; the RISC-V scalar cryptography specification, § Entropy Source).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SeedPoll
{
    /// `ES16` (`0b10`): bits \[15:0\] hold 16 bits of entropy.
    Es16(u16),
    /// `BIST` (`0b00`, a self-test is running) or `WAIT` (`0b01`, no entropy
    /// is ready yet): a later read may return a sample.
    NotReady,
    /// `DEAD` (`0b11`): an unrecoverable self-test failure. A read that
    /// trapped decodes here too: its fixup returns `u64::MAX`, whose `OPST`
    /// is `DEAD` (`entropy::seed_fault_fixup`).
    Dead,
}

/// Decode the value a read of the `seed` CSR returned.
pub(super) fn decode_seed(value: u64) -> SeedPoll
{
    match (value >> 30) & 0b11
    {
        0b10 => SeedPoll::Es16((value & 0xFFFF) as u16),
        0b11 => SeedPoll::Dead,
        _ => SeedPoll::NotReady,
    }
}

/// Why [`seed_word`] built no word.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SeedError
{
    /// A read reported `DEAD`, or trapped: the source is unusable.
    Dead,
    /// The source stayed in `BIST` or `WAIT` until the word's wait budget was
    /// spent.
    TimedOut,
}

/// Build a 64-bit word from four `ES16` samples of the `seed` CSR, the first
/// sample in the low 16 bits.
///
/// `read` reads the CSR once. Each read that finds the source not ready calls
/// `expired`, which says whether the word's wait budget is spent; until it is,
/// the read is repeated.
///
/// # Errors
/// [`SeedError::Dead`] at the first `DEAD` read (or trapped one);
/// [`SeedError::TimedOut`] when `expired` reports the budget spent.
pub(super) fn seed_word(
    mut read: impl FnMut() -> u64,
    mut expired: impl FnMut() -> bool,
) -> Result<u64, SeedError>
{
    let mut word = 0u64;
    for shift in [0u32, 16, 32, 48]
    {
        let sample = loop
        {
            match decode_seed(read())
            {
                SeedPoll::Es16(sample) => break sample,
                SeedPoll::NotReady =>
                {
                    if expired()
                    {
                        return Err(SeedError::TimedOut);
                    }
                    core::hint::spin_loop();
                }
                SeedPoll::Dead => return Err(SeedError::Dead),
            }
        };
        word |= u64::from(sample) << shift;
    }
    Ok(word)
}

// ── The U-mode state-enable CSRs (`sstateen0`, `senvcfg`) ───────────────────

/// The value every hart writes to `sstateen0`: no state enabled for U-mode.
///
/// The CSR's bits that reach U-mode gate state the kernel does not save and
/// restore on a context switch, so each is clear: bit 0 (`C`) the
/// implementation's custom state, bit 1 (`FCSR`) the `fcsr` of a hart whose
/// floating point runs on the integer registers (Zfinx; read-only zero on a
/// hart with F, which the floor requires), and bit 2 (`JVT`) the Zcmt jump
/// table register `jvt`. A bit a later extension defines is clear too, so U-mode
/// reaches its state only once the kernel switches that state and sets the bit
/// here. See docs/platform-requirements.md § riscv64 Classification.
pub(super) const SSTATEEN0_USER_ENABLES: u64 = 0;

/// The U-mode environment controls, as the `senvcfg` value: none granted.
/// `CBZE`, `CBCFE` and `CBIE` clear make every U-mode cache-block operation
/// (`cbo.zero`, `cbo.clean`, `cbo.flush`, `cbo.inval`) raise an
/// illegal-instruction exception; `cbo.inval` would otherwise discard a
/// block's dirty data and expose what memory held below it. `PMM` clear turns
/// pointer masking off, `LPE` and `SSE` clear keep the landing-pad and
/// shadow-stack enforcement and the `ssp` CSR from U-mode, and `FIOM` clear
/// keeps fences on I/O and memory separate. A field whose extension the hart
/// lacks is read-only zero, so the value is the same on every hart, and 0 is a
/// legal value of every field.
pub(super) const SENVCFG_USER_ENABLES: u64 = 0;

/// Why the write of a U-mode state-enable CSR did not take.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum StateEnableError
{
    /// The write or the read back trapped: M-mode firmware keeps the CSR from
    /// S-mode (`mstateen0.SE0` clear for `sstateen0`, `mstateen0.ENVCFG`
    /// clear for `senvcfg`), or the hart lacks the CSR.
    Inaccessible,
    /// The CSR read back this value, not the one written.
    Kept(u64),
}

/// Judge the write of `written` to a U-mode state-enable CSR (`sstateen0` or
/// `senvcfg`) by its read back: `None` when an access trapped, else the value
/// the CSR held after the write.
///
/// # Errors
/// [`StateEnableError::Inaccessible`] when an access trapped;
/// [`StateEnableError::Kept`] when the CSR holds another value.
pub(super) fn check_state_enable(
    written: u64,
    read_back: Option<u64>,
) -> Result<(), StateEnableError>
{
    match read_back
    {
        None => Err(StateEnableError::Inaccessible),
        Some(value) if value == written => Ok(()),
        Some(value) => Err(StateEnableError::Kept(value)),
    }
}

// ── PTE permission bits and the kernel spurious-fault test ───────────────────

/// Sv39/Sv48/Sv57 PTE bit V: the entry is valid.
pub(super) const PTE_VALID: u64 = 1 << 0;
/// PTE bit R: read permission.
pub(super) const PTE_READ: u64 = 1 << 1;
/// PTE bit W: write permission.
pub(super) const PTE_WRITE: u64 = 1 << 2;
/// PTE bit X: execute permission.
pub(super) const PTE_EXECUTE: u64 = 1 << 3;

/// The access an S-mode page fault made, for the kernel's spurious-fault
/// retry (`paging::kernel_fault_is_spurious`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KernelAccess
{
    /// A load (`scause` 13).
    Load,
    /// A store or AMO (`scause` 15).
    Store,
}

/// Whether the kernel leaf PTE `pte` is valid and grants `access`, so that a
/// fault of that access on its page is a stale TLB entry the hart resolves on
/// retry: the decision of `paging::kernel_fault_is_spurious` once its walk
/// found the leaf.
pub(super) fn kernel_leaf_permits(pte: u64, access: KernelAccess) -> bool
{
    let permits = match access
    {
        KernelAccess::Load => pte & PTE_READ != 0,
        KernelAccess::Store => pte & PTE_WRITE != 0,
    };
    pte & PTE_VALID != 0 && permits
}

/// PTE bit U: the page is reachable from U-mode.
pub(super) const PTE_USER: u64 = 1 << 4;
/// Svpbmt PBMT field, bits \[62:61\]: zero (PMA) is the platform's memory
/// type, which every RAM mapping uses; NC and IO are the non-cacheable types.
pub(super) const PTE_PBMT_MASK: u64 = 0b11 << 61;

/// RSW bit 8 of a user leaf: its [`LeafGrant`] holds write. The RSW field,
/// bits \[9:8\], is the only one the privileged specification leaves to
/// supervisor software (bits \[60:54\] are reserved and must be zero); bit 8
/// of a table-pointer entry is `paging::POOLED_TABLE` instead, which every
/// reader checks only on an entry with no R, W or X. See
/// core/kernel/docs/memory-internals.md § Leaf Grant.
pub(super) const PTE_GRANT_WRITE: u64 = 1 << 8;
/// RSW bit 9 of a user leaf: its [`LeafGrant`] holds execute.
pub(super) const PTE_GRANT_EXECUTE: u64 = 1 << 9;

/// The software bits that record `grant` in a user leaf.
pub(super) fn grant_bits(grant: LeafGrant) -> u64
{
    let mut bits = 0;
    if grant.writable
    {
        bits |= PTE_GRANT_WRITE;
    }
    if grant.executable
    {
        bits |= PTE_GRANT_EXECUTE;
    }
    bits
}

/// The [`LeafGrant`] the user leaf `pte` records (`paging::user_leaf_grant`).
pub(super) fn user_leaf_grant(pte: u64) -> LeafGrant
{
    LeafGrant {
        writable: pte & PTE_GRANT_WRITE != 0,
        executable: pte & PTE_GRANT_EXECUTE != 0,
    }
}

/// The bits a permission change keeps from the leaf it rewrites: the memory
/// type (PBMT) and the grant.
const KEPT_BY_PROTECT: u64 = PTE_PBMT_MASK | PTE_GRANT_WRITE | PTE_GRANT_EXECUTE;

/// The leaf a permission change installs in place of the present user leaf
/// `prior`, given `new`, a fresh user leaf of the same frame with the new
/// rights; or [`PagingError::NotGranted`] when `new` holds W or X that
/// `prior`'s grant lacks.
///
/// The result keeps `prior`'s memory type and grant: an IO device leaf of
/// `SYS_MMIO_MAP` stays IO, which `SYS_THREAD_READ_MEM` and
/// `SYS_THREAD_WRITE_MEM` rely on to refuse device memory
/// (`AddressSpace::copy_user_bytes`), and the grant stays what the installing
/// capability carried.
pub(super) fn protected_leaf(prior: u64, new: u64) -> Result<u64, PagingError>
{
    let grant = user_leaf_grant(prior);
    if (new & PTE_WRITE != 0 && !grant.writable) || (new & PTE_EXECUTE != 0 && !grant.executable)
    {
        return Err(PagingError::NotGranted);
    }
    Ok((new & !KEPT_BY_PROTECT) | (prior & KEPT_BY_PROTECT))
}

/// The access the user leaf PTE `pte` grants, or `None` when it is not valid
/// or not user-accessible (`paging::user_leaf_flags`). `uncacheable` is set
/// for any PBMT other than PMA.
pub(super) fn user_leaf_flags(pte: u64) -> Option<crate::mm::paging::PageFlags>
{
    if pte & PTE_VALID == 0 || pte & PTE_USER == 0
    {
        return None;
    }
    Some(crate::mm::paging::PageFlags {
        readable: pte & PTE_READ != 0,
        writable: pte & PTE_WRITE != 0,
        executable: pte & PTE_EXECUTE != 0,
        uncacheable: pte & PTE_PBMT_MASK != 0,
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests
{
    use super::*;

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
    fn period_ticks_for_10ms_at_10_mhz()
    {
        // 10 ms = 10_000 µs → 10_000_000 * 10_000 / 1_000_000 = 100_000 ticks.
        assert_eq!(ticks_for_period(10_000_000, 10_000), 100_000);
    }

    #[test]
    fn period_ticks_for_1ms_at_10_mhz()
    {
        assert_eq!(ticks_for_period(10_000_000, 1_000), 10_000);
    }

    #[test]
    fn period_ticks_for_1ms_at_non_mhz_multiple()
    {
        // 1_193_182 Hz (a frequency with no whole ticks-per-µs ratio):
        // 1 ms = 1_193.182 ticks, truncated.
        assert_eq!(ticks_for_period(1_193_182, 1_000), 1_193);
    }

    #[test]
    fn period_ticks_saturate_past_u64_max()
    {
        // Defect caught: a quotient past u64::MAX truncated to a short period.
        assert_eq!(ticks_for_period(u64::MAX, u64::MAX), u64::MAX);
    }

    #[test]
    fn ticks_to_us_exact_at_10_mhz()
    {
        assert_eq!(ticks_to_us(12_345, 10_000_000), 1_234);
        assert_eq!(ticks_to_us(10_000_000, 10_000_000), 1_000_000);
    }

    #[test]
    fn ticks_to_us_exact_at_arbitrary_frequencies()
    {
        for freq in [1_193_182u64, 24_000_000, 3, u64::from(u32::MAX)]
        {
            for ticks in [0u64, 1, freq - 1, freq, freq + 1, 1 << 40, 1 << 60]
            {
                let exact = u128::from(ticks) * 1_000_000 / u128::from(freq);
                let expected = u64::try_from(exact).unwrap_or(u64::MAX);
                assert_eq!(
                    ticks_to_us(ticks, freq),
                    expected,
                    "ticks={ticks} freq={freq}"
                );
            }
        }
    }

    #[test]
    fn ticks_to_us_saturates_past_u64_max_microseconds()
    {
        // Defect caught: the whole-second product wrapping to a small time.
        assert_eq!(ticks_to_us(u64::MAX, 1), u64::MAX);
        assert_eq!(ticks_to_us(u64::MAX, 3), u64::MAX);
    }

    #[test]
    fn ticks_to_us_zero_frequency_is_zero()
    {
        assert_eq!(ticks_to_us(12_345, 0), 0);
    }

    #[test]
    fn page_round_up_aligns()
    {
        assert_eq!(page_round_up(1), Some(0x1000));
        assert_eq!(page_round_up(0x1000), Some(0x1000));
        assert_eq!(page_round_up(0x1001), Some(0x2000));
    }

    #[test]
    fn page_round_up_past_the_end_of_the_address_space_is_none()
    {
        // Defect caught: a size in the last page wrapping to 0 when rounded up.
        assert_eq!(
            page_round_up(0xFFFF_FFFF_FFFF_F000),
            Some(0xFFFF_FFFF_FFFF_F000)
        );
        assert_eq!(page_round_up(0xFFFF_FFFF_FFFF_F001), None);
        assert_eq!(page_round_up(u64::MAX), None);
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

    // Defect caught: a first-use trap test that ignored the saved `sstatus.FS`
    // would restore the saved state over the live one for an F/D/V
    // instruction refused with the units on, and re-execute it for ever,
    // instead of delivering the thread's illegal-instruction fault.
    #[test]
    fn only_an_fp_v_trap_with_the_units_off_is_the_first_use_trap()
    {
        /// `fadd.d f0, f0, f0` with the reserved rounding mode 101.
        const FADD_RESERVED_RM: u64 = 0x0200_5053;
        /// `sstatus.SPIE` (bit 5), so the units' fields are not the only bits.
        const OTHER_BITS: u64 = 1 << 5;
        assert!(is_first_use_trap(OTHER_BITS, FADD_RESERVED_RM));
        for fs in [1u64, 2, 3]
        {
            let units_on = OTHER_BITS | (fs << 13) | (fs << 9);
            assert!(!is_first_use_trap(units_on, FADD_RESERVED_RM), "FS {fs}");
        }
        assert!(!is_first_use_trap(OTHER_BITS, 0x0000_0013)); // addi: not F/D/V
        assert!(!is_first_use_trap(OTHER_BITS, 0)); // stval 0: no encoding
    }

    // Defect caught: a predicate that swapped R and W, or ignored them, would
    // retry a genuine kernel load or store the leaf forbids forever instead of
    // reporting the kernel exception.
    #[test]
    fn a_kernel_leaf_permits_a_load_when_readable_and_a_store_when_writable()
    {
        let ro = PTE_VALID | PTE_READ;
        let rw = PTE_VALID | PTE_READ | PTE_WRITE;
        let x_only = PTE_VALID | PTE_EXECUTE;
        assert!(kernel_leaf_permits(ro, KernelAccess::Load));
        assert!(!kernel_leaf_permits(ro, KernelAccess::Store));
        assert!(kernel_leaf_permits(rw, KernelAccess::Store));
        assert!(!kernel_leaf_permits(x_only, KernelAccess::Load));
    }

    // Defect caught: a retry of a fault on an invalid leaf loops forever.
    #[test]
    fn an_invalid_kernel_leaf_permits_nothing()
    {
        let invalid = PTE_READ | PTE_WRITE;
        assert!(!kernel_leaf_permits(invalid, KernelAccess::Load));
        assert!(!kernel_leaf_permits(invalid, KernelAccess::Store));
    }

    // Defect caught: a decoder that let a supervisor or invalid leaf through
    // would let SYS_THREAD_READ_MEM read a page the thread cannot reach, and one
    // that dropped X, W or the memory type would skip the instruction-cache
    // sync, permit a text write without THREAD_MEM_TEXT, or read device
    // memory through the direct map.
    #[test]
    fn a_user_leaf_decodes_to_its_access_and_memory_type()
    {
        assert!(user_leaf_flags(PTE_VALID | PTE_READ | PTE_WRITE).is_none());
        assert!(user_leaf_flags(PTE_USER | PTE_READ).is_none());
        let rx = user_leaf_flags(PTE_VALID | PTE_USER | PTE_READ | PTE_EXECUTE).unwrap();
        assert!(rx.readable && rx.executable && !rx.writable && !rx.uncacheable);
        let x_only = user_leaf_flags(PTE_VALID | PTE_USER | PTE_EXECUTE).unwrap();
        assert!(!x_only.readable && x_only.executable);
        let rw = user_leaf_flags(PTE_VALID | PTE_USER | PTE_READ | PTE_WRITE).unwrap();
        assert!(rw.writable && !rw.executable);
        let io = user_leaf_flags(PTE_VALID | PTE_USER | PTE_READ | (0b10 << 61)).unwrap();
        assert!(io.uncacheable);
        let nc = user_leaf_flags(PTE_VALID | PTE_USER | PTE_READ | (0b01 << 61)).unwrap();
        assert!(nc.uncacheable);
    }

    // Defect caught: a protect that rebuilt the leaf from its new rights alone
    // would turn an IO device leaf into PMA memory, so SYS_THREAD_READ_MEM
    // would take the device frame for RAM and copy it through the direct map;
    // and one that kept other bits of the old leaf would keep its old rights.
    #[test]
    fn a_rights_change_keeps_the_leaf_memory_type()
    {
        let ppn = 0x200 << 10;
        let device =
            PTE_VALID | PTE_USER | PTE_READ | PTE_WRITE | PTE_GRANT_WRITE | (0b10 << 61) | ppn;
        let read_only = PTE_VALID | PTE_USER | PTE_READ | ppn;
        let protected = protected_leaf(device, read_only).unwrap();
        let flags = user_leaf_flags(protected).unwrap();
        assert!(flags.uncacheable && !flags.writable);
        assert_eq!(protected & !(PTE_PBMT_MASK | PTE_GRANT_WRITE), read_only);

        let ram = PTE_VALID | PTE_USER | PTE_READ | ppn;
        let protected = protected_leaf(ram, read_only | (0b10 << 61)).unwrap();
        assert!(!user_leaf_flags(protected).unwrap().uncacheable);
    }

    // Defect caught (#868): a permission change that let a leaf take W or X
    // its installing capability lacked, so a read-only Mmio or Memory mapping
    // turned writable or executable through any other Memory capability; one
    // that dropped the grant, so a narrowing lost the rights a later protect
    // may take back; or grant bits that overlap a field the hart reads.
    #[test]
    fn a_rights_change_stays_within_the_leaf_grant_and_keeps_it()
    {
        let ppn = 0x300 << 10;
        let base = PTE_VALID | PTE_USER | PTE_READ | ppn;
        let rw = base | PTE_WRITE;
        let rx = base | PTE_EXECUTE;
        let write = LeafGrant {
            writable: true,
            executable: false,
        };
        let exec = LeafGrant {
            writable: false,
            executable: true,
        };

        // A Map-only leaf: no widening at all, a read-only rewrite taken.
        let map_only = base | grant_bits(LeafGrant::default());
        assert_eq!(map_only, base);
        assert_eq!(protected_leaf(map_only, rw), Err(PagingError::NotGranted));
        assert_eq!(protected_leaf(map_only, rx), Err(PagingError::NotGranted));
        assert_eq!(protected_leaf(map_only, base), Ok(base));

        // A read-only leaf of a Write-bearing capability widens to W, not to
        // X, and keeps its grant across a narrowing and back.
        let rw_cap = base | grant_bits(write);
        assert_eq!(user_leaf_grant(rw_cap), write);
        let widened = protected_leaf(rw_cap, rw).unwrap();
        assert!(user_leaf_flags(widened).unwrap().writable);
        assert_eq!(user_leaf_grant(widened), write);
        assert_eq!(protected_leaf(rw_cap, rx), Err(PagingError::NotGranted));
        assert_eq!(protected_leaf(widened, base), Ok(rw_cap));

        // An Execute-bearing one widens to X only.
        let exec_cap = base | grant_bits(exec);
        assert!(
            user_leaf_flags(protected_leaf(exec_cap, rx).unwrap())
                .unwrap()
                .executable
        );
        assert_eq!(protected_leaf(exec_cap, rw), Err(PagingError::NotGranted));

        // The grant sits in RSW alone: clear of V/R/W/X/U/G/A/D (bits 7:0),
        // the PPN (53:10), PBMT (62:61) and N (63).
        let both = grant_bits(LeafGrant {
            writable: true,
            executable: true,
        });
        assert_eq!(both, 0b11 << 8);
        assert_eq!(
            both & (0xFF | (0xFFF_FFFF_FFFF << 10) | PTE_PBMT_MASK | (1 << 63)),
            0
        );
    }

    // ── The Zkr `seed` CSR ──

    /// A `seed` value with status `opst` and entropy `bits`.
    fn seed(opst: u64, bits: u64) -> u64
    {
        (opst << 30) | bits
    }

    #[test]
    fn seed_status_decodes_by_opst_alone()
    {
        assert_eq!(decode_seed(seed(0b10, 0xABCD)), SeedPoll::Es16(0xABCD));
        // Custom bits [23:16] beside a sample are not entropy.
        assert_eq!(
            decode_seed(seed(0b10, 0xABCD) | (0x5A << 16)),
            SeedPoll::Es16(0xABCD)
        );
        assert_eq!(decode_seed(seed(0b00, 0)), SeedPoll::NotReady);
        assert_eq!(decode_seed(seed(0b01, 0)), SeedPoll::NotReady);
        assert_eq!(decode_seed(seed(0b11, 0)), SeedPoll::Dead);
    }

    #[test]
    fn the_fixup_value_of_a_trapped_seed_read_decodes_as_dead()
    {
        // The probe reports the source absent on this value; decoding it as
        // anything else would draw from a hart that has no source.
        assert_eq!(decode_seed(u64::MAX), SeedPoll::Dead);
    }

    #[test]
    fn a_seed_word_takes_four_samples_low_first_across_not_ready_reads()
    {
        let mut reads = [
            seed(0b01, 0),
            seed(0b10, 0x1111),
            seed(0b00, 0),
            seed(0b10, 0x2222),
            seed(0b10, 0x3333),
            seed(0b01, 0),
            seed(0b10, 0x4444),
        ]
        .into_iter();
        let mut waits = 0;
        let word = seed_word(
            || reads.next().unwrap(),
            || {
                waits += 1;
                false
            },
        );
        assert_eq!(word, Ok(0x4444_3333_2222_1111));
        assert_eq!(waits, 3);
        assert_eq!(reads.next(), None);
    }

    #[test]
    fn a_dead_seed_read_ends_the_word()
    {
        let mut reads = [seed(0b10, 0x1111), seed(0b11, 0)].into_iter();
        assert_eq!(
            seed_word(|| reads.next().unwrap(), || false),
            Err(SeedError::Dead)
        );
    }

    #[test]
    fn a_seed_source_not_ready_past_the_budget_times_out()
    {
        let mut reads = 0;
        let mut waits = 0;
        let word = seed_word(
            || {
                reads += 1;
                seed(0b01, 0)
            },
            || {
                waits += 1;
                waits == 3
            },
        );
        assert_eq!(word, Err(SeedError::TimedOut));
        assert_eq!(reads, 3);
    }

    // ── The U-mode state-enable CSRs ──

    #[test]
    fn an_sstateen0_that_reads_back_the_value_written_is_accepted()
    {
        assert_eq!(
            check_state_enable(SSTATEEN0_USER_ENABLES, Some(SSTATEEN0_USER_ENABLES)),
            Ok(())
        );
    }

    #[test]
    fn a_trapped_sstateen0_access_is_inaccessible()
    {
        // The access's fixup reports a trap as `None`; accepting it would let
        // U-mode keep whatever state enables the firmware left.
        assert_eq!(
            check_state_enable(SSTATEEN0_USER_ENABLES, None),
            Err(StateEnableError::Inaccessible)
        );
    }

    #[test]
    fn an_sstateen0_enable_left_set_is_reported_with_the_value_read()
    {
        // The `JVT` bit kept set: U-mode would reach `jvt`, which no switch saves.
        let jvt_kept = SSTATEEN0_USER_ENABLES | (1 << 2);
        assert_eq!(
            check_state_enable(SSTATEEN0_USER_ENABLES, Some(jvt_kept)),
            Err(StateEnableError::Kept(jvt_kept))
        );
    }

    #[test]
    fn a_senvcfg_that_reads_back_the_value_written_is_accepted()
    {
        assert_eq!(
            check_state_enable(SENVCFG_USER_ENABLES, Some(SENVCFG_USER_ENABLES)),
            Ok(())
        );
    }

    #[test]
    fn a_trapped_senvcfg_access_is_inaccessible()
    {
        // Firmware that grants `sstateen0` (`mstateen0.SE0`) but leaves
        // `mstateen0.ENVCFG` clear traps the `senvcfg` write; the fixup
        // reports it as `None`, and accepting it would let U-mode keep the
        // environment enables the firmware or reset left.
        assert_eq!(
            check_state_enable(SENVCFG_USER_ENABLES, None),
            Err(StateEnableError::Inaccessible)
        );
    }

    #[test]
    fn a_senvcfg_enable_left_set_is_reported_with_the_value_read()
    {
        // `CBIE` (bits 5:4) kept at 0b01: U-mode `cbo.inval` would flush, and
        // at 0b11 discard dirty data.
        let cbie_kept = SENVCFG_USER_ENABLES | (0b01 << 4);
        assert_eq!(
            check_state_enable(SENVCFG_USER_ENABLES, Some(cbie_kept)),
            Err(StateEnableError::Kept(cbie_kept))
        );
    }
}

/// Bounded proofs of the register-map and encoding arithmetic
/// (docs/testing.md § Bounded verification), compiled on every host by the
/// `cfg(kani)` include in `arch/mod.rs`. Every register value and hart ID
/// is symbolic over every value its type holds; the one loop is
/// `seed_word`'s, bounded in its harness.
///
/// The timer conversions (`ticks_for_period`, `ticks_to_us`) are not proved
/// here: their exactness is an identity of 64-bit products and quotients of a
/// symbolic frequency, which the solver does not settle within the harness
/// time limit (docs/testing.md § Bounded verification), and their unit tests
/// hold it at the boundary frequencies and counts.
#[cfg(kani)]
mod proofs
{
    use core::cell::Cell;

    use super::{
        KernelAccess, PTE_EXECUTE, PTE_GRANT_EXECUTE, PTE_GRANT_WRITE, PTE_PBMT_MASK, PTE_READ,
        PTE_USER, PTE_VALID, PTE_WRITE, SSTATUS_FS_MASK, SeedError, SeedPoll, decode_seed,
        grant_bits, is_first_use_trap, kernel_leaf_permits, page_round_up, protected_leaf,
        sbi_hart_mask, seed_word, user_leaf_flags, user_leaf_grant,
    };
    use crate::mm::paging::{LeafGrant, PagingError};

    /// The `OPST` field of a `seed` CSR value.
    fn opst(value: u64) -> u64
    {
        (value >> 30) & 0b11
    }

    /// The SBI window of any hart ID names that hart alone: one bit of the
    /// mask, at the hart's offset from a 64-aligned base.
    #[kani::proof]
    fn the_hart_mask_window_names_its_hart_alone()
    {
        let hart: u32 = kani::any();
        let (mask, base) = sbi_hart_mask(hart);
        assert!(mask.is_power_of_two() && base.is_multiple_of(64));
        assert_eq!(base + u64::from(mask.trailing_zeros()), u64::from(hart));
    }

    /// Rounding up gives the least page boundary at or above `n`, and fails
    /// exactly when that boundary passes the end of the address space.
    #[kani::proof]
    fn page_round_up_gives_the_least_boundary_at_or_above()
    {
        let n: u64 = kani::any();
        match page_round_up(n)
        {
            Some(up) =>
            {
                assert!(up >= n && up - n < 0x1000 && up.is_multiple_of(0x1000));
            }
            None => assert!(n > u64::MAX - 0xFFF),
        }
    }

    /// The first-use trap needs the F/D unit Off and a nonzero instruction,
    /// and a `seed` value decodes by its `OPST` field alone, `ES16`
    /// carrying the low 16 bits; the leaf decodes read their bits: a kernel
    /// leaf permits an access only when valid and granting it, and a user
    /// leaf decodes only when valid and user-accessible.
    #[kani::proof]
    fn every_trap_seed_and_leaf_decode_reads_its_own_bits()
    {
        let sstatus: u64 = kani::any();
        let stval: u64 = kani::any();
        if is_first_use_trap(sstatus, stval)
        {
            assert!(sstatus & SSTATUS_FS_MASK == 0 && stval != 0);
        }

        let value: u64 = kani::any();
        match decode_seed(value)
        {
            SeedPoll::Es16(sample) =>
            {
                assert!(opst(value) == 0b10 && u64::from(sample) == value & 0xFFFF)
            }
            SeedPoll::Dead => assert_eq!(opst(value), 0b11),
            SeedPoll::NotReady => assert!(opst(value) < 0b10),
        }

        let pte: u64 = kani::any();
        assert_eq!(
            kernel_leaf_permits(pte, KernelAccess::Load),
            pte & PTE_VALID != 0 && pte & PTE_READ != 0
        );
        assert_eq!(
            kernel_leaf_permits(pte, KernelAccess::Store),
            pte & PTE_VALID != 0 && pte & PTE_WRITE != 0
        );
        match user_leaf_flags(pte)
        {
            Some(flags) =>
            {
                assert!(pte & PTE_VALID != 0 && pte & PTE_USER != 0);
                assert_eq!(flags.readable, pte & PTE_READ != 0);
                assert_eq!(flags.writable, pte & PTE_WRITE != 0);
                assert_eq!(flags.executable, pte & PTE_EXECUTE != 0);
                assert_eq!(flags.uncacheable, pte & PTE_PBMT_MASK != 0);
            }
            None => assert!(pte & PTE_VALID == 0 || pte & PTE_USER == 0),
        }
    }

    /// A leaf's grant decodes to the grant its bits encoded, whatever the
    /// leaf's other bits hold.
    #[kani::proof]
    fn a_grant_round_trips_through_its_leaf_bits()
    {
        let grant = LeafGrant {
            writable: kani::any(),
            executable: kani::any(),
        };
        let other: u64 = kani::any();
        let pte = (other & !(PTE_GRANT_WRITE | PTE_GRANT_EXECUTE)) | grant_bits(grant);
        assert_eq!(user_leaf_grant(pte), grant);
    }

    /// A permission change refuses exactly the write or execute the prior
    /// leaf's grant lacks, and the leaf it installs holds no W or X beyond
    /// that grant, keeps the prior memory type and grant, and takes every
    /// other bit from the new leaf.
    #[kani::proof]
    fn a_permission_change_never_exceeds_the_grant_or_changes_the_memory_type()
    {
        let prior: u64 = kani::any();
        let new: u64 = kani::any();
        let kept = PTE_PBMT_MASK | PTE_GRANT_WRITE | PTE_GRANT_EXECUTE;
        let grant = user_leaf_grant(prior);
        let exceeds = (new & PTE_WRITE != 0 && !grant.writable)
            || (new & PTE_EXECUTE != 0 && !grant.executable);
        match protected_leaf(prior, new)
        {
            Ok(leaf) =>
            {
                assert!(!exceeds);
                assert!(leaf & PTE_WRITE == 0 || grant.writable);
                assert!(leaf & PTE_EXECUTE == 0 || grant.executable);
                assert_eq!(leaf & kept, prior & kept);
                assert_eq!(leaf & !kept, new & !kept);
            }
            Err(e) => assert!(exceeds && e == PagingError::NotGranted),
        }
    }

    /// Reads a harness gives `seed_word`.
    const READS: usize = 4;

    /// A word is built only from four `ES16` reads, its 16-bit lanes their
    /// samples in read order; `DEAD` is reported at the first `DEAD` read,
    /// and a timeout at a not-ready read on which the budget is spent. The
    /// reads are any `READS` values, so four `ES16` reads and every early
    /// end among them are covered, each read being judged alone.
    ///
    /// The budget is spent at every ask: a not-ready read with budget left
    /// runs `core::hint::spin_loop`, an x86_64 `pause` on the host, which Kani
    /// cannot compile, and then the same read again, which the unit tests
    /// cover. The loops run at most `READS` reads, so an unwind bound of
    /// `READS + 1` covers them.
    #[kani::proof]
    #[kani::unwind(5)]
    fn a_seed_word_holds_four_es16_samples_in_read_order()
    {
        let values: [u64; READS] = kani::any();
        let reads = Cell::new(0usize);
        let asked = Cell::new(0usize);
        let result = seed_word(
            || {
                let i = reads.get();
                reads.set(i + 1);
                values[i]
            },
            || {
                asked.set(asked.get() + 1);
                true
            },
        );
        let read = reads.get();
        let mut word = 0u64;
        for (lane, &value) in values.iter().take(read).enumerate()
        {
            let last = lane + 1 == read;
            match opst(value)
            {
                0b10 => word |= (value & 0xFFFF) << (16 * lane),
                0b11 => assert!(last && result == Err(SeedError::Dead)),
                _ => assert!(last && result == Err(SeedError::TimedOut) && asked.get() == 1),
            }
        }
        if result.is_err()
        {
            assert!(read > 0 && opst(values[read - 1]) != 0b10);
        }
        if let Ok(built) = result
        {
            assert!(read == READS && built == word && asked.get() == 0);
        }
    }
}
