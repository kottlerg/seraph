// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/arch/riscv64/encoding.rs

//! RISC-V register-map and instruction-encoding arithmetic: the APLIC source
//! modes and MSI targets, the IMSIC identity range and its EID rows, the
//! routed-source word, the SBI hart-mask window, page
//! rounding, the F/D/V opcode decode the lazy extended-state trap uses, the
//! PTE permission bits and their test in the kernel's spurious-fault retry,
//! and the user leaf's grant bits and the permission change they bound.
//!
//! Pure functions of their arguments with no dependency on the rest of the
//! arch module. `arch/mod.rs` also compiles this file into host test builds
//! of the other architectures, so `cargo xtask test` (run on an `x86_64`
//! host) runs its tests.

use crate::mm::paging::{LeafGrant, PagingError};

/// Largest APLIC interrupt source the RISC-V Advanced Interrupt Architecture
/// allows (sources 1..=1023; source 0 is reserved).
pub(super) const APLIC_MAX_SOURCES: u32 = 1023;

/// Smallest APLIC domain register window: the 16 KiB that hold `domaincfg`,
/// every `sourcecfg`, the enable and pending registers, and every `target`
/// (`target[1023]` ends at 0x4000). A reported window below it is refused.
pub(super) const APLIC_MIN_WINDOW: u64 = 0x4000;

/// Fewest interrupt identities an IMSIC interrupt file implements (AIA
/// specification: identities `1..=ids`, `ids` from 63 to 2047).
pub(super) const IMSIC_MIN_IDS: u32 = 63;

/// Most interrupt identities an IMSIC interrupt file implements.
pub(super) const IMSIC_MAX_IDS: u32 = 2047;

/// Largest hart index an APLIC `target` register holds in MSI delivery mode:
/// its Hart Index field is bits 31:18, 14 bits wide.
pub(super) const APLIC_MAX_HART_INDEX: u32 = (1 << 14) - 1;

/// The source count of an APLIC domain reporting `reported` sources: the report
/// when it lies in `1..=APLIC_MAX_SOURCES`, else `None` (no domain, or a count
/// the specification does not admit; the boot refuses either).
pub(super) fn aplic_sources_for(reported: u64) -> Option<u32>
{
    match u32::try_from(reported)
    {
        Ok(n) if (1..=APLIC_MAX_SOURCES).contains(&n) => Some(n),
        _ => None,
    }
}

/// Whether an IMSIC file of `ids` interrupt identities lies in the range the
/// AIA specification admits.
pub(super) const fn imsic_ids_valid(ids: u32) -> bool
{
    ids >= IMSIC_MIN_IDS && ids <= IMSIC_MAX_IDS
}

/// APLIC `sourcecfg` source mode for a `SYS_IRQ_REGISTER` trigger and polarity
/// word (`IRQ_MODE_LEVEL`, `IRQ_MODE_ACTIVE_LOW` in `abi/syscall`; a word with
/// other bits is refused before this is reached): Edge1 (4) for a rising edge,
/// Edge0 (5) for a falling edge, Level1 (6) for active-high, Level0 (7) for
/// active-low.
pub(super) fn aplic_source_mode(mode: u32) -> u32
{
    let level = u64::from(mode) & syscall::IRQ_MODE_LEVEL != 0;
    let low = u64::from(mode) & syscall::IRQ_MODE_ACTIVE_LOW != 0;
    match (level, low)
    {
        (false, false) => 4,
        (false, true) => 5,
        (true, false) => 6,
        (true, true) => 7,
    }
}

/// Whether an APLIC source mode is level-sensitive (Level1 or Level0).
pub(super) const fn aplic_mode_is_level(source_mode: u32) -> bool
{
    source_mode == 6 || source_mode == 7
}

/// The APLIC `target` register value, in MSI delivery mode, that forwards a
/// source as identity `eid` to the supervisor-level file at hart index
/// `hart_index`, guest index 0: `hart_index << 18 | eid`. `None` when the hart
/// index exceeds [`APLIC_MAX_HART_INDEX`], or `eid` is 0 or past
/// [`IMSIC_MAX_IDS`] (the 11-bit EIID field).
pub(super) const fn aplic_msi_target(hart_index: u32, eid: u32) -> Option<u32>
{
    if hart_index > APLIC_MAX_HART_INDEX || eid == 0 || eid > IMSIC_MAX_IDS
    {
        return None;
    }
    Some((hart_index << 18) | eid)
}

/// Number of 64-bit `eip`/`eie` registers covering identities `0..=ids` of an
/// IMSIC file: each holds 64 identities.
pub(super) const fn imsic_reg_words(ids: u32) -> u32
{
    (ids + 1).div_ceil(64)
}

/// The lowest free identity in an EID row (`row[eid]` is 0 when identity
/// `eid` is free; entry 0, the reserved identity 0, is never taken), or `None`
/// when every identity is taken.
pub(super) fn lowest_free_eid(row: &[core::sync::atomic::AtomicU32]) -> Option<u32>
{
    let (index, _) = row
        .iter()
        .enumerate()
        .skip(1)
        .find(|(_, entry)| entry.load(core::sync::atomic::Ordering::Relaxed) == 0)?;
    u32::try_from(index).ok()
}

/// A routed APLIC source: the logical CPU whose IMSIC file it is delivered to,
/// the identity it takes there, and whether it is level-sensitive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct SourceRoute
{
    /// Logical index of the target CPU.
    pub cpu: u32,
    /// The identity the source takes in the target CPU's file.
    pub eid: u32,
    /// Whether the source is level-sensitive, so its unmask re-pends it.
    pub level: bool,
}

/// Bit marking a packed [`SourceRoute`] as routed, so a zero word is unrouted.
const SOURCE_ROUTED: u64 = 1 << 63;

/// Bit holding a packed [`SourceRoute`]'s `level`.
const SOURCE_LEVEL: u64 = 1 << 62;

impl SourceRoute
{
    /// The route packed into one word: the identity in bits 0..=31, the CPU
    /// in bits 32..=61, `level` and the routed mark above them. A CPU index
    /// is below `MAX_CPUS`, which 30 bits hold.
    pub(super) const fn pack(self) -> u64
    {
        let level = if self.level { SOURCE_LEVEL } else { 0 };
        SOURCE_ROUTED | level | ((self.cpu as u64) << 32) | self.eid as u64
    }

    /// The route a word [`Self::pack`] wrote, or `None` for an unrouted (zero)
    /// word.
    pub(super) const fn unpack(word: u64) -> Option<Self>
    {
        if word & SOURCE_ROUTED == 0
        {
            return None;
        }
        // Each field is a u32 `pack` placed in its own bit range.
        #[allow(clippy::cast_possible_truncation)]
        Some(Self {
            cpu: ((word >> 32) & 0x3FFF_FFFF) as u32,
            eid: word as u32,
            level: word & SOURCE_LEVEL != 0,
        })
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

    // Defect caught: a trigger or polarity bit read wrongly, so a level line
    // is programmed as an edge (never re-pended at unmask) or a polarity
    // inverted (a line that interrupts forever, or never).
    #[test]
    fn source_mode_follows_trigger_and_polarity()
    {
        let level = syscall::IRQ_MODE_LEVEL as u32;
        let low = syscall::IRQ_MODE_ACTIVE_LOW as u32;
        assert_eq!(aplic_source_mode(0), 4);
        assert_eq!(aplic_source_mode(low), 5);
        assert_eq!(aplic_source_mode(level), 6);
        assert_eq!(aplic_source_mode(level | low), 7);
        assert!(!aplic_mode_is_level(aplic_source_mode(low)));
        assert!(aplic_mode_is_level(aplic_source_mode(level | low)));
    }

    // Defect caught: a hart index or identity past the target register's
    // fields written into it, which would deliver to another hart or identity.
    #[test]
    fn msi_target_refuses_what_its_fields_cannot_hold()
    {
        assert_eq!(aplic_msi_target(3, 5), Some((3 << 18) | 5));
        assert_eq!(
            aplic_msi_target(APLIC_MAX_HART_INDEX, IMSIC_MAX_IDS),
            Some((APLIC_MAX_HART_INDEX << 18) | IMSIC_MAX_IDS)
        );
        assert_eq!(aplic_msi_target(APLIC_MAX_HART_INDEX + 1, 1), None);
        assert_eq!(aplic_msi_target(0, 0), None);
        assert_eq!(aplic_msi_target(0, IMSIC_MAX_IDS + 1), None);
    }

    // Defect caught: an APLIC source count or IMSIC identity count outside the
    // specification accepted, which would size the routing table or the EID
    // rows past the registers the controllers implement.
    #[test]
    fn controller_counts_outside_the_specification_are_refused()
    {
        assert_eq!(aplic_sources_for(96), Some(96));
        assert_eq!(aplic_sources_for(1023), Some(1023));
        assert_eq!(aplic_sources_for(0), None);
        assert_eq!(aplic_sources_for(1024), None);
        assert!(imsic_ids_valid(63) && imsic_ids_valid(255) && imsic_ids_valid(2047));
        assert!(!imsic_ids_valid(62) && !imsic_ids_valid(2048) && !imsic_ids_valid(0));
    }

    // Defect caught: a register count that misses the file's last identities
    // (left disabled or pending) or writes past its last register.
    #[test]
    fn imsic_registers_cover_every_identity()
    {
        assert_eq!(imsic_reg_words(63), 1);
        assert_eq!(imsic_reg_words(255), 4);
        assert_eq!(imsic_reg_words(2047), 32);
    }

    // Defect caught: identity 0 handed out (the IMSIC reserves it, so the
    // source would never be claimed), a taken identity handed out twice, or
    // a full row not reported.
    #[test]
    fn lowest_free_eid_skips_identity_zero_and_taken_ones()
    {
        use core::sync::atomic::AtomicU32;
        let row: [AtomicU32; 4] = [const { AtomicU32::new(0) }; 4];
        assert_eq!(lowest_free_eid(&row), Some(1));
        row[1].store(10, core::sync::atomic::Ordering::Relaxed);
        row[3].store(11, core::sync::atomic::Ordering::Relaxed);
        assert_eq!(lowest_free_eid(&row), Some(2));
        row[2].store(12, core::sync::atomic::Ordering::Relaxed);
        assert_eq!(lowest_free_eid(&row), None);
    }

    // Defect caught: a field lost or bled into another in the packed word, so
    // an unroute frees the wrong identity or CPU, or an unmask misses the
    // level re-pend; or a zero word read as routed.
    #[test]
    fn source_route_round_trips_and_zero_is_unrouted()
    {
        let route = SourceRoute {
            cpu: 8191,
            eid: IMSIC_MAX_IDS,
            level: true,
        };
        assert_eq!(SourceRoute::unpack(route.pack()), Some(route));
        let edge = SourceRoute {
            cpu: 0,
            eid: 1,
            level: false,
        };
        assert_eq!(SourceRoute::unpack(edge.pack()), Some(edge));
        assert_eq!(SourceRoute::unpack(0), None);
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
        let rx_cap = base | grant_bits(exec);
        assert!(
            user_leaf_flags(protected_leaf(rx_cap, rx).unwrap())
                .unwrap()
                .executable
        );
        assert_eq!(protected_leaf(rx_cap, rw), Err(PagingError::NotGranted));

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
}
