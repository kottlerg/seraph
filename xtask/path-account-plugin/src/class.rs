// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/path-account-plugin/src/class.rs

//! What an instruction is to the recorder, read from its bytes: a read of the
//! cycle counter, an instruction that traps by design, an instruction of a
//! unit the kernel can turn off, or any other.

/// A guest architecture the recorder knows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Arch
{
    /// `x86_64`.
    X86_64,
    /// `riscv64`.
    Riscv64,
}

impl Arch
{
    /// The architecture QEMU names `target` (`qemu_info_t::target_name`).
    #[must_use]
    pub fn from_target(target: &str) -> Option<Self>
    {
        match target
        {
            "x86_64" => Some(Self::X86_64),
            "riscv64" => Some(Self::Riscv64),
            _ => None,
        }
    }

    /// The name QEMU gives the architecture, which the record's header carries.
    #[must_use]
    pub const fn name(self) -> &'static str
    {
        match self
        {
            Self::X86_64 => "x86_64",
            Self::Riscv64 => "riscv64",
        }
    }
}

/// Where a counter read leaves the value it read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dest
{
    /// `rdtsc`: the low half in EAX, the high half in EDX.
    EdxEax,
    /// `csrr rd, cycle`: general register `x<rd>`.
    Gpr(u8),
}

/// A unit of the processor that the kernel can turn off for a thread, so
/// that the thread's first instruction of the unit traps and the kernel turns
/// it on (the kernel switches the units' state lazily).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unit
{
    /// x86-64's x87, MMX, SSE and AVX state: off while `CR0.TS` or `CR0.EM`
    /// is set.
    X86Fpu,
    /// riscv64's floating-point unit: off while `sstatus.FS` is 0.
    Fp,
    /// riscv64's vector unit: off while `sstatus.VS` is 0.
    Vector,
    /// Both of riscv64's: a vector floating-point instruction.
    VectorFp,
}

impl Unit
{
    /// The register, by the name QEMU gives it, whose bits say whether the
    /// unit is off.
    #[must_use]
    pub const fn state_register(self) -> &'static str
    {
        match self
        {
            Self::X86Fpu => "cr0",
            Self::Fp | Self::Vector | Self::VectorFp => "sstatus",
        }
    }

    /// Whether an instruction of the unit is refused in `state`, the value of
    /// [`Unit::state_register`] when the instruction trapped: a unit it needs
    /// is off.
    #[must_use]
    pub const fn off(self, state: u64) -> bool
    {
        /// `CR0.TS` and `CR0.EM`.
        const TS_EM: u64 = (1 << 3) | (1 << 2);
        /// `sstatus.FS` and `sstatus.VS`.
        const FS: u64 = 3 << 13;
        const VS: u64 = 3 << 9;
        let fs_off = state & FS == 0;
        let vs_off = state & VS == 0;
        match self
        {
            Self::X86Fpu => state & TS_EM != 0,
            Self::Fp => fs_off,
            Self::Vector => vs_off,
            Self::VectorFp => fs_off || vs_off,
        }
    }
}

/// An instruction's class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class
{
    /// An instruction that is none of the others.
    Plain,
    /// An instruction that traps by design (a system call, a breakpoint): it
    /// retires, so the trap it raises does not interrupt it.
    Trap,
    /// An instruction of a unit the kernel can turn off.
    Unit(Unit),
    /// A read of the cycle counter: `rdtsc`, or `csrr rd, cycle`.
    Read(Dest),
    /// An x86-64 `rep` string instruction, and the memory accesses each of
    /// its iterations makes: it runs once per iteration, and an interrupt
    /// between two iterations is reported from its own address.
    RepString(u8),
}

/// The class of the instruction whose bytes `bytes` starts with, on `arch`.
#[must_use]
pub fn classify(arch: Arch, bytes: &[u8]) -> Class
{
    match arch
    {
        Arch::X86_64 => match bytes
        {
            [0x0f, 0x31, ..] => Class::Read(Dest::EdxEax),
            // syscall, sysenter, int3, int imm8, int1.
            [0x0f, 0x05 | 0x34, ..] | [0xcc | 0xcd | 0xf1, ..] => Class::Trap,
            _ if x86_fpu(bytes) => Class::Unit(Unit::X86Fpu),
            _ => x86_rep_string(bytes).map_or(Class::Plain, Class::RepString),
        },
        Arch::Riscv64 => match bytes
        {
            // c.ebreak.
            [0x02, 0x90, ..] => Class::Trap,
            [b0, b1, b2, b3, ..] if b0 & 3 == 3 =>
            {
                let word = u32::from_le_bytes([*b0, *b1, *b2, *b3]);
                match word
                {
                    // ecall, ebreak.
                    0x0000_0073 | 0x0010_0073 => Class::Trap,
                    // csrrs rd, cycle (0xc00), x0.
                    w if w & 0xffff_f07f == 0xc000_2073 => u8::try_from((w >> 7) & 31)
                        .map_or(Class::Plain, |rd| Class::Read(Dest::Gpr(rd))),
                    w => riscv_unit(w).map_or(Class::Plain, Class::Unit),
                }
            }
            // c.fld, c.fsd (quadrant 0), c.fldsp, c.fsdsp (quadrant 2).
            [b0, b1, ..] if matches!(b0 & 3, 0 | 2) && matches!(b1 >> 5, 1 | 5) =>
            {
                Class::Unit(Unit::Fp)
            }
            _ => Class::Plain,
        },
    }
}

/// The memory accesses of one iteration of the x86-64 instruction `bytes`
/// starts with when it is a `rep`, `repe` or `repne` string instruction
/// (`movs` and `cmps` two, `stos`, `lods` and `scas` one), after any
/// legacy prefix and REX; `None` for any other instruction.
fn x86_rep_string(bytes: &[u8]) -> Option<u8>
{
    let mut rest = bytes;
    let mut rep = false;
    while let [
        prefix @ (0x26 | 0x2e | 0x36 | 0x3e | 0x64 | 0x65 | 0x66 | 0x67 | 0xf0 | 0xf2 | 0xf3),
        tail @ ..,
    ] = rest
    {
        rep |= matches!(prefix, 0xf2 | 0xf3);
        rest = tail;
    }
    if let [0x40..=0x4f, tail @ ..] = rest
    {
        rest = tail;
    }
    match rest
    {
        [0xa4..=0xa7, ..] if rep => Some(2),
        [0xaa..=0xaf, ..] if rep => Some(1),
        _ => None,
    }
}

/// Whether the x86-64 instruction `bytes` starts with uses the x87, MMX, SSE
/// or AVX state: an x87 escape, a VEX or EVEX instruction other than the
/// general-purpose ones of BMI1 and BMI2 (the `0x0f38` map's `0xf0..=0xf7`
/// and the `0x0f3a` map's `0xf0`, which never raise `#NM`), or a `0x0f`
/// opcode of the MMX and SSE maps other than `invept`, `invvpid` and
/// `invpcid` (`fxsave`, `fxrstor`, `ldmxcsr`,
/// `stmxcsr`, `xsave` and `xrstor` among the `0x0f 0xae` group), after
/// any legacy prefix and REX.
fn x86_fpu(bytes: &[u8]) -> bool
{
    let mut rest = bytes;
    while let [
        0x26 | 0x2e | 0x36 | 0x3e | 0x64 | 0x65 | 0x66 | 0x67 | 0xf0 | 0xf2 | 0xf3,
        tail @ ..,
    ] = rest
    {
        rest = tail;
    }
    if let [0x40..=0x4f, tail @ ..] = rest
    {
        rest = tail;
    }
    match rest
    {
        // A three-byte VEX prefix names its map in its second byte's low five
        // bits (2: 0x0f38, 3: 0x0f3a); the two-byte one implies 0x0f.
        [0xc4, map, _, op, ..] => !matches!((map & 0x1f, op), (2, 0xf0..=0xf7) | (3, 0xf0)),
        [0xd8..=0xdf | 0xc4 | 0xc5 | 0x62, ..] => true,
        // The 0x38 map less invept, invvpid and invpcid (0x80..=0x82), and
        // movbe, crc32 and the BMI and ADX opcodes (0xf0 and above).
        [0x0f, 0x38, op, ..] => *op < 0xf0 && !matches!(op, 0x80..=0x82),
        [0x0f, 0xae, modrm, ..] => modrm >> 6 != 3 && (modrm >> 3) & 7 <= 5,
        [0x0f, op, ..] => matches!(
            op,
            0x0e | 0x10..=0x17 | 0x28..=0x2f | 0x3a | 0x50..=0x7f | 0xc2 | 0xc4..=0xc6 | 0xd0..=0xff
        ),
        _ => false,
    }
}

/// The unit the riscv64 instruction `word` needs, of those the kernel can
/// turn off: the vector opcode (its floating-point forms need both units), the
/// floating-point loads and stores, whose widths 1 to 4 are scalar and the
/// others vector, and the floating-point and fused multiply-add opcodes.
const fn riscv_unit(word: u32) -> Option<Unit>
{
    let funct3 = (word >> 12) & 7;
    match (word & 0x7f, funct3)
    {
        // OP-V: OPFVV and OPFVF are floating-point.
        (0x57, 1 | 5) => Some(Unit::VectorFp),
        // LOAD-FP and STORE-FP at a scalar width; OP-FP, MADD, MSUB, NMSUB,
        // NMADD.
        (0x07 | 0x27, 1..=4) | (0x53 | 0x43 | 0x47 | 0x4b | 0x4f, _) => Some(Unit::Fp),
        // OP-V; LOAD-FP and STORE-FP at a vector width.
        (0x57 | 0x07 | 0x27, _) => Some(Unit::Vector),
        _ => None,
    }
}

/// Whether `pc` is in the lower, user, half of the address space on both
/// architectures (the kernel's half has the top bit set).
#[must_use]
pub const fn user_half(pc: u64) -> bool
{
    pc >> 63 == 0
}

#[cfg(test)]
mod tests
{
    use super::{Arch, Class, Dest, Unit, classify, user_half};

    #[test]
    fn x86_64_reads_traps_and_others()
    {
        let c = |b: &[u8]| classify(Arch::X86_64, b);
        assert_eq!(c(&[0x0f, 0x31]), Class::Read(Dest::EdxEax));
        assert_eq!(c(&[0x0f, 0x05]), Class::Trap);
        assert_eq!(c(&[0x0f, 0x34]), Class::Trap);
        assert_eq!(c(&[0xcc]), Class::Trap);
        assert_eq!(c(&[0xcd, 0x80]), Class::Trap);
        // rep stosb, rep movsq, repne scasb; a movsb without rep.
        assert_eq!(c(&[0xf3, 0xaa]), Class::RepString(1));
        assert_eq!(c(&[0xf3, 0x48, 0xa5]), Class::RepString(2));
        assert_eq!(c(&[0xf2, 0xae]), Class::RepString(1));
        assert_eq!(c(&[0xa4]), Class::Plain);
        assert_eq!(c(&[0x0f, 0x01, 0xf9]), Class::Plain);
        assert_eq!(c(&[0x48, 0x89, 0xc3]), Class::Plain);
        assert_eq!(c(&[0x0f]), Class::Plain);
        assert_eq!(c(&[]), Class::Plain);
    }

    #[test]
    fn riscv64_reads_traps_and_others()
    {
        let c = |w: u32| classify(Arch::Riscv64, &w.to_le_bytes());
        // csrr a0, cycle; csrr t1, cycle.
        assert_eq!(c(0xc000_2573), Class::Read(Dest::Gpr(10)));
        assert_eq!(c(0xc000_2373), Class::Read(Dest::Gpr(6)));
        // csrr a0, time (0xc01) and csrr a0, instret (0xc02) are not cycle reads.
        assert_eq!(c(0xc010_2573), Class::Plain);
        assert_eq!(c(0xc020_2573), Class::Plain);
        // csrrs a0, cycle, a1 writes the counter's bits: not a plain read.
        assert_eq!(c(0xc005_a573), Class::Plain);
        assert_eq!(c(0x0000_0073), Class::Trap);
        assert_eq!(c(0x0010_0073), Class::Trap);
        assert_eq!(classify(Arch::Riscv64, &[0x02, 0x90]), Class::Trap);
        // c.addi a0, 1 is compressed: never read as a word.
        assert_eq!(
            classify(Arch::Riscv64, &[0x05, 0x05, 0x73, 0x00]),
            Class::Plain
        );
        assert_eq!(c(0x0000_0013), Class::Plain);
    }

    #[test]
    fn x86_64_fpu_instructions_are_of_the_unit()
    {
        let c = |b: &[u8]| classify(Arch::X86_64, b);
        let fpu = Class::Unit(Unit::X86Fpu);
        // movaps xmm0, [rdi]; movdqu xmm1, [rsi] (f3 0f 6f); movq xmm0, rax
        // (66 48 0f 6e c0); vmovdqu ymm0, [rsi] (c5 fe 6f 06); fld st(0).
        assert_eq!(c(&[0x0f, 0x28, 0x07]), fpu);
        assert_eq!(c(&[0xf3, 0x0f, 0x6f, 0x0e]), fpu);
        assert_eq!(c(&[0x66, 0x48, 0x0f, 0x6e, 0xc0]), fpu);
        assert_eq!(c(&[0xc5, 0xfe, 0x6f, 0x06]), fpu);
        assert_eq!(c(&[0xd9, 0xc0]), fpu);
        // fxsave [rdi] (0f ae /0) is; lfence (0f ae e8) is not.
        assert_eq!(c(&[0x0f, 0xae, 0x07]), fpu);
        assert_eq!(c(&[0x0f, 0xae, 0xe8]), Class::Plain);
        // movbe eax, [rdi] (0f 38 f0) and popcnt (f3 0f b8) are not.
        assert_eq!(c(&[0x0f, 0x38, 0xf0, 0x07]), Class::Plain);
        // invpcid rax, [rdi] (66 0f 38 82 07) is not; pshufb xmm0, [rdi]
        // (66 0f 38 00 07) is.
        assert_eq!(c(&[0x66, 0x0f, 0x38, 0x82, 0x07]), Class::Plain);
        assert_eq!(c(&[0x66, 0x0f, 0x38, 0x00, 0x07]), fpu);
        assert_eq!(c(&[0xf3, 0x0f, 0xb8, 0xc0]), Class::Plain);
        // The VEX general-purpose instructions are not: andn eax, ebx, [rdi]
        // (c4 e2 60 f2 07), pdep (c4 e2 63 f5 07), shlx (c4 e2 61 f7 07), and
        // rorx eax, [rdi], 5 (c4 e3 7b f0 07 05). vbroadcastss ymm0, [rsi]
        // (c4 e2 7d 18 06) and vpermq (c4 e3 fd 00 06 1b) are.
        assert_eq!(c(&[0xc4, 0xe2, 0x60, 0xf2, 0x07]), Class::Plain);
        assert_eq!(c(&[0xc4, 0xe2, 0x63, 0xf5, 0x07]), Class::Plain);
        assert_eq!(c(&[0xc4, 0xe2, 0x61, 0xf7, 0x07]), Class::Plain);
        assert_eq!(c(&[0xc4, 0xe3, 0x7b, 0xf0, 0x07, 0x05]), Class::Plain);
        assert_eq!(c(&[0xc4, 0xe2, 0x7d, 0x18, 0x06]), fpu);
        assert_eq!(c(&[0xc4, 0xe3, 0xfd, 0x00, 0x06, 0x1b]), fpu);
    }

    #[test]
    fn riscv64_fp_and_vector_instructions_are_of_their_units()
    {
        let c = |w: u32| classify(Arch::Riscv64, &w.to_le_bytes());
        // vsetivli zero, 2, e64, m1, ta, ma; vl1re64.v v8, (a4); vse64.v v8, (a0).
        assert_eq!(c(0xcd81_7057), Class::Unit(Unit::Vector));
        assert_eq!(c(0x0287_7407), Class::Unit(Unit::Vector));
        assert_eq!(c(0x0205_7427), Class::Unit(Unit::Vector));
        // vfadd.vv v8, v8, v9 (OPFVV).
        assert_eq!(c(0x0284_9457), Class::Unit(Unit::VectorFp));
        // fld fa0, 0(a0); fadd.d fa0, fa0, fa1; fmadd.d.
        assert_eq!(c(0x0005_3507), Class::Unit(Unit::Fp));
        assert_eq!(c(0x02b5_7553), Class::Unit(Unit::Fp));
        assert_eq!(c(0x6ab5_7543), Class::Unit(Unit::Fp));
        // c.fldsp fa0, 0(sp) (0x2502); c.fld fa0, 0(a0) (0x2108).
        assert_eq!(
            classify(Arch::Riscv64, &[0x02, 0x25]),
            Class::Unit(Unit::Fp)
        );
        assert_eq!(
            classify(Arch::Riscv64, &[0x08, 0x21]),
            Class::Unit(Unit::Fp)
        );
        // csrr a1, vlenb is a CSR read, checked when it runs: plain.
        assert_eq!(c(0xc220_25f3), Class::Plain);
        // c.ld a0, 0(a0) (0x6108) is not FP.
        assert_eq!(classify(Arch::Riscv64, &[0x08, 0x61]), Class::Plain);
    }

    #[test]
    fn a_unit_is_off_by_its_state_register()
    {
        assert!(Unit::X86Fpu.off(0x8000_0033 | (1 << 3)));
        assert!(!Unit::X86Fpu.off(0x8000_0033));
        // sstatus: FS bits 14:13, VS bits 10:9.
        let fs_on = 1 << 13;
        let vs_on = 1 << 9;
        assert!(Unit::Vector.off(fs_on));
        assert!(!Unit::Vector.off(vs_on));
        assert!(Unit::Fp.off(vs_on));
        assert!(!Unit::Fp.off(fs_on | vs_on));
        assert!(Unit::VectorFp.off(vs_on));
        assert!(!Unit::VectorFp.off(fs_on | vs_on));
    }

    #[test]
    fn the_user_half_is_the_top_bit_clear()
    {
        assert!(user_half(0x0000_7fff_ffff_ffff));
        assert!(user_half(0x36_e721_e000));
        assert!(!user_half(0xffff_ffff_8000_0000));
        assert!(!user_half(0xffff_ffc0_0000_0000));
    }

    #[test]
    fn target_names_round_trip()
    {
        for arch in [Arch::X86_64, Arch::Riscv64]
        {
            assert_eq!(Arch::from_target(arch.name()), Some(arch));
        }
        assert_eq!(Arch::from_target("aarch64"), None);
    }
}
