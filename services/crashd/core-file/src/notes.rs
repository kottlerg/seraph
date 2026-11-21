// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/crashd/core-file/src/notes.rs

//! The `PT_NOTE` contents of a core: one `NT_PRPSINFO`, an `NT_AUXV` when
//! the image's header was read, and for each thread, the faulting one first,
//! an `NT_PRSTATUS` followed by its floating-point and vector state. The
//! layouts are Linux's, which host `gdb` reads: it takes a thread's state
//! from the notes after its `NT_PRSTATUS`, and the first thread as the one
//! the core stopped in.

use alloc::vec::Vec;

use syscall_abi::{
    EXT_REGS_RISCV64_FCSR_OFFSET, EXT_REGS_RISCV64_V0_OFFSET, EXT_REGS_RISCV64_VCSR_OFFSET,
    EXT_REGS_RISCV64_VL_OFFSET, EXT_REGS_RISCV64_VSTART_OFFSET, EXT_REGS_RISCV64_VTYPE_OFFSET,
    EXT_REGS_X86_64_XCR0, FAULT_EXC_ALIGNMENT, FAULT_EXC_BREAKPOINT, FAULT_EXC_DEBUG,
    FAULT_EXC_DIVIDE, FAULT_EXC_FP, FAULT_EXC_ILLEGAL_INSTRUCTION, FAULT_EXC_OVERFLOW,
};

use crate::{Machine, pad_to, put_u32, put_u64};

/// `NT_PRSTATUS`: a thread's signal and general registers.
pub const NT_PRSTATUS: u32 = 1;
/// `NT_FPREGSET` (`NT_PRFPREG`): a thread's floating-point registers.
pub const NT_FPREGSET: u32 = 2;
/// `NT_PRPSINFO`: the process's name.
pub const NT_PRPSINFO: u32 = 3;
/// `NT_AUXV`: the auxiliary vector, from which `gdb` relocates a
/// position-independent image.
pub const NT_AUXV: u32 = 6;
/// `NT_X86_XSTATE`: a thread's XSAVE area.
pub const NT_X86_XSTATE: u32 = 0x202;
/// `NT_RISCV_VECTOR`: a thread's vector registers.
pub const NT_RISCV_VECTOR: u32 = 0x901;

/// Signal numbers `NT_PRSTATUS` reports the fault as, Linux's.
const SIGILL: u16 = 4;
const SIGTRAP: u16 = 5;
const SIGBUS: u16 = 7;
const SIGFPE: u16 = 8;
const SIGSEGV: u16 = 11;

/// Bytes of the FXSAVE region at the start of the x86-64 image, the
/// `NT_FPREGSET` contents.
const FXSAVE_BYTES: usize = 512;
/// Offset in the XSAVE area of the software-reserved word `gdb` reads the
/// area's XCR0 from.
const XSTATE_XCR0_OFFSET: usize = 464;
/// Bytes of the riscv64 `NT_FPREGSET`: `f0`-`f31`, then `fcsr` in a
/// doubleword.
const RISCV_FPREGSET_BYTES: usize = 264;
/// Vector registers of riscv64.
const RISCV_VREGS: usize = 32;

/// Bytes of the `elf_prstatus` fields before `pr_reg`.
const PRSTATUS_HEAD: usize = 112;
/// Bytes of `pr_fname` and `pr_psargs` in `elf_prpsinfo`.
const PSINFO_FNAME: usize = 16;
const PSINFO_PSARGS: usize = 80;

/// `AT_*` keys of the auxiliary vector.
const AT_NULL: u64 = 0;
const AT_PHDR: u64 = 3;
const AT_PHENT: u64 = 4;
const AT_PHNUM: u64 = 5;
const AT_ENTRY: u64 = 9;

/// Why the core was written: the fault the process died of, as the fault
/// message gives it, or a live process's capture.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cause
{
    /// A live process captured by `SNAPSHOT`: no signal, so `gdb` reports
    /// no termination.
    Live,
    /// A page fault the pager forwarded.
    Vm,
    /// An exception of the normalized class (`FAULT_EXC_*`).
    Exception(u64),
}

impl Cause
{
    /// The signal Linux would have delivered for the fault, which `gdb`
    /// reports the core as terminated by; 0 for a live process.
    #[must_use]
    pub fn signal(self) -> u16
    {
        match self
        {
            Self::Live => 0,
            Self::Vm => SIGSEGV,
            Self::Exception(class) => match class
            {
                FAULT_EXC_ILLEGAL_INSTRUCTION => SIGILL,
                FAULT_EXC_BREAKPOINT | FAULT_EXC_DEBUG => SIGTRAP,
                FAULT_EXC_DIVIDE | FAULT_EXC_OVERFLOW | FAULT_EXC_FP => SIGFPE,
                FAULT_EXC_ALIGNMENT => SIGBUS,
                // Bound range, access, protection, and a class unknown here.
                _ => SIGSEGV,
            },
        }
    }
}

/// The image's placement, from its ELF header as mapped at the load bias:
/// what `NT_AUXV` reports so `gdb` relocates the executable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Auxv
{
    /// The program headers' address.
    pub phdr: u64,
    /// Bytes of one program header.
    pub phent: u64,
    /// Program headers.
    pub phnum: u64,
    /// The entry point's address.
    pub entry: u64,
}

impl Auxv
{
    /// The placement of the image whose ELF header is `header`, loaded at
    /// `bias`; `None` when `header` is not a 64-bit little-endian ELF header.
    #[must_use]
    pub fn from_header(header: &[u8], bias: u64) -> Option<Self>
    {
        if header.get(..4)? != b"\x7fELF" || header.get(4)? != &2 || header.get(5)? != &1
        {
            return None;
        }
        let entry = word(header, 24)?;
        let phoff = word(header, 32)?;
        let phent = u64::from(half(header, 54)?);
        let phnum = u64::from(half(header, 56)?);
        Some(Self {
            phdr: bias.checked_add(phoff)?,
            phent,
            phnum,
            entry: bias.checked_add(entry)?,
        })
    }
}

/// The process a core describes.
#[derive(Clone, Copy, Debug)]
pub struct Process<'a>
{
    /// The process's id in the notes: its badge's low 32 bits.
    pub pid: u32,
    /// Its name, the first string of its argv.
    pub name: &'a [u8],
    /// Why the core was written.
    pub cause: Cause,
    /// Its image's placement, when its ELF header was read.
    pub auxv: Option<Auxv>,
}

/// One thread's state, as `SYS_THREAD_READ_REGS` and
/// `SYS_THREAD_READ_EXT_REGS` return it.
#[derive(Clone, Copy, Debug)]
pub struct Thread<'a>
{
    /// The thread's id in the notes, unique within the core and nonzero.
    pub tid: u32,
    /// The register file.
    pub regs: &'a [u8],
    /// The extended-state image; empty when it could not be read.
    pub ext: &'a [u8],
}

/// The `PT_NOTE` contents for `process` and its `threads`, the faulting
/// thread first, on `machine`.
#[must_use]
pub fn encode(machine: Machine, process: &Process<'_>, threads: &[Thread<'_>]) -> Vec<u8>
{
    let mut out = Vec::new();
    note(&mut out, b"CORE", NT_PRPSINFO, &psinfo(process));
    if let Some(auxv) = process.auxv
    {
        note(&mut out, b"CORE", NT_AUXV, &auxv_desc(auxv));
    }
    for (index, thread) in threads.iter().enumerate()
    {
        let signal = if index == 0
        {
            process.cause.signal()
        }
        else
        {
            0
        };
        let fp = fpregset(machine, thread.ext);
        note(
            &mut out,
            b"CORE",
            NT_PRSTATUS,
            &prstatus(machine, process.pid, thread, signal, fp.is_some()),
        );
        if let Some(fp) = fp
        {
            note(&mut out, b"CORE", NT_FPREGSET, &fp);
        }
        if let Some((kind, desc)) = extended(machine, thread.ext)
        {
            note(&mut out, b"LINUX", kind, &desc);
        }
    }
    out
}

/// Append one note: its name and descriptor, each padded to 4 bytes.
fn note(out: &mut Vec<u8>, name: &[u8], kind: u32, desc: &[u8])
{
    // A name and a descriptor this module builds are far below 4 GiB.
    put_u32(
        out,
        u32::try_from(name.len().saturating_add(1)).unwrap_or(u32::MAX),
    );
    put_u32(out, u32::try_from(desc.len()).unwrap_or(u32::MAX));
    put_u32(out, kind);
    out.extend_from_slice(name);
    out.push(0);
    pad_to(out, 4);
    out.extend_from_slice(desc);
    pad_to(out, 4);
}

/// `elf_prstatus`: the signal, the ids, the general registers in
/// `user_regs_struct` (x86-64) or `pc`, `x1`-`x31` (riscv64) order, and
/// whether floating-point state follows.
#[expect(
    clippy::fn_params_excessive_bools,
    reason = "fp_valid is the value written as pr_fpvalid"
)]
fn prstatus(machine: Machine, pid: u32, thread: &Thread<'_>, signal: u16, fp_valid: bool)
-> Vec<u8>
{
    let mut out = Vec::new();
    put_u32(&mut out, u32::from(signal));
    put_u32(&mut out, 0);
    put_u32(&mut out, 0);
    out.extend_from_slice(&signal.to_le_bytes());
    out.resize(32, 0);
    put_u32(&mut out, thread.tid);
    put_u32(&mut out, 0);
    put_u32(&mut out, pid);
    put_u32(&mut out, pid);
    out.resize(PRSTATUS_HEAD, 0);
    for value in general_registers(machine, thread.regs)
    {
        put_u64(&mut out, value);
    }
    put_u32(&mut out, u32::from(fp_valid));
    pad_to(&mut out, 8);
    out
}

/// The general registers in the order Linux's `pr_reg` holds them, from the
/// register file's (`TrapFrame`) order; a word the file lacks reads 0.
fn general_registers(machine: Machine, regs: &[u8]) -> Vec<u64>
{
    let at = |index: usize| {
        index
            .checked_mul(8)
            .and_then(|offset| word(regs, offset))
            .unwrap_or(0)
    };
    match machine
    {
        Machine::X86_64 =>
        {
            // The file: rax rbx rcx rdx rsi rdi rbp r8-r15 rip rflags rsp cs ss fs_base.
            // pr_reg: r15 r14 r13 r12 rbp rbx r11 r10 r9 r8 rax rcx rdx rsi rdi
            // orig_rax rip cs eflags rsp ss fs_base gs_base ds es fs gs.
            let mut out: Vec<u64> = [14, 13, 12, 11, 6, 1, 10, 9, 8, 7, 0, 2, 3, 4, 5]
                .into_iter()
                .map(at)
                .collect();
            // orig_rax: -1, no syscall to restart.
            out.push(u64::MAX);
            out.extend([15, 18, 16, 17, 19, 20].into_iter().map(at));
            // gs_base, ds, es, fs, gs: not in the file.
            out.extend([0; 5]);
            out
        }
        Machine::Riscv64 =>
        {
            // The file: x1-x31, then sepc. pr_reg: pc, then x1-x31.
            let mut out = Vec::with_capacity(32);
            out.push(at(31));
            out.extend((0..31).map(at));
            out
        }
    }
}

/// `NT_FPREGSET`'s descriptor from the extended image; `None` when the image
/// is too short to hold it.
fn fpregset(machine: Machine, ext: &[u8]) -> Option<Vec<u8>>
{
    match machine
    {
        Machine::X86_64 => ext.get(..FXSAVE_BYTES).map(<[u8]>::to_vec),
        Machine::Riscv64 =>
        {
            let fcsr_end = EXT_REGS_RISCV64_FCSR_OFFSET.checked_add(4)?;
            let mut out = ext.get(..fcsr_end)?.to_vec();
            out.resize(RISCV_FPREGSET_BYTES, 0);
            Some(out)
        }
    }
}

/// The vector-state note's type and descriptor; `None` when the image holds
/// no such state.
fn extended(machine: Machine, ext: &[u8]) -> Option<(u32, Vec<u8>)>
{
    match machine
    {
        Machine::X86_64 =>
        {
            // The kernel saves the XSAVE area for EXT_REGS_X86_64_XCR0; gdb
            // reads which components it holds from the software-reserved word.
            if ext.len() <= FXSAVE_BYTES
            {
                return None;
            }
            let mut out = ext.to_vec();
            let end = XSTATE_XCR0_OFFSET.checked_add(8)?;
            out.get_mut(XSTATE_XCR0_OFFSET..end)?
                .copy_from_slice(&EXT_REGS_X86_64_XCR0.to_le_bytes());
            Some((NT_X86_XSTATE, out))
        }
        Machine::Riscv64 =>
        {
            let vregs = ext.get(EXT_REGS_RISCV64_V0_OFFSET..)?;
            let vlenb = vregs.len().checked_div(RISCV_VREGS)?;
            if vlenb == 0
            {
                return None;
            }
            let mut out = Vec::new();
            for offset in [
                EXT_REGS_RISCV64_VSTART_OFFSET,
                EXT_REGS_RISCV64_VL_OFFSET,
                EXT_REGS_RISCV64_VTYPE_OFFSET,
                EXT_REGS_RISCV64_VCSR_OFFSET,
            ]
            {
                put_u64(&mut out, word(ext, offset)?);
            }
            put_u64(&mut out, u64::try_from(vlenb).ok()?);
            out.extend_from_slice(vregs);
            Some((NT_RISCV_VECTOR, out))
        }
    }
}

/// `elf_prpsinfo`: the state, the ids, and the name as `pr_fname` (its
/// last path component) and `pr_psargs`.
fn psinfo(process: &Process<'_>) -> Vec<u8>
{
    let mut out = Vec::new();
    // pr_state 0, pr_sname 'R', pr_zomb 0, pr_nice 0, then pr_flag.
    out.extend_from_slice(&[0, b'R', 0, 0]);
    out.resize(24, 0);
    put_u32(&mut out, process.pid);
    out.resize(40, 0);
    let base = process
        .name
        .rsplit(|&b| b == b'/')
        .next()
        .unwrap_or(process.name);
    fixed(&mut out, base, PSINFO_FNAME);
    fixed(&mut out, process.name, PSINFO_PSARGS);
    out
}

/// Append `text` in a field of `len` bytes, cut to leave a terminating NUL.
fn fixed(out: &mut Vec<u8>, text: &[u8], len: usize)
{
    let kept = text.get(..len.saturating_sub(1)).unwrap_or(text);
    out.extend_from_slice(kept);
    out.resize(out.len().saturating_add(len.saturating_sub(kept.len())), 0);
}

/// `NT_AUXV`'s descriptor: key and value pairs ending in `AT_NULL`.
fn auxv_desc(auxv: Auxv) -> Vec<u8>
{
    let mut out = Vec::new();
    for (key, value) in [
        (AT_PHDR, auxv.phdr),
        (AT_PHENT, auxv.phent),
        (AT_PHNUM, auxv.phnum),
        (AT_ENTRY, auxv.entry),
        (AT_NULL, 0),
    ]
    {
        put_u64(&mut out, key);
        put_u64(&mut out, value);
    }
    out
}

/// The little-endian doubleword of `bytes` at `offset`.
fn word(bytes: &[u8], offset: usize) -> Option<u64>
{
    let end = offset.checked_add(8)?;
    let mut value = [0u8; 8];
    value.copy_from_slice(bytes.get(offset..end)?);
    Some(u64::from_le_bytes(value))
}

/// The little-endian halfword of `bytes` at `offset`.
fn half(bytes: &[u8], offset: usize) -> Option<u16>
{
    let end = offset.checked_add(2)?;
    let mut value = [0u8; 2];
    value.copy_from_slice(bytes.get(offset..end)?);
    Some(u16::from_le_bytes(value))
}

#[cfg(test)]
mod tests
{
    use super::*;

    /// The notes of `bytes`: name, type, descriptor.
    fn parse(bytes: &[u8]) -> Vec<(Vec<u8>, u32, Vec<u8>)>
    {
        let mut out = Vec::new();
        let mut at = 0;
        let u32_at = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap()) as usize;
        while at < bytes.len()
        {
            let (namesz, descsz, kind) = (
                u32_at(at),
                u32_at(at + 4),
                u32::try_from(u32_at(at + 8)).unwrap(),
            );
            let name = bytes[at + 12..at + 12 + namesz - 1].to_vec();
            let desc_at = at + 12 + namesz.div_ceil(4) * 4;
            out.push((name, kind, bytes[desc_at..desc_at + descsz].to_vec()));
            at = desc_at + descsz.div_ceil(4) * 4;
        }
        out
    }

    fn u64_at(bytes: &[u8], at: usize) -> u64
    {
        u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
    }

    /// A register file whose word `i` holds `base + i`.
    fn regs(words: usize, base: u64) -> Vec<u8>
    {
        (0..words as u64)
            .flat_map(|i| (base + i).to_le_bytes())
            .collect()
    }

    fn process(name: &[u8]) -> Process<'_>
    {
        Process {
            pid: 7,
            name,
            cause: Cause::Vm,
            auxv: None,
        }
    }

    #[test]
    fn x86_64_threads_carry_linux_prstatus_then_their_fp_and_xsave_state()
    {
        let file = regs(21, 0x100);
        let mut ext = vec![0xaau8; 832];
        ext[464..472].copy_from_slice(&[0; 8]);
        let threads = [
            Thread {
                tid: 1,
                regs: &file,
                ext: &ext,
            },
            Thread {
                tid: 2,
                regs: &file,
                ext: &[],
            },
        ];
        let notes = parse(&encode(Machine::X86_64, &process(b"svc"), &threads));
        let kinds: Vec<u32> = notes.iter().map(|n| n.1).collect();
        assert_eq!(
            kinds,
            [
                NT_PRPSINFO,
                NT_PRSTATUS,
                NT_FPREGSET,
                NT_X86_XSTATE,
                NT_PRSTATUS
            ]
        );
        let first = &notes[1].2;
        assert_eq!(
            first.len(),
            336,
            "bfd reads an x86-64 elf_prstatus of 336 bytes"
        );
        assert_eq!(u32::from_le_bytes(first[0..4].try_into().unwrap()), 11);
        assert_eq!(u16::from_le_bytes(first[12..14].try_into().unwrap()), 11);
        assert_eq!(u32::from_le_bytes(first[32..36].try_into().unwrap()), 1);
        // pr_reg: r15 first, rax at 10, orig_rax -1 at 15, rip at 16, cs at 17,
        // eflags at 18, rsp at 19, ss at 20, fs_base at 21.
        let reg = |i: usize| u64_at(first, 112 + 8 * i);
        assert_eq!(
            [
                reg(0),
                reg(10),
                reg(15),
                reg(16),
                reg(17),
                reg(18),
                reg(19),
                reg(20),
                reg(21)
            ],
            [
                0x10e,
                0x100,
                u64::MAX,
                0x10f,
                0x112,
                0x110,
                0x111,
                0x113,
                0x114
            ]
        );
        assert_eq!(u32::from_le_bytes(first[328..332].try_into().unwrap()), 1);
        assert_eq!(notes[2].2, ext[..512]);
        assert_eq!(notes[3].0, b"LINUX");
        assert_eq!(u64_at(&notes[3].2, 464), EXT_REGS_X86_64_XCR0);
        // The second thread: no signal, no floating-point state.
        let second = &notes[4].2;
        assert_eq!(u16::from_le_bytes(second[12..14].try_into().unwrap()), 0);
        assert_eq!(u32::from_le_bytes(second[328..332].try_into().unwrap()), 0);
    }

    #[test]
    fn riscv64_threads_carry_pc_first_then_fp_and_vector_state()
    {
        let file = regs(35, 0x200);
        let vlenb = 16;
        let mut ext: Vec<u8> = (0..EXT_REGS_RISCV64_V0_OFFSET + 32 * vlenb)
            .map(|i| u8::try_from(i % 251).unwrap())
            .collect();
        ext[EXT_REGS_RISCV64_VL_OFFSET..EXT_REGS_RISCV64_VL_OFFSET + 8]
            .copy_from_slice(&9u64.to_le_bytes());
        let threads = [Thread {
            tid: 3,
            regs: &file,
            ext: &ext,
        }];
        let notes = parse(&encode(Machine::Riscv64, &process(b"svc"), &threads));
        let kinds: Vec<u32> = notes.iter().map(|n| n.1).collect();
        assert_eq!(
            kinds,
            [NT_PRPSINFO, NT_PRSTATUS, NT_FPREGSET, NT_RISCV_VECTOR]
        );
        let status = &notes[1].2;
        assert_eq!(
            status.len(),
            376,
            "bfd reads a riscv64 elf_prstatus of 376 bytes"
        );
        // pc is sepc (word 31), then x1 (word 0) through x31 (word 30).
        assert_eq!(u64_at(status, 112), 0x200 + 31);
        assert_eq!(u64_at(status, 120), 0x200);
        assert_eq!(u64_at(status, 112 + 8 * 31), 0x200 + 30);
        let fp = &notes[2].2;
        assert_eq!(fp.len(), 264);
        assert_eq!(fp[..260], ext[..260]);
        assert_eq!(fp[260..], [0; 4]);
        let vector = &notes[3].2;
        assert_eq!(u64_at(vector, 8), 9, "vl");
        assert_eq!(u64_at(vector, 32), vlenb as u64, "vlenb");
        assert_eq!(vector[40..], ext[EXT_REGS_RISCV64_V0_OFFSET..]);
    }

    #[test]
    fn a_riscv64_image_without_vector_registers_has_no_vector_note()
    {
        let file = regs(35, 0);
        let ext = vec![0u8; EXT_REGS_RISCV64_V0_OFFSET];
        let threads = [Thread {
            tid: 1,
            regs: &file,
            ext: &ext,
        }];
        let notes = parse(&encode(Machine::Riscv64, &process(b"svc"), &threads));
        assert!(notes.iter().all(|n| n.1 != NT_RISCV_VECTOR));
        assert!(notes.iter().any(|n| n.1 == NT_FPREGSET));
    }

    #[test]
    fn the_fault_maps_to_the_signal_linux_would_have_sent()
    {
        assert_eq!(Cause::Live.signal(), 0);
        assert_eq!(Cause::Vm.signal(), SIGSEGV);
        assert_eq!(
            Cause::Exception(FAULT_EXC_ILLEGAL_INSTRUCTION).signal(),
            SIGILL
        );
        assert_eq!(Cause::Exception(FAULT_EXC_BREAKPOINT).signal(), SIGTRAP);
        assert_eq!(Cause::Exception(FAULT_EXC_DIVIDE).signal(), SIGFPE);
        assert_eq!(Cause::Exception(FAULT_EXC_ALIGNMENT).signal(), SIGBUS);
        assert_eq!(
            Cause::Exception(syscall_abi::FAULT_EXC_PROTECTION).signal(),
            SIGSEGV
        );
        assert_eq!(
            Cause::Exception(syscall_abi::FAULT_EXC_UNKNOWN).signal(),
            SIGSEGV
        );
    }

    #[test]
    fn the_auxv_relocates_the_header_by_the_load_bias()
    {
        let mut header = vec![0u8; 64];
        header[..6].copy_from_slice(b"\x7fELF\x02\x01");
        header[24..32].copy_from_slice(&0x1234u64.to_le_bytes());
        header[32..40].copy_from_slice(&64u64.to_le_bytes());
        header[54..56].copy_from_slice(&56u16.to_le_bytes());
        header[56..58].copy_from_slice(&9u16.to_le_bytes());
        let auxv = Auxv::from_header(&header, 0x4000_0000).unwrap();
        assert_eq!(
            auxv,
            Auxv {
                phdr: 0x4000_0040,
                phent: 56,
                phnum: 9,
                entry: 0x4000_1234
            }
        );
        let notes = parse(&encode(
            Machine::X86_64,
            &Process {
                auxv: Some(auxv),
                ..process(b"svc")
            },
            &[],
        ));
        let desc = &notes[1].2;
        assert_eq!(notes[1].1, NT_AUXV);
        assert_eq!(
            (u64_at(desc, 48), u64_at(desc, 56)),
            (AT_ENTRY, 0x4000_1234)
        );
        assert_eq!((u64_at(desc, 64), u64_at(desc, 72)), (AT_NULL, 0));
        header[0] = 0;
        assert_eq!(Auxv::from_header(&header, 0), None);
        assert_eq!(Auxv::from_header(b"\x7fELF", 0), None);
    }

    #[test]
    fn psinfo_names_the_process_by_its_last_path_component_cut_to_fit()
    {
        let notes = parse(&encode(
            Machine::X86_64,
            &process(b"/programs/a-rather-long-program-name"),
            &[],
        ));
        let desc = &notes[0].2;
        assert_eq!(
            desc.len(),
            136,
            "bfd reads a 64-bit elf_prpsinfo of 136 bytes"
        );
        assert_eq!(&desc[40..56], b"a-rather-long-p\0");
        assert!(desc[56..].starts_with(b"/programs/a-rather-long-program-name\0"));
    }
}
