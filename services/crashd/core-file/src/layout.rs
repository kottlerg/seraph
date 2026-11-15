// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/crashd/core-file/src/layout.rs

//! The core file's layout: the ELF header, one `PT_NOTE`, one `PT_LOAD` per
//! page run, and which runs' bytes the per-core byte budget holds.
//!
//! The file is the header, the program headers and the notes, padded to a
//! page, then the bytes of each kept run in program-header order. A run left
//! out, by the budget or because the kernel refuses to copy its pages
//! (`PAGE_RUN_NO_COPY`), keeps its `PT_LOAD` with no file bytes, so the core
//! still shows the mapping.

use alloc::vec::Vec;

use syscall_abi::{PAGE_RUN_EXECUTE, PAGE_RUN_NO_COPY, PAGE_RUN_READ, PAGE_RUN_WRITE, PAGE_SIZE};

use crate::{Machine, pad_to, put_u16, put_u32, put_u64};

/// Bytes of the ELF header.
const EHDR_BYTES: u64 = 64;
/// Bytes of one program header.
const PHDR_BYTES: u64 = 56;
/// `ET_CORE`.
const ET_CORE: u16 = 4;
/// `EM_X86_64`, `EM_RISCV`.
const EM_X86_64: u16 = 62;
const EM_RISCV: u16 = 243;
/// `PT_LOAD`, `PT_NOTE`.
const PT_LOAD: u32 = 1;
const PT_NOTE: u32 = 4;
/// `PF_X`, `PF_W`, `PF_R`.
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;

/// Most `PT_LOAD` headers a core carries: `e_phnum` is 16 bits, and the
/// `PN_XNUM` extension is not written. Runs past it are not recorded.
pub const MAX_LOADS: usize = 0xfffe;

/// One run of mapped pages with one protection, as `SYS_THREAD_LIST_PAGES`
/// reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Run
{
    /// The first page's address.
    pub va: u64,
    /// Pages in the run.
    pub pages: u64,
    /// `PAGE_RUN_*` bits.
    pub prot: u64,
}

impl Run
{
    /// The run's bytes; saturating, as no run reaches 2^64 bytes.
    fn bytes(&self) -> u64
    {
        self.pages.saturating_mul(PAGE_SIZE)
    }

    /// Whether `addr` lies in the run.
    fn holds(&self, addr: u64) -> bool
    {
        addr.checked_sub(self.va)
            .is_some_and(|into| into < self.bytes())
    }
}

/// One `PT_LOAD` the file carries, and where its bytes go.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Load
{
    /// The run.
    pub run: Run,
    /// Where its bytes start in the file.
    pub offset: u64,
    /// Bytes of it the file holds: the run's, or 0 when it is left out.
    pub file_bytes: u64,
}

/// A core's layout.
#[derive(Debug, PartialEq, Eq)]
pub struct Core
{
    /// The file's first bytes: the ELF header, the program headers, the
    /// notes, padded to a page.
    pub head: Vec<u8>,
    /// The `PT_LOAD`s, in the runs' order.
    pub loads: Vec<Load>,
    /// The file's size.
    pub size: u64,
}

/// Why a core cannot be laid out within the budget.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LayoutError
{
    /// The header, program headers and notes alone exceed the budget.
    HeadOverBudget,
}

/// Lay out the core of `runs` (in address order) with `notes` on `machine`,
/// within `budget` bytes. The runs holding an address of `first` (the fault's
/// instruction pointer, each thread's stack pointer) are kept first, in that
/// order, then the others in address order; each run is kept whole when it
/// fits what the budget leaves, and left out otherwise.
///
/// # Errors
///
/// [`LayoutError::HeadOverBudget`] when no page bytes would fit at all
/// because the head alone exceeds `budget`.
pub fn plan(
    machine: Machine,
    notes: &[u8],
    runs: &[Run],
    first: &[u64],
    budget: u64,
) -> Result<Core, LayoutError>
{
    let runs = runs.get(..MAX_LOADS).unwrap_or(runs);
    let head_bytes = head_size(notes, runs.len());
    let Some(mut left) = budget.checked_sub(head_bytes)
    else
    {
        return Err(LayoutError::HeadOverBudget);
    };
    let mut kept = alloc::vec![false; runs.len()];
    let order = first
        .iter()
        .filter_map(|&addr| runs.iter().position(|run| run.holds(addr)))
        .chain(0..runs.len());
    for index in order
    {
        let (Some(run), Some(keep)) = (runs.get(index), kept.get_mut(index))
        else
        {
            continue;
        };
        if *keep || run.prot & PAGE_RUN_NO_COPY != 0 || run.bytes() > left
        {
            continue;
        }
        *keep = true;
        left = left.saturating_sub(run.bytes());
    }

    let mut loads = Vec::with_capacity(runs.len());
    let mut offset = head_bytes;
    for (run, keep) in runs.iter().zip(kept)
    {
        let file_bytes = if keep { run.bytes() } else { 0 };
        loads.push(Load {
            run: *run,
            offset,
            file_bytes,
        });
        offset = offset.saturating_add(file_bytes);
    }
    let head = head(machine, notes, &loads);
    Ok(Core {
        head,
        loads,
        size: offset,
    })
}

/// Bytes of the head for `runs` loads and `notes`: the headers and the notes,
/// rounded up to a page.
fn head_size(notes: &[u8], runs: usize) -> u64
{
    let phdrs = u64::try_from(runs).unwrap_or(u64::MAX).saturating_add(1);
    let raw = EHDR_BYTES
        .saturating_add(phdrs.saturating_mul(PHDR_BYTES))
        .saturating_add(u64::try_from(notes.len()).unwrap_or(u64::MAX));
    raw.div_ceil(PAGE_SIZE).saturating_mul(PAGE_SIZE)
}

/// The head's bytes: the ELF header, the `PT_NOTE` header, a `PT_LOAD` header
/// per load, the notes, and zeros to the page.
fn head(machine: Machine, notes: &[u8], loads: &[Load]) -> Vec<u8>
{
    let mut out = Vec::new();
    let phnum = u16::try_from(loads.len().saturating_add(1)).unwrap_or(u16::MAX);
    out.extend_from_slice(b"\x7fELF");
    // ELFCLASS64, ELFDATA2LSB, EV_CURRENT, ELFOSABI_NONE, then padding.
    out.extend_from_slice(&[2, 1, 1, 0]);
    out.resize(16, 0);
    put_u16(&mut out, ET_CORE);
    put_u16(
        &mut out,
        match machine
        {
            Machine::X86_64 => EM_X86_64,
            Machine::Riscv64 => EM_RISCV,
        },
    );
    put_u32(&mut out, 1);
    // e_entry, e_phoff, e_shoff.
    put_u64(&mut out, 0);
    put_u64(&mut out, EHDR_BYTES);
    put_u64(&mut out, 0);
    // e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx.
    put_u32(&mut out, 0);
    put_u16(&mut out, 64);
    put_u16(&mut out, 56);
    put_u16(&mut out, phnum);
    put_u16(&mut out, 0);
    put_u16(&mut out, 0);
    put_u16(&mut out, 0);

    let notes_offset = EHDR_BYTES.saturating_add(u64::from(phnum).saturating_mul(PHDR_BYTES));
    let notes_bytes = u64::try_from(notes.len()).unwrap_or(u64::MAX);
    phdr(
        &mut out,
        PT_NOTE,
        0,
        notes_offset,
        0,
        notes_bytes,
        notes_bytes,
        4,
    );
    for load in loads
    {
        phdr(
            &mut out,
            PT_LOAD,
            flags(load.run.prot),
            load.offset,
            load.run.va,
            load.file_bytes,
            load.run.bytes(),
            PAGE_SIZE,
        );
    }
    out.extend_from_slice(notes);
    pad_to(&mut out, usize::try_from(PAGE_SIZE).unwrap_or(1));
    out
}

/// Append one program header.
#[expect(
    clippy::too_many_arguments,
    reason = "the eight fields of Elf64_Phdr, written in order"
)]
fn phdr(
    out: &mut Vec<u8>,
    kind: u32,
    flags: u32,
    offset: u64,
    vaddr: u64,
    file_bytes: u64,
    mem_bytes: u64,
    align: u64,
)
{
    put_u32(out, kind);
    put_u32(out, flags);
    put_u64(out, offset);
    put_u64(out, vaddr);
    put_u64(out, 0);
    put_u64(out, file_bytes);
    put_u64(out, mem_bytes);
    put_u64(out, align);
}

/// `p_flags` from a run's `PAGE_RUN_*` bits.
fn flags(prot: u64) -> u32
{
    let mut out = 0;
    if prot & PAGE_RUN_READ != 0
    {
        out |= PF_R;
    }
    if prot & PAGE_RUN_WRITE != 0
    {
        out |= PF_W;
    }
    if prot & PAGE_RUN_EXECUTE != 0
    {
        out |= PF_X;
    }
    out
}

#[cfg(test)]
mod tests
{
    use super::*;

    const PAGE: u64 = PAGE_SIZE;
    const RW: u64 = PAGE_RUN_READ | PAGE_RUN_WRITE;
    const RX: u64 = PAGE_RUN_READ | PAGE_RUN_EXECUTE;

    fn run(va: u64, pages: u64, prot: u64) -> Run
    {
        Run { va, pages, prot }
    }

    fn u16_at(bytes: &[u8], at: usize) -> u16
    {
        u16::from_le_bytes(bytes[at..at + 2].try_into().unwrap())
    }

    fn u32_at(bytes: &[u8], at: usize) -> u32
    {
        u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
    }

    fn u64_at(bytes: &[u8], at: usize) -> u64
    {
        u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
    }

    #[test]
    fn the_head_describes_the_notes_and_each_run_with_its_protection()
    {
        let notes = [0x5au8; 20];
        let runs = [
            run(0x1000, 2, RX),
            run(0x8000, 1, RW),
            run(0xf000, 1, RW | PAGE_RUN_NO_COPY),
        ];
        let core = plan(Machine::Riscv64, &notes, &runs, &[], u64::MAX).unwrap();
        let head = &core.head;
        assert_eq!(head.len() as u64, PAGE);
        assert_eq!(&head[..4], b"\x7fELF");
        assert_eq!((u16_at(head, 16), u16_at(head, 18)), (ET_CORE, EM_RISCV));
        assert_eq!(u16_at(head, 56), 4, "a PT_NOTE and three PT_LOADs");
        // PT_NOTE, then the notes right after the program headers.
        let note_at = 64 + 4 * 56;
        assert_eq!(u32_at(head, 64), PT_NOTE);
        assert_eq!((u64_at(head, 72), u64_at(head, 96)), (note_at as u64, 20));
        assert_eq!(head[note_at..note_at + 20], notes);
        // Each PT_LOAD: flags, offset, vaddr, filesz, memsz.
        let load = |i: usize| {
            let at = 64 + 56 * (i + 1);
            (
                u32_at(head, at + 4),
                u64_at(head, at + 8),
                u64_at(head, at + 16),
                u64_at(head, at + 32),
                u64_at(head, at + 40),
            )
        };
        assert_eq!(load(0), (PF_R | PF_X, PAGE, 0x1000, 2 * PAGE, 2 * PAGE));
        assert_eq!(load(1), (PF_R | PF_W, 3 * PAGE, 0x8000, PAGE, PAGE));
        // A run the kernel will not copy is recorded with no bytes.
        assert_eq!(load(2), (PF_R | PF_W, 4 * PAGE, 0xf000, 0, PAGE));
        assert_eq!(core.size, 4 * PAGE);
    }

    #[test]
    fn the_budget_keeps_the_runs_at_the_given_addresses_first_then_what_fits()
    {
        let runs = [
            run(0x1000, 4, RW),
            run(0x10000, 1, RX),
            run(0x20000, 2, RW),
            run(0x30000, 1, RW),
        ];
        // Head (one page) plus four pages: the stack run at 0x20000 is kept
        // first, the 4-page run no longer fits, the two 1-page runs do.
        let core = plan(Machine::X86_64, &[], &runs, &[0x20ff8], 5 * PAGE).unwrap();
        let kept: Vec<u64> = core.loads.iter().map(|l| l.file_bytes / PAGE).collect();
        assert_eq!(kept, [0, 1, 2, 1]);
        assert!(core.size <= 5 * PAGE);
        // The file bytes follow the head in program-header order.
        let offsets: Vec<u64> = core.loads.iter().map(|l| l.offset / PAGE).collect();
        assert_eq!(offsets, [1, 1, 2, 4]);
    }

    #[test]
    fn a_head_over_the_budget_is_refused()
    {
        let runs = [run(0x1000, 1, RW)];
        assert_eq!(
            plan(Machine::X86_64, &[0; 64], &runs, &[], PAGE - 1),
            Err(LayoutError::HeadOverBudget)
        );
        // Exactly the head: every run recorded, none with bytes.
        let core = plan(Machine::X86_64, &[0; 64], &runs, &[], PAGE).unwrap();
        assert_eq!(core.loads[0].file_bytes, 0);
    }

    #[test]
    fn runs_past_the_program_header_limit_are_not_recorded()
    {
        let runs: Vec<Run> = (0..MAX_LOADS as u64 + 3)
            .map(|i| run(i * 2 * PAGE, 1, RW | PAGE_RUN_NO_COPY))
            .collect();
        let core = plan(Machine::X86_64, &[], &runs, &[], u64::MAX).unwrap();
        assert_eq!(core.loads.len(), MAX_LOADS);
        assert_eq!(u16_at(&core.head, 56), 0xffff);
    }
}
