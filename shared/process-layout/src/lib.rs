// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/process-layout/src/lib.rs

//! Per-process bootstrap virtual-address layout.
//!
//! A process creator (procmgr for general processes, init for memmgr/procmgr)
//! must place four bootstrap surfaces in a new process's address space before
//! it runs: the `ProcessInfo` handover page, the main-thread stack, the
//! main-thread TLS block, and the main-thread IPC buffer. This crate owns the
//! choice of where those surfaces go, so the decision lives in one place rather
//! than being pinned as ABI constants in `process-abi`.
//!
//! The creator is the chooser: it calls [`choose_process_layout`] once per
//! process and writes the chosen VAs into the handover surface
//! (`ProcessInfo.stack_top_vaddr`, `ProcessInfo.main_tls_vaddr`,
//! `ProcessInfo.ipc_buffer_vaddr`) and into the entry register that delivers the
//! `ProcessInfo` page address. The created process reads them back from the
//! struct and the register — it does not assume any fixed address.
//!
//! [`choose_process_layout`] is deterministic: it returns the same VAs every
//! time. It is the single seam where per-process randomisation (ASLR, #39) will
//! substitute an entropy draw for the constants below, mirroring the
//! deterministic-first reservation arena in
//! `runtime/ruststd/src/sys/reserve/seraph.rs`.

#![no_std]

/// Default `ProcessInfo` handover-page virtual address.
pub const DEFAULT_PROCESS_INFO_VA: u64 = 0x0000_7FFF_FFFF_0000;

/// Default top of the main-thread user stack. `stack_pages` pages are mapped
/// immediately below this, with one unmapped guard page beneath them.
pub const DEFAULT_STACK_TOP: u64 = 0x0000_7FFF_FFFF_E000;

/// Default base (region start) of the main-thread IPC buffer.
pub const DEFAULT_IPC_BUFFER_VA: u64 = 0x0000_7FFF_FFFE_0000;

/// Default base (region start) of the main-thread TLS block.
pub const DEFAULT_MAIN_TLS_VA: u64 = 0x0000_7FFF_FFFD_0000;

/// The bootstrap virtual addresses for one new process.
///
/// Page counts are not part of the layout: the stack size comes from the
/// binary's `.note.seraph.stack` ELF note and the TLS block size from its
/// `PT_TLS` segment, both resolved by the creator. This struct carries only the
/// base addresses the creator places those regions at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessLayout
{
    /// Virtual address of the read-only `ProcessInfo` handover page. Delivered
    /// to the new process in its entry register (`rdi`/`a0`), not stored in the
    /// struct (which would be circular — the process needs this to find it).
    pub process_info_va: u64,
    /// Top of the main-thread user stack; written to `ProcessInfo.stack_top_vaddr`
    /// and passed as the initial stack pointer.
    pub stack_top: u64,
    /// Base of the main-thread TLS block; written to `ProcessInfo.main_tls_vaddr`
    /// (when the process has a `PT_TLS` segment) and used to derive the thread
    /// pointer.
    pub tls_base: u64,
    /// Base of the main-thread IPC buffer; written to `ProcessInfo.ipc_buffer_vaddr`.
    pub ipc_buffer_va: u64,
}

/// Choose the bootstrap VA layout for a new process.
///
/// Deterministic: returns the `DEFAULT_*` addresses above. This is the single
/// seam ASLR (#39) replaces with a per-process entropy draw.
#[must_use]
pub fn choose_process_layout() -> ProcessLayout
{
    ProcessLayout {
        process_info_va: DEFAULT_PROCESS_INFO_VA,
        stack_top: DEFAULT_STACK_TOP,
        tls_base: DEFAULT_MAIN_TLS_VA,
        ipc_buffer_va: DEFAULT_IPC_BUFFER_VA,
    }
}
