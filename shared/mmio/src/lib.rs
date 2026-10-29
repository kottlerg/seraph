// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/mmio/src/lib.rs

//! Architecture-specific MMIO ordering primitives.
//!
//! Provides the memory barriers required to correctly sequence accesses to
//! memory-mapped I/O regions on each supported architecture. Device driver
//! code calls these functions by name; the crate selects the correct
//! per-architecture implementation at compile time behind a module boundary,
//! keeping the caller free of `#[cfg(target_arch)]` noise per
//! `docs/coding-standards.md` §C.
//!
//! # What these barriers order
//!
//! - [`dma_to_mmio_barrier`] — flush prior main-memory (DMA) writes before a
//!   subsequent MMIO write. Call this after populating a DMA descriptor ring
//!   and before writing the device's notify/doorbell register.
//!
//! - [`mmio_to_mmio_barrier`] — order two MMIO writes. Call this after every
//!   MMIO write that is part of a sequence the device must observe in program
//!   order (register programming, enable-then-status writes).
//!
//! - [`mmio_to_dma_barrier`] — order a prior MMIO read before a subsequent
//!   main-memory read. Call this after reading a completion/status register
//!   when the memory it gates (e.g. a descriptor's length field) is about to
//!   be read.
//!
//! # Why these are needed on RISC-V
//!
//! On RISC-V (RVWMO), the memory subsystem is permitted to reorder:
//!
//! - main-memory writes vs. I/O-region writes
//! - two I/O-region writes relative to each other
//! - I/O-region reads vs. subsequent main-memory reads
//!
//! Raw `core::ptr::write_volatile` / `read_volatile` compiles to a bare
//! `sw`/`sh`/`sb` / `lw`/`lh`/`lb`; it prevents compiler reordering but does
//! not emit any hardware fence. Without an explicit `fence`, a device
//! emulation (or real device) observer may see writes in a different order
//! than program order.
//!
//! This crate is the direct analogue of Linux's `arch/riscv/include/asm/io.h`
//! `__io_bw` / `__io_aw` / `__io_br` / `__io_ar` barriers used inside
//! `writel()` / `readl()`. Raw `write_volatile` corresponds to
//! `writel_relaxed()` — safe only where the caller supplies the barriers
//! manually, which is what this crate exists to do.
//!
//! # Why these are free on `x86_64`
//!
//! `x86_64` TSO orders all stores from one core in program order, and MMIO
//! mappings created via `SYS_MMIO_MAP` are strong-uncacheable (see
//! `core/kernel/docs/syscalls.md` § `SYS_MMIO_MAP`), which forces serialised
//! access. Each of the barriers in this crate
//! compiles to nothing on `x86_64`; the API exists so arch-neutral driver
//! code can call the barrier unconditionally and pay no cost on TSO
//! architectures.
//!
//! # Adding a new architecture
//!
//! Create `src/arch/<name>/mod.rs` implementing all three barriers and add a
//! `#[cfg(target_arch = "<name>")] #[path = "<name>/mod.rs"] pub mod current;`
//! arm to `src/arch/mod.rs`, following `docs/coding-standards.md` § C
//! (every architecture implements the full surface; a no-op's rustdoc says
//! why).

#![no_std]

mod arch;

pub use arch::current::{dma_to_mmio_barrier, mmio_to_dma_barrier, mmio_to_mmio_barrier};
