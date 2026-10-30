// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/syscall/src/arch/mod.rs

//! Architecture dispatch module: selects the active architecture's raw syscall
//! wrappers as `current`.
//!
//! This is the only file in this crate permitted to contain
//! `#[cfg(target_arch)]` guards (`docs/coding-standards.md` § C. Architecture
//! Invariants). Every architecture defines the same wrappers: `syscall2` to
//! `syscall6` (primary return only), `syscall5_ret2`, `syscall1_ret4`,
//! `syscall6_ret3`, and `syscall4_any` (every argument register declared
//! clobbered, behind the untyped `raw_syscall3` and `raw_syscall4`).
//!
//! # Safety
//!
//! Every wrapper is an `unsafe fn` with one contract: `nr` must be a syscall
//! number the kernel defines, and the remaining arguments must be that call's
//! arguments, in the order `core/kernel/docs/syscalls.md` gives. Beyond that, the
//! call's effects on memory must leave every live Rust object intact:
//!
//! - a pointer argument must be valid for the access the call's contract specifies;
//! - a call that reads or writes the calling thread's registered IPC buffer page
//!   (`SYS_IPC_CALL` reads it for the request and writes it with the reply,
//!   `SYS_IPC_RECV` writes it, `SYS_IPC_REPLY` reads it) must hold no Rust
//!   reference into that page across the call; the page is the one
//!   `crate::ipc_buffer_set` registered under its own `# Safety`;
//! - a call that changes mappings of the caller's own address space
//!   (`SYS_MEM_MAP`, `SYS_MEM_UNMAP`, `SYS_MEM_PROTECT`, `SYS_MMIO_MAP`) must
//!   change none that a live Rust object or the registered IPC buffer page
//!   occupies;
//! - a call that sets the entry state of a thread of the caller's own address
//!   space (`SYS_THREAD_CONFIGURE`, `SYS_THREAD_WRITE_REGS`) must start or
//!   resume it only on code, a stack, and a TLS block the program dedicates to
//!   that thread.
//!
//! The exception is `syscall4_any`, which accepts any `nr` and arguments under
//! its own `# Safety`. The kernel ABI's register clobbers are declared in each
//! wrapper's asm.

#[cfg(target_arch = "x86_64")]
#[path = "x86_64/mod.rs"]
pub(crate) mod current;

#[cfg(target_arch = "riscv64")]
#[path = "riscv64/mod.rs"]
pub(crate) mod current;
