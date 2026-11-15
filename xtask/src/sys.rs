// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/sys.rs

//! Hand-declared bindings to the host's C library (Unix) and the Windows
//! API, for the operating-system calls xtask makes that std does not wrap.
//!
//! Each item is declared in the one form xtask calls it with, and each
//! constant has the value it has on every host of its family, so no
//! binding crate is needed (`docs/coding-standards.md` § Dependencies).

/// The Unix C library: `signal(2)`.
#[cfg(unix)]
pub mod unix
{
    use std::ffi::c_int;

    /// `SIGINT`: 2 on every Unix (Linux on every architecture, macOS, the
    /// BSDs, illumos and Solaris).
    pub const SIGINT: c_int = 2;

    /// `SIG_ERR`: `(sighandler_t)-1` on every Unix.
    pub const SIG_ERR: usize = usize::MAX;

    unsafe extern "C" {
        /// `signal(2)`. `handler` is declared as the function form xtask
        /// installs (`sighandler_t` is a pointer-sized handler pointer); the
        /// return value is the previous `sighandler_t`, which can also be
        /// `SIG_DFL`, `SIG_IGN` or [`SIG_ERR`], so it is read as an integer.
        pub fn signal(signum: c_int, handler: extern "C" fn(c_int)) -> usize;
    }
}

/// The Windows API: `SetConsoleCtrlHandler`.
#[cfg(windows)]
pub mod windows
{
    /// `BOOL`.
    pub type Bool = i32;

    /// `TRUE`.
    pub const TRUE: Bool = 1;

    /// `FALSE`.
    pub const FALSE: Bool = 0;

    /// `CTRL_C_EVENT`: Ctrl+C at the console.
    pub const CTRL_C_EVENT: u32 = 0;

    /// `CTRL_BREAK_EVENT`: Ctrl+Break at the console.
    pub const CTRL_BREAK_EVENT: u32 = 1;

    /// `PHANDLER_ROUTINE`: a console control handler, given the event's
    /// code, returning [`TRUE`] when it handled the event.
    pub type HandlerRoutine = Option<unsafe extern "system" fn(u32) -> Bool>;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        /// `SetConsoleCtrlHandler`: adds (`add` [`TRUE`]) or removes
        /// `handler` from the calling process's console control handlers.
        /// Returns nonzero on success.
        pub fn SetConsoleCtrlHandler(handler: HandlerRoutine, add: Bool) -> Bool;
    }
}
