// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/sys.rs

//! Hand-declared bindings to the host's C library (Unix) and the Windows
//! API, for the operating-system calls xtask makes that std does not wrap.
//!
//! Each item is declared in the one form xtask calls it with, and each
//! constant has the value the host's own headers give it, chosen per host by
//! `cfg`, so no binding crate is needed (`docs/coding-standards.md`
//! § Dependencies). The Unix bindings name every host they hold values for,
//! by `target_os`: `linux` (every architecture, glibc, musl and uClibc), `macos`,
//! `freebsd`, `dragonfly`, `netbsd`, `openbsd`, `illumos` and `solaris`.
//! xtask fails to compile on any other Unix, naming this file, rather than
//! call its C library with a value that may be wrong there.

/// The Unix C library: `signal(2)`, `fcntl(2)`, the terminal attribute and
/// window-size calls, `getloadavg(3)`, and `access(2)`.
#[cfg(unix)]
pub mod unix
{
    use std::ffi::{c_char, c_double, c_int};

    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "illumos",
        target_os = "solaris"
    )))]
    compile_error!(
        "xtask/src/sys.rs holds no C-library values for this Unix host; \
         add them there from the host's headers"
    );

    /// illumos and Solaris, which share the System V terminal interface.
    const SOLARISH: bool = cfg!(any(target_os = "illumos", target_os = "solaris"));

    /// `SIGINT`: 2 on every Unix (Linux on every architecture, macOS, the
    /// BSDs, illumos and Solaris).
    pub const SIGINT: c_int = 2;

    /// `SIG_ERR`: `(sighandler_t)-1` on every Unix.
    pub const SIG_ERR: usize = usize::MAX;

    /// `F_GETFD`: 1 on every host this module names.
    pub const F_GETFD: c_int = 1;

    /// `F_SETFD`: 2 on every host this module names.
    pub const F_SETFD: c_int = 2;

    /// `FD_CLOEXEC`: 1 on every host this module names.
    pub const FD_CLOEXEC: c_int = 1;

    /// `TCSANOW`: `tcsetattr` applies the change at once. 0, except on
    /// illumos and Solaris and under glibc and uClibc on MIPS Linux, which
    /// define it as the `TCSETS` ioctl, `('T' << 8) | 14`.
    pub const TCSANOW: c_int = if SOLARISH
        || cfg!(all(
            target_os = "linux",
            any(target_env = "gnu", target_env = "uclibc"),
            any(
                target_arch = "mips",
                target_arch = "mips64",
                target_arch = "mips32r6",
                target_arch = "mips64r6"
            )
        ))
    {
        0x540e
    }
    else
    {
        0
    };

    /// The type of `ioctl`'s request argument: `int` under musl (`target_env`
    /// `musl` or `ohos`) and on illumos and Solaris, `unsigned long`
    /// everywhere else.
    #[cfg(any(
        target_os = "illumos",
        target_os = "solaris",
        all(target_os = "linux", any(target_env = "musl", target_env = "ohos"))
    ))]
    pub type IoctlRequest = c_int;

    /// The type of `ioctl`'s request argument: `int` under musl (`target_env`
    /// `musl` or `ohos`) and on illumos and Solaris, `unsigned long`
    /// everywhere else.
    #[cfg(not(any(
        target_os = "illumos",
        target_os = "solaris",
        all(target_os = "linux", any(target_env = "musl", target_env = "ohos"))
    )))]
    pub type IoctlRequest = std::ffi::c_ulong;

    /// The request numbered `code` as an `int` request argument, its 32
    /// bits kept as they are: musl's `ioctl` takes `_IOW` requests, whose
    /// top bit is set, as negative `int`s.
    #[cfg(any(
        target_os = "illumos",
        target_os = "solaris",
        all(target_os = "linux", any(target_env = "musl", target_env = "ohos"))
    ))]
    const fn request(code: u32) -> IoctlRequest
    {
        code.cast_signed()
    }

    /// The request numbered `code` as an `unsigned long` request argument.
    #[cfg(not(any(
        target_os = "illumos",
        target_os = "solaris",
        all(target_os = "linux", any(target_env = "musl", target_env = "ohos"))
    )))]
    const fn request(code: u32) -> IoctlRequest
    {
        code as IoctlRequest
    }

    /// The window-size requests of Linux's generic ioctl numbering, which
    /// every Linux architecture but MIPS, PowerPC and SPARC uses.
    #[cfg(all(
        target_os = "linux",
        not(any(
            target_arch = "mips",
            target_arch = "mips64",
            target_arch = "mips32r6",
            target_arch = "mips64r6",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "sparc",
            target_arch = "sparc64"
        ))
    ))]
    mod winsize_requests
    {
        use super::{IoctlRequest, request};

        pub const TIOCGWINSZ: IoctlRequest = request(0x5413);
        pub const TIOCSWINSZ: IoctlRequest = request(0x5414);
    }

    /// The window-size requests of the BSD ioctl encoding,
    /// `_IOR('t', 104, struct winsize)` and `_IOW('t', 103, struct
    /// winsize)`, which macOS, the BSDs, and Linux on MIPS, PowerPC and SPARC
    /// use.
    #[cfg(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "netbsd",
        target_os = "openbsd",
        all(
            target_os = "linux",
            any(
                target_arch = "mips",
                target_arch = "mips64",
                target_arch = "mips32r6",
                target_arch = "mips64r6",
                target_arch = "powerpc",
                target_arch = "powerpc64",
                target_arch = "sparc",
                target_arch = "sparc64"
            )
        )
    ))]
    mod winsize_requests
    {
        use super::{IoctlRequest, request};

        pub const TIOCGWINSZ: IoctlRequest = request(0x4008_7468);
        pub const TIOCSWINSZ: IoctlRequest = request(0x8008_7467);
    }

    /// The window-size requests of illumos and Solaris, `('T' << 8) | 104`
    /// and `('T' << 8) | 103`.
    #[cfg(any(target_os = "illumos", target_os = "solaris"))]
    mod winsize_requests
    {
        use super::{IoctlRequest, request};

        pub const TIOCGWINSZ: IoctlRequest = request(0x5468);
        pub const TIOCSWINSZ: IoctlRequest = request(0x5467);
    }

    /// `TIOCGWINSZ` reads a terminal's window size into a [`Winsize`];
    /// `TIOCSWINSZ` sets it from one.
    pub use winsize_requests::{TIOCGWINSZ, TIOCSWINSZ};

    /// `struct termios`, held opaque. xtask saves a terminal's attributes
    /// and restores them unread, so it needs only storage at least as large
    /// and as aligned as the C library's struct: 256 bytes aligned to 8 hold
    /// it on every host this module names, the largest being macOS's, 72
    /// bytes aligned to 8, and glibc's, 60 bytes aligned to 4.
    #[repr(C, align(8))]
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub struct Termios([u8; 256]);

    impl Termios
    {
        /// Storage for `tcgetattr` to fill.
        pub const fn zeroed() -> Self
        {
            Self([0; 256])
        }
    }

    /// `struct winsize`: four `unsigned short`s on every host this module
    /// names, in this order.
    #[repr(C)]
    #[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
    pub struct Winsize
    {
        /// `ws_row`: rows, in characters.
        pub row: u16,
        /// `ws_col`: columns, in characters.
        pub col: u16,
        /// `ws_xpixel`: width, in pixels.
        pub xpixel: u16,
        /// `ws_ypixel`: height, in pixels.
        pub ypixel: u16,
    }

    unsafe extern "C" {
        /// `signal(2)`. `handler` is declared as the function form xtask
        /// installs (`sighandler_t` is a pointer-sized handler pointer); the
        /// return value is the previous `sighandler_t`, which can also be
        /// `SIG_DFL`, `SIG_IGN` or [`SIG_ERR`], so it is read as an integer.
        pub fn signal(signum: c_int, handler: extern "C" fn(c_int)) -> usize;

        /// `fcntl(2)`, variadic as C declares it: [`F_GETFD`] takes no
        /// third argument, [`F_SETFD`] an `int`.
        pub fn fcntl(fd: c_int, cmd: c_int, ...) -> c_int;

        /// `ioctl(2)`, variadic as C declares it; the window-size requests
        /// take a pointer to a [`Winsize`].
        pub fn ioctl(fd: c_int, request: IoctlRequest, ...) -> c_int;

        /// `tcgetattr(3)`: writes `fd`'s terminal attributes to `termios`.
        pub fn tcgetattr(fd: c_int, termios: *mut Termios) -> c_int;

        /// `tcsetattr(3)`: sets `fd`'s terminal attributes from `termios`,
        /// at the time `optional_actions` ([`TCSANOW`]) names.
        pub fn tcsetattr(fd: c_int, optional_actions: c_int, termios: *const Termios) -> c_int;

        /// `getloadavg(3)`: writes up to `nelem` (at most 3) load
        /// averages to `loadavg` and returns how many it wrote, or -1.
        pub fn getloadavg(loadavg: *mut c_double, nelem: c_int) -> c_int;

        /// `access(2)`: 0 when the calling process may access the file at
        /// `path`, a NUL-terminated string, as `mode` ([`X_OK`]) asks, as
        /// the kernel decides it for the process's ids and groups; else -1.
        pub fn access(path: *const c_char, mode: c_int) -> c_int;
    }

    /// `X_OK`: [`access`]'s test for permission to execute; 1 on every host
    /// this module names.
    pub const X_OK: c_int = 1;
}

/// The Windows API: `SetConsoleCtrlHandler` and the console-mode calls.
#[cfg(windows)]
pub mod windows
{
    use std::ffi::c_void;

    /// `BOOL`.
    pub type Bool = i32;

    /// `TRUE`.
    pub const TRUE: Bool = 1;

    /// `FALSE`.
    pub const FALSE: Bool = 0;

    /// `HANDLE`.
    pub type Handle = *mut c_void;

    /// `INVALID_HANDLE_VALUE`: `(HANDLE)(LONG_PTR)-1`.
    pub const INVALID_HANDLE_VALUE: Handle = std::ptr::without_provenance_mut(usize::MAX);

    /// `STD_INPUT_HANDLE`: `(DWORD)-10`.
    pub const STD_INPUT_HANDLE: u32 = 0xFFFF_FFF6;

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

        /// `GetStdHandle`: the handle of a standard device
        /// ([`STD_INPUT_HANDLE`]); [`INVALID_HANDLE_VALUE`] on failure, and
        /// null when the process has no such handle.
        pub fn GetStdHandle(std_handle: u32) -> Handle;

        /// `GetConsoleMode`: writes a console handle's mode to `mode`.
        /// Returns nonzero on success, and 0 for a handle that is no console.
        pub fn GetConsoleMode(console: Handle, mode: *mut u32) -> Bool;

        /// `SetConsoleMode`: sets a console handle's mode. Returns nonzero on
        /// success.
        pub fn SetConsoleMode(console: Handle, mode: u32) -> Bool;
    }
}
