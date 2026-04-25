// seraph-overlay: std::sys::process::seraph
//
// `std::process::Command` for Seraph: spawns the target binary via
// `CREATE_FROM_VFS` to procmgr, binds a death-notification `EventQueue` to
// the child's main thread, starts it, and surfaces `Child::wait` /
// `Child::kill` on top of the resulting caps.
//
// Wire-up:
//   * Spawn: ipc_call(procmgr_endpoint, CREATE_FROM_VFS | path_len<<16,
//            data=[stdio_token, path_words], caps=[creator_endpoint?])
//            Reply caps: [process_handle, thread_for_caller].
//   * Bind death: syscall::thread_bind_notification(thread_cap, event_queue_cap).
//   * Start: ipc_call(process_handle, START_PROCESS, 0, &[]).
//   * Wait: syscall::event_recv(event_queue_cap) — blocks until kernel posts
//           the exit reason on thread exit. Exit reason 0 = clean
//           `SYS_THREAD_EXIT`; 0x1000+vector = fault exit.
//   * Kill: ipc_call(process_handle, DESTROY_PROCESS, 0, &[]) — procmgr
//           revokes + deletes the child's kernel objects; the bound
//           EventQueue is woken with exit reason 0.
//
// Stdio:
//   * `Stdio::Inherit` (default) — child inherits the spawner's stdout/stderr
//     surfaces (procmgr populates the child's stdout/stderr caps from its
//     own log_endpoint at `CREATE_FROM_VFS` time) and has no stdin (zero cap
//     → read returns EOF).
//   * `Stdio::Null` — same as Inherit on the stdout/stderr side; stdin also
//     zero (EOF on read). Redirection to a user-chosen sink is not
//     implemented yet.
//   * `Stdio::MakePipe` — not supported yet; returns `Unsupported`. Pipes
//     require wiring the shared-memory SPSC ring in `shared/shmem` into
//     `ProcessInfo` stdio slots. Until that lands, `Command::output()` and
//     friends that default to `MakePipe` fail.
//
// Identity:
//   * `Process::id()` returns the low 32 bits of procmgr's internal process
//     token (unique, monotonic, nonzero). Not a POSIX pid — processes in
//     Seraph are identified by capability, not pid.
//
// Argv/env:
//   * `Command::arg(...)` accumulates into `self.args`; `Command::env_mut()`
//     tracks into `CommandEnv`. Both are serialised at `spawn` time into the
//     label + data of `CREATE_FROM_VFS` (same encoding as `CREATE_PROCESS`)
//     and end up in the child's `ProcessInfo` page, surfaced via
//     `std::env::{args, vars}` on the child side. Blobs are bounded by
//     `ipc::ARGS_BLOB_MAX` and 8-bit counts; oversize returns
//     `ArgumentListTooLong`.

use crate::ffi::{OsStr, OsString};
pub use crate::ffi::OsString as EnvKey;
use crate::fmt;
use crate::io;
use crate::num::NonZero;
use crate::path::Path;
use crate::process::StdioPipes;
use crate::sys::fs::File;
use crate::sys::unsupported;

use super::CommandEnvs;
use super::env::CommandEnv;

use ipc::{procmgr_errors, procmgr_labels};

// ── Stdio ───────────────────────────────────────────────────────────────────

pub enum Stdio {
    Inherit,
    Null,
    MakePipe,
    ParentStdout,
    ParentStderr,
    #[allow(dead_code)]
    InheritFile(File),
}

impl From<crate::sys::pipe::Pipe> for Stdio {
    fn from(pipe: crate::sys::pipe::Pipe) -> Stdio {
        pipe.diverge()
    }
}

impl From<io::Stdout> for Stdio {
    fn from(_: io::Stdout) -> Stdio {
        Stdio::ParentStdout
    }
}

impl From<io::Stderr> for Stdio {
    fn from(_: io::Stderr) -> Stdio {
        Stdio::ParentStderr
    }
}

impl From<File> for Stdio {
    fn from(file: File) -> Stdio {
        Stdio::InheritFile(file)
    }
}

// ── Command ─────────────────────────────────────────────────────────────────

pub struct Command {
    program: OsString,
    args: Vec<OsString>,
    env: CommandEnv,
    cwd: Option<OsString>,
    stdin: Option<Stdio>,
    stdout: Option<Stdio>,
    stderr: Option<Stdio>,
}

impl Command {
    pub fn new(program: &OsStr) -> Command {
        Command {
            program: program.to_owned(),
            args: vec![program.to_owned()],
            env: Default::default(),
            cwd: None,
            stdin: None,
            stdout: None,
            stderr: None,
        }
    }

    pub fn arg(&mut self, arg: &OsStr) {
        self.args.push(arg.to_owned());
    }

    pub fn env_mut(&mut self) -> &mut CommandEnv {
        &mut self.env
    }

    pub fn cwd(&mut self, dir: &OsStr) {
        self.cwd = Some(dir.to_owned());
    }

    pub fn stdin(&mut self, stdin: Stdio) {
        self.stdin = Some(stdin);
    }

    pub fn stdout(&mut self, stdout: Stdio) {
        self.stdout = Some(stdout);
    }

    pub fn stderr(&mut self, stderr: Stdio) {
        self.stderr = Some(stderr);
    }

    pub fn get_program(&self) -> &OsStr {
        &self.program
    }

    pub fn get_args(&self) -> CommandArgs<'_> {
        let mut iter = self.args.iter();
        iter.next();
        CommandArgs { iter }
    }

    pub fn get_envs(&self) -> CommandEnvs<'_> {
        self.env.iter()
    }

    pub fn get_env_clear(&self) -> bool {
        self.env.does_clear()
    }

    pub fn get_current_dir(&self) -> Option<&Path> {
        self.cwd.as_ref().map(|cs| Path::new(cs))
    }

    pub fn spawn(
        &mut self,
        default: Stdio,
        _needs_stdin: bool,
    ) -> io::Result<(Process, StdioPipes)> {
        // Pipe-backed stdio is not wired yet — see module-level comment.
        let effective_stdin = self.stdin.as_ref().unwrap_or(&default);
        let effective_stdout = self.stdout.as_ref().unwrap_or(&default);
        let effective_stderr = self.stderr.as_ref().unwrap_or(&default);
        if matches!(effective_stdin, Stdio::MakePipe)
            || matches!(effective_stdout, Stdio::MakePipe)
            || matches!(effective_stderr, Stdio::MakePipe)
        {
            return unsupported();
        }

        let info = crate::os::seraph::try_startup_info().ok_or_else(|| {
            io::Error::other("std::process on seraph: startup info not installed")
        })?;
        let procmgr_ep = info.procmgr_endpoint;
        if procmgr_ep == 0 {
            return Err(io::Error::other(
                "std::process on seraph: spawning process has no procmgr endpoint",
            ));
        }

        let path_bytes = self.program.as_encoded_bytes();
        if path_bytes.is_empty() || path_bytes.len() > ipc::MAX_PATH_LEN {
            return Err(io::Error::from(io::ErrorKind::InvalidFilename));
        }

        // Pack argv (NUL-terminated UTF-8 concatenation of self.args).
        let mut args_blob: Vec<u8> = Vec::new();
        for arg in &self.args {
            let bytes = arg.as_encoded_bytes();
            if bytes.iter().any(|&b| b == 0) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "argv contains embedded NUL",
                ));
            }
            args_blob.extend_from_slice(bytes);
            args_blob.push(0);
        }
        if args_blob.len() > ipc::ARGS_BLOB_MAX || self.args.len() > u8::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::ArgumentListTooLong,
                "argv exceeds procmgr limits",
            ));
        }
        let args_count: u32 = self.args.len() as u32;

        // Pack env (NUL-terminated KEY=VALUE concatenation of CommandEnv.capture()).
        let mut env_blob: Vec<u8> = Vec::new();
        let mut env_count_usize: usize = 0;
        for (key, val) in self.env.capture() {
            let key_bytes = key.as_encoded_bytes();
            let val_bytes = val.as_encoded_bytes();
            if key_bytes.iter().any(|&b| b == 0 || b == b'=')
                || val_bytes.iter().any(|&b| b == 0)
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "env contains embedded NUL or '=' in key",
                ));
            }
            env_blob.extend_from_slice(key_bytes);
            env_blob.push(b'=');
            env_blob.extend_from_slice(val_bytes);
            env_blob.push(0);
            env_count_usize += 1;
        }
        if env_blob.len() > ipc::ARGS_BLOB_MAX || env_count_usize > u8::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::ArgumentListTooLong,
                "env exceeds procmgr limits",
            ));
        }
        let env_count: u32 = env_count_usize as u32;

        // SAFETY: `info.ipc_buffer` is the kernel-registered IPC buffer for
        // this thread, installed at `_start` time; page-aligned, u64-aligned,
        // and mapped for the process lifetime.
        let ipc_ptr = info.ipc_buffer as *mut u64;

        let path_len = path_bytes.len().min(ipc::MAX_PATH_LEN);
        let path_words = path_len.div_ceil(8);
        let argv_words = if args_blob.is_empty() {
            0
        } else {
            args_blob.len().div_ceil(8)
        };
        let env_header_words = if env_count > 0 && !env_blob.is_empty() {
            1 + env_blob.len().div_ceil(8)
        } else {
            0
        };

        let argv_word_offset = path_words;
        let env_len_word_offset = argv_word_offset + argv_words;
        let env_blob_word_offset = env_len_word_offset + 1;

        let builder = ipc::IpcMessage::builder(procmgr_labels::CREATE_FROM_VFS
            | ((path_bytes.len() as u64) << 16)
            | ((args_blob.len() as u64) << 32)
            | ((u64::from(args_count)) << 48)
            | ((u64::from(env_count)) << 56))
            .bytes(0, &path_bytes[..path_len]);
        let builder = if !args_blob.is_empty() {
            builder.bytes(argv_word_offset, &args_blob)
        } else {
            builder
        };
        let builder = if env_count > 0 && !env_blob.is_empty() {
            builder
                .word(env_len_word_offset, env_blob.len() as u64)
                .bytes(env_blob_word_offset, &env_blob)
        } else {
            builder
        };
        let total_words = path_words + argv_words + env_header_words;
        // CREATE_FROM_VFS carries no caps for Command-spawned children:
        // creator endpoint is not needed (Command children don't do the
        // bootstrap handshake) and stdio is installed separately below.
        let msg = builder.word_count(total_words).build();

        // SAFETY: `ipc_ptr` is the kernel-registered IPC buffer page for
        // this thread, installed at `_start` time.
        let reply = unsafe { ipc::ipc_call(procmgr_ep, &msg, ipc_ptr) }
            .map_err(|_| io::Error::other("CREATE_FROM_VFS syscall failed"))?;
        if reply.label != procmgr_errors::SUCCESS {
            return Err(map_procmgr_error(reply.label));
        }

        let reply_caps = reply.caps();
        if reply_caps.len() < 2 {
            return Err(io::Error::other(
                "CREATE_FROM_VFS reply missing process_handle or thread cap",
            ));
        }
        let process_handle = reply_caps[0];
        let thread_cap = reply_caps[1];

        // Bind an `EventQueue` to the child's main thread BEFORE start, so a
        // short-lived child cannot exit before the binding lands and leave
        // `wait()` blocked forever.
        let destroy_msg = ipc::IpcMessage::new(procmgr_labels::DESTROY_PROCESS);
        let death_eq = match syscall::event_queue_create(4) {
            Ok(eq) => eq,
            Err(_) => {
                let _ = syscall::cap_delete(thread_cap);
                // SAFETY: `ipc_ptr` is the kernel-registered IPC buffer page.
                let _ = unsafe { ipc::ipc_call(process_handle, &destroy_msg, ipc_ptr) };
                let _ = syscall::cap_delete(process_handle);
                return Err(io::Error::other("event_queue_create for child failed"));
            }
        };
        // Correlator 0: the spawner uses a dedicated per-child EventQueue,
        // so routing is trivial (one thread per queue) and the payload
        // stays equal to `exit_reason`.
        if syscall::thread_bind_notification(thread_cap, death_eq, 0).is_err() {
            let _ = syscall::cap_delete(death_eq);
            let _ = syscall::cap_delete(thread_cap);
            // SAFETY: `ipc_ptr` is the kernel-registered IPC buffer page.
            let _ = unsafe { ipc::ipc_call(process_handle, &destroy_msg, ipc_ptr) };
            let _ = syscall::cap_delete(process_handle);
            return Err(io::Error::other("thread_bind_notification for child failed"));
        }

        // The child has no stdio caps wired by default — `Stdio::piped()`
        // is not yet implemented, and the child reaches the system log
        // through the discovery cap procmgr installs in its
        // `ProcessInfo`. The `CONFIGURE_STDIO` plumbing is preserved for
        // Phase 3, which will route shmem-backed pipes through it.

        // Kick the child off.
        let start_msg = ipc::IpcMessage::new(procmgr_labels::START_PROCESS);
        // SAFETY: `ipc_ptr` is the kernel-registered IPC buffer page.
        let start_reply = unsafe { ipc::ipc_call(process_handle, &start_msg, ipc_ptr) }
            .map_err(|_| io::Error::other("START_PROCESS syscall failed"))?;
        if start_reply.label != procmgr_errors::SUCCESS {
            let _ = syscall::cap_delete(death_eq);
            let _ = syscall::cap_delete(thread_cap);
            // SAFETY: `ipc_ptr` is the kernel-registered IPC buffer page.
            let _ = unsafe { ipc::ipc_call(process_handle, &destroy_msg, ipc_ptr) };
            let _ = syscall::cap_delete(process_handle);
            return Err(map_procmgr_error(start_reply.label));
        }

        Ok((
            Process {
                process_handle,
                thread_cap,
                death_eq,
                exit_status: None,
            },
            StdioPipes {
                stdin: None,
                stdout: None,
                stderr: None,
            },
        ))
    }
}

impl fmt::Debug for Command {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            let mut debug_command = f.debug_struct("Command");
            debug_command
                .field("program", &self.program)
                .field("args", &self.args);
            if !self.env.is_unchanged() {
                debug_command.field("env", &self.env);
            }
            if self.cwd.is_some() {
                debug_command.field("cwd", &self.cwd);
            }
            if self.stdin.is_some() {
                debug_command.field("stdin", &self.stdin);
            }
            if self.stdout.is_some() {
                debug_command.field("stdout", &self.stdout);
            }
            if self.stderr.is_some() {
                debug_command.field("stderr", &self.stderr);
            }
            debug_command.finish()
        } else {
            if self.program != self.args[0] {
                write!(f, "[{:?}] ", self.program)?;
            }
            write!(f, "{:?}", self.args[0])?;
            for arg in &self.args[1..] {
                write!(f, " {:?}", arg)?;
            }
            Ok(())
        }
    }
}

impl fmt::Debug for Stdio {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Stdio::Inherit => f.write_str("Inherit"),
            Stdio::Null => f.write_str("Null"),
            Stdio::MakePipe => f.write_str("MakePipe"),
            Stdio::ParentStdout => f.write_str("ParentStdout"),
            Stdio::ParentStderr => f.write_str("ParentStderr"),
            Stdio::InheritFile(_) => f.write_str("InheritFile(_)"),
        }
    }
}

// ── Process ─────────────────────────────────────────────────────────────────

pub struct Process {
    process_handle: u32,
    thread_cap: u32,
    death_eq: u32,
    exit_status: Option<ExitStatus>,
}

impl Process {
    pub fn id(&self) -> u32 {
        // No POSIX pid on Seraph; the capability slot index uniquely
        // identifies the process within this caller's CSpace.
        self.process_handle
    }

    pub fn kill(&mut self) -> io::Result<()> {
        // Kernel posts to `death_notification` only on voluntary exit
        // (`SYS_THREAD_EXIT`) or fault — cap_revoke-driven teardown is
        // silent. Synthesize the event ourselves so `wait()` returns a
        // well-defined status after kill. Value chosen outside the
        // kernel fault range (0x1000..0x2000) so callers can tell apart
        // a user-initiated kill from a hardware fault.
        const EXIT_KILLED: u64 = 0x2000;
        let _ = syscall::event_post(self.death_eq, EXIT_KILLED);
        if let Some(info) = crate::os::seraph::try_startup_info() {
            let ipc_ptr = info.ipc_buffer as *mut u64;
            let destroy_msg = ipc::IpcMessage::new(procmgr_labels::DESTROY_PROCESS);
            // SAFETY: `ipc_ptr` is the kernel-registered IPC buffer page.
            let _ = unsafe { ipc::ipc_call(self.process_handle, &destroy_msg, ipc_ptr) };
        }
        Ok(())
    }

    pub fn wait(&mut self) -> io::Result<ExitStatus> {
        if let Some(cached) = self.exit_status {
            return Ok(cached);
        }
        let reason = syscall::event_recv(self.death_eq)
            .map_err(|_| io::Error::other("event_recv on child death queue failed"))?;
        let status = ExitStatus(reason);
        self.exit_status = Some(status);
        Ok(status)
    }

    pub fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        if let Some(cached) = self.exit_status {
            return Ok(Some(cached));
        }
        // Kernel returns `WouldBlock` (-6) if the death event queue is
        // empty (child still running). Any other error is genuine.
        match syscall::event_try_recv(self.death_eq) {
            Ok(reason) => {
                let status = ExitStatus(reason);
                self.exit_status = Some(status);
                Ok(Some(status))
            }
            Err(-6) => Ok(None),
            Err(_) => Err(io::Error::other("event_try_recv on child death queue failed")),
        }
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        if self.exit_status.is_none() {
            // Caller dropped Child without waiting. Tear the child down and
            // release the per-child kernel objects. We do not `event_recv`
            // here — cap_revoke-driven teardown posts nothing to the queue,
            // so a recv would block forever. `cap_delete` on the queue
            // below is sufficient.
            if let Some(info) = crate::os::seraph::try_startup_info() {
                let ipc_ptr = info.ipc_buffer as *mut u64;
                let destroy_msg = ipc::IpcMessage::new(procmgr_labels::DESTROY_PROCESS);
                // SAFETY: `ipc_ptr` is the kernel-registered IPC buffer page.
                let _ = unsafe { ipc::ipc_call(self.process_handle, &destroy_msg, ipc_ptr) };
            }
        }
        let _ = syscall::cap_delete(self.death_eq);
        let _ = syscall::cap_delete(self.thread_cap);
        let _ = syscall::cap_delete(self.process_handle);
    }
}

// ── ExitStatus / ExitCode ───────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct ExitStatus(u64);

impl ExitStatus {
    pub fn exit_ok(&self) -> Result<(), ExitStatusError> {
        if self.0 == 0 {
            Ok(())
        } else {
            Err(ExitStatusError(*self))
        }
    }

    pub fn code(&self) -> Option<i32> {
        // exit_reason packs a clean-exit value (0) or kernel fault encoding
        // (0x1000 + vector). Widen to i32 by saturating to preserve sign
        // semantics; callers distinguish "clean" via `.exit_ok()`.
        Some(self.0 as i32)
    }
}

impl fmt::Display for ExitStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0 == 0 {
            write!(f, "exit status: 0")
        } else if self.0 >= 0x1000 {
            write!(f, "fault exit: 0x{:x}", self.0)
        } else {
            write!(f, "exit status: {}", self.0)
        }
    }
}

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub struct ExitStatusError(ExitStatus);

impl From<ExitStatusError> for ExitStatus {
    fn from(e: ExitStatusError) -> ExitStatus {
        e.0
    }
}

impl ExitStatusError {
    pub fn code(self) -> Option<NonZero<i32>> {
        NonZero::new(self.0.0 as i32)
    }
}

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub struct ExitCode(u8);

impl ExitCode {
    pub const SUCCESS: ExitCode = ExitCode(0);
    pub const FAILURE: ExitCode = ExitCode(1);

    pub fn as_i32(&self) -> i32 {
        self.0 as i32
    }
}

impl From<u8> for ExitCode {
    fn from(code: u8) -> Self {
        Self(code)
    }
}

// ── CommandArgs ─────────────────────────────────────────────────────────────

pub struct CommandArgs<'a> {
    iter: crate::slice::Iter<'a, OsString>,
}

impl<'a> Iterator for CommandArgs<'a> {
    type Item = &'a OsStr;
    fn next(&mut self) -> Option<&'a OsStr> {
        self.iter.next().map(|os| &**os)
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.iter.size_hint()
    }
}

impl<'a> ExactSizeIterator for CommandArgs<'a> {
    fn len(&self) -> usize {
        self.iter.len()
    }
    fn is_empty(&self) -> bool {
        self.iter.is_empty()
    }
}

impl<'a> fmt::Debug for CommandArgs<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.iter.clone()).finish()
    }
}

// ── ChildPipe (no pipes yet — stub) ─────────────────────────────────────────

pub type ChildPipe = crate::sys::pipe::Pipe;

pub fn read_output(
    _out: ChildPipe,
    _stdout: &mut Vec<u8>,
    _err: ChildPipe,
    _stderr: &mut Vec<u8>,
) -> io::Result<()> {
    // `Pipe` is the upstream unsupported impl on seraph; any ChildPipe
    // reaching here is an uninhabited `!`, so this branch is unreachable.
    unsupported()
}

pub fn output(_cmd: &mut Command) -> io::Result<(ExitStatus, Vec<u8>, Vec<u8>)> {
    // `Command::output` captures stdout/stderr, which requires pipe-backed
    // stdio — not implemented on seraph yet (see module-level note).
    unsupported()
}

pub fn getpid() -> u32 {
    // Seraph does not have POSIX pids; return a sentinel. Callers needing
    // a unique identity use capability slot indices.
    0
}

// ── Helpers ─────────────────────────────────────────────────────────────────

fn map_procmgr_error(code: u64) -> io::Error {
    match code {
        procmgr_errors::INVALID_ELF => io::Error::new(io::ErrorKind::InvalidData, "INVALID_ELF"),
        procmgr_errors::OUT_OF_MEMORY => {
            io::Error::new(io::ErrorKind::OutOfMemory, "OUT_OF_MEMORY")
        }
        procmgr_errors::INVALID_TOKEN => {
            io::Error::new(io::ErrorKind::InvalidInput, "INVALID_TOKEN")
        }
        procmgr_errors::ALREADY_STARTED => {
            io::Error::new(io::ErrorKind::AlreadyExists, "ALREADY_STARTED")
        }
        procmgr_errors::INVALID_ARGUMENT => {
            io::Error::new(io::ErrorKind::InvalidInput, "INVALID_ARGUMENT")
        }
        procmgr_errors::NO_VFSD_ENDPOINT => {
            io::Error::new(io::ErrorKind::NotConnected, "NO_VFSD_ENDPOINT")
        }
        procmgr_errors::FILE_NOT_FOUND => {
            io::Error::new(io::ErrorKind::NotFound, "FILE_NOT_FOUND")
        }
        procmgr_errors::IO_ERROR => io::Error::other("IO_ERROR"),
        procmgr_errors::UNKNOWN_OPCODE => io::Error::other("UNKNOWN_OPCODE"),
        other => io::Error::other(format!("procmgr error {other}")),
    }
}
