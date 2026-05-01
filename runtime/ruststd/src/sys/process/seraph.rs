// seraph-overlay: std::sys::process::seraph
//
// `std::process::Command` for Seraph: spawns the target binary via
// `CREATE_FROM_VFS` to procmgr, optionally installs shmem-backed stdio
// pipes via `CONFIGURE_PIPE`, binds a death-notification `EventQueue`
// to the child's main thread, starts it, and surfaces `Child::wait` /
// `Child::kill` on top of the resulting caps.
//
// Wire-up:
//   * Create: ipc_call(procmgr_endpoint, CREATE_FROM_VFS, ...).
//             Reply caps: [process_handle, thread_for_caller].
//   * Pipe (per piped direction): allocate (frame, data_sig, space_sig)
//             via Pipe::create_for_child; ipc_call(process_handle,
//             CONFIGURE_PIPE, data=[direction, ring_capacity],
//             caps=[frame_handoff, data_sig_handoff, space_sig_handoff]).
//             Parent retains its own Pipe end (the originals).
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
//   * `Stdio::Inherit` (default) / `Stdio::Null` — no pipe installed
//     for that direction. Child reads return EOF; child writes silent-
//     drop. Same shape as a Unix daemon with no stderr.
//   * `Stdio::MakePipe` — allocates a shmem SPSC ring + 2 signal caps,
//     calls CONFIGURE_PIPE, and retains the parent-side Pipe end as
//     `ChildStdin` / `ChildStdout` / `ChildStderr`.
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
use crate::sync::Arc;
use crate::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use crate::sys::fs::File;
use crate::thread::JoinHandle;
use super::CommandEnvs;
use super::env::CommandEnv;

use ipc::{procmgr_errors, procmgr_labels};

/// Sentinel `event_post` payload used by `Process::Drop` to unblock the
/// bridge thread cleanly when the spawner discards the child without
/// waiting. Real death payloads pack `(correlator << 32) | exit_reason`
/// and the spawner uses correlator=0 (the high 32 bits are always zero
/// on a real death), so `u64::MAX` is unambiguous.
const BRIDGE_SENTINEL_DROP: u64 = u64::MAX;

/// Reasons the bridge writes to the shared `exit_reason` atom outside
/// the normal kernel-encoded range. Outside `EXIT_FAULT_BASE..0x2000`
/// to remain distinguishable from real fault codes.
const EXIT_KILLED: u64 = 0x2000;

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
        let effective_stdin = self.stdin.as_ref().unwrap_or(&default);
        let effective_stdout = self.stdout.as_ref().unwrap_or(&default);
        let effective_stderr = self.stderr.as_ref().unwrap_or(&default);
        let want_stdin_pipe = matches!(effective_stdin, Stdio::MakePipe);
        let want_stdout_pipe = matches!(effective_stdout, Stdio::MakePipe);
        let want_stderr_pipe = matches!(effective_stderr, Stdio::MakePipe);

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
        let death_eq = match crate::sys::alloc::seraph::object_slab_acquire(88)
            .and_then(|slab| syscall::event_queue_create(slab, 4).ok())
        {
            Some(eq) => eq,
            None => {
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

        // For each piped direction, allocate a parent-side `Pipe` end
        // (frame + 2 signal caps) and install the corresponding triple
        // into the child's CSpace via `CONFIGURE_PIPE`. Per-direction
        // calls are independent — we issue 0–3 IPC rounds depending on
        // which directions the caller piped. Errors tear the partial
        // child down before returning.
        let pipes_result = (|| -> io::Result<(
            Option<crate::sys::pipe::seraph::Pipe>,
            Option<crate::sys::pipe::seraph::Pipe>,
            Option<crate::sys::pipe::seraph::Pipe>,
        )> {
            let stdin = if want_stdin_pipe {
                Some(install_pipe(
                    process_handle,
                    ipc_ptr,
                    procmgr_labels::PIPE_DIR_STDIN,
                    crate::sys::pipe::seraph::Role::Writer,
                )?)
            } else {
                None
            };
            let stdout = if want_stdout_pipe {
                Some(install_pipe(
                    process_handle,
                    ipc_ptr,
                    procmgr_labels::PIPE_DIR_STDOUT,
                    crate::sys::pipe::seraph::Role::Reader,
                )?)
            } else {
                None
            };
            let stderr = if want_stderr_pipe {
                Some(install_pipe(
                    process_handle,
                    ipc_ptr,
                    procmgr_labels::PIPE_DIR_STDERR,
                    crate::sys::pipe::seraph::Role::Reader,
                )?)
            } else {
                None
            };
            Ok((stdin, stdout, stderr))
        })();
        let (mut child_stdin_pipe, mut child_stdout_pipe, mut child_stderr_pipe) =
            match pipes_result {
                Ok(triple) => triple,
                Err(e) => {
                    // Pipes built before the error already ran Drop (closer
                    // protocol + unmap + cap_delete). Tear down the child.
                    let _ = syscall::cap_delete(death_eq);
                    let _ = syscall::cap_delete(thread_cap);
                    // SAFETY: ipc_ptr is the kernel-registered IPC buffer.
                    let _ = unsafe { ipc::ipc_call(process_handle, &destroy_msg, ipc_ptr) };
                    let _ = syscall::cap_delete(process_handle);
                    return Err(e);
                }
            };

        // Spawn the death-bridge thread only when at least one stdio
        // direction is piped — non-piped spawns use `event_recv` on
        // `death_eq` directly and skip the per-spawn thread entirely.
        // Built BEFORE `START_PROCESS` so a child that faults
        // immediately still has the bridge in place to wake the
        // parent-side pipe waits.
        let any_pipe = child_stdin_pipe.is_some()
            || child_stdout_pipe.is_some()
            || child_stderr_pipe.is_some();
        let bridge = if any_pipe {
            let bridge_setup = (|| -> io::Result<Bridge> {
                let completion_slab = crate::sys::alloc::seraph::object_slab_acquire(120)
                    .ok_or_else(|| io::Error::other("object_slab_acquire (completion) failed"))?;
                let completion_signal = syscall::cap_create_signal(completion_slab)
                    .map_err(|_| io::Error::other("cap_create_signal for completion failed"))?;
                let exit_reason = Arc::new(AtomicU64::new(0));
                let peer_dead = Arc::new(AtomicBool::new(false));

                let mut pipe_signals: [Option<PipeBridgeSignals>; 3] = [None, None, None];
                for (slot, pipe) in pipe_signals.iter_mut().zip([
                    child_stdin_pipe.as_mut(),
                    child_stdout_pipe.as_mut(),
                    child_stderr_pipe.as_mut(),
                ]) {
                    if let Some(p) = pipe {
                        p.set_peer_dead(peer_dead.clone());
                        *slot = Some(PipeBridgeSignals {
                            data_signal: p.data_signal_cap(),
                            space_signal: p.space_signal_cap(),
                        });
                    }
                }

                let handles = BridgeHandles {
                    death_eq,
                    completion_signal,
                    pipe_signals,
                    exit_reason: exit_reason.clone(),
                    peer_dead,
                };
                let handle = crate::thread::Builder::new()
                    .name(crate::string::String::from("seraph-deathbridge"))
                    .spawn(move || bridge_main(handles))
                    .map_err(|e| io::Error::other(crate::format!(
                        "spawn death-bridge thread failed: {e}"
                    )))?;
                Ok(Bridge {
                    completion_signal,
                    handle: Some(handle),
                    exit_reason,
                })
            })();
            match bridge_setup {
                Ok(b) => Some(b),
                Err(e) => {
                    let _ = syscall::cap_delete(death_eq);
                    let _ = syscall::cap_delete(thread_cap);
                    // SAFETY: ipc_ptr is the kernel-registered IPC buffer.
                    let _ = unsafe { ipc::ipc_call(process_handle, &destroy_msg, ipc_ptr) };
                    let _ = syscall::cap_delete(process_handle);
                    return Err(e);
                }
            }
        } else {
            None
        };

        // Kick the child off.
        let start_msg = ipc::IpcMessage::new(procmgr_labels::START_PROCESS);
        // SAFETY: `ipc_ptr` is the kernel-registered IPC buffer page.
        let start_reply = unsafe { ipc::ipc_call(process_handle, &start_msg, ipc_ptr) }
            .map_err(|_| io::Error::other("START_PROCESS syscall failed"))?;
        if start_reply.label != procmgr_errors::SUCCESS {
            // If a bridge is running, wake it with the sentinel so it
            // joins cleanly before we delete the caps it holds.
            if let Some(b) = bridge {
                let _ = syscall::event_post(death_eq, BRIDGE_SENTINEL_DROP);
                if let Some(h) = b.handle {
                    let _ = h.join();
                }
                let _ = syscall::cap_delete(b.completion_signal);
            }
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
                bridge,
                exit_status: None,
            },
            StdioPipes {
                stdin: child_stdin_pipe,
                stdout: child_stdout_pipe,
                stderr: child_stderr_pipe,
            },
        ))
    }
}

/// Allocate a parent-side `Pipe` end for one direction and install the
/// matching cap triple into the child's CSpace via `CONFIGURE_PIPE`.
/// Returns the parent-side end on success; the parent retains its
/// originals (the IPC transfers `cap_derive`'d handoff slots), so the
/// returned `Pipe` is valid for read/write through its full lifetime.
fn install_pipe(
    process_handle: u32,
    ipc_ptr: *mut u64,
    direction: u64,
    parent_role: crate::sys::pipe::seraph::Role,
) -> io::Result<crate::sys::pipe::seraph::Pipe> {
    use crate::sys::pipe::seraph::{Pipe, RING_CAPACITY};
    let (parent, caps) = Pipe::create_for_child(parent_role)?;
    let cap_msg = ipc::IpcMessage::builder(procmgr_labels::CONFIGURE_PIPE)
        .word(0, direction)
        .word(1, u64::from(RING_CAPACITY))
        .cap(caps.frame)
        .cap(caps.data_signal)
        .cap(caps.space_signal)
        .build();
    // SAFETY: `ipc_ptr` is the calling thread's kernel-registered IPC
    // buffer (installed by `_start`).
    let reply = unsafe { ipc::ipc_call(process_handle, &cap_msg, ipc_ptr) }
        .map_err(|_| io::Error::other("CONFIGURE_PIPE syscall failed"))?;
    if reply.label != procmgr_errors::SUCCESS {
        return Err(map_procmgr_error(reply.label));
    }
    Ok(parent)
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

/// Per-spawn state used only when stdio is piped. Non-piped spawns
/// skip the bridge thread entirely and use `event_recv(death_eq)`
/// directly — no signal cap, no Arcs, no extra thread.
struct Bridge {
    /// Bridge → `wait` rendezvous. Bridge `signal_send`s once after
    /// publishing `exit_reason`; `wait` `signal_wait`s.
    completion_signal: u32,
    /// Bridge thread handle. Taken by `wait` (after completion fires)
    /// or `Drop` (after sentinel post).
    handle: Option<JoinHandle<()>>,
    /// Exit reason published by the bridge before raising
    /// `completion_signal`. Read by `wait` after the wake.
    exit_reason: Arc<AtomicU64>,
}

pub struct Process {
    process_handle: u32,
    thread_cap: u32,
    /// Death-notification queue bound to the child thread. Owned by
    /// `Process` regardless of stdio mode. With `bridge` present the
    /// bridge thread consumes the EQ; otherwise `wait` does so directly.
    death_eq: u32,
    /// Per-spawn bridge state — only allocated for piped spawns. The
    /// bridge translates a child death into the parent-side `peer_dead`
    /// atomic + pipe-signal wakes that unblock any blocked
    /// `Pipe::read` / `write`. Non-piped spawns leave this `None` and
    /// `wait` reads `death_eq` directly, saving an entire userspace
    /// thread per spawn.
    bridge: Option<Bridge>,
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
        // silent. Synthesize the event ourselves on `death_eq` so the
        // bridge (or `wait` directly, for non-piped spawns) returns a
        // well-defined status after kill. Value chosen outside the
        // kernel fault range (0x1000..0x2000) so callers can tell apart
        // a user-initiated kill from a hardware fault.
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
        let reason = if let Some(b) = self.bridge.as_mut() {
            // Bridge raises `completion_signal` exactly once after
            // publishing `exit_reason`. Loop on zero-bit wakes
            // (e.g. spurious / timeout) until real bits arrive.
            loop {
                let bits = syscall::signal_wait(b.completion_signal)
                    .map_err(|_| io::Error::other("signal_wait on completion_signal failed"))?;
                if bits != 0 {
                    break;
                }
            }
            if let Some(h) = b.handle.take() {
                let _ = h.join();
            }
            b.exit_reason.load(Ordering::Acquire)
        } else {
            // Non-piped: `wait` consumes the kernel's death post on
            // `death_eq` directly. No bridge thread allocated.
            syscall::event_recv(self.death_eq)
                .map_err(|_| io::Error::other("event_recv on child death queue failed"))?
        };
        let status = ExitStatus(reason);
        self.exit_status = Some(status);
        Ok(status)
    }

    pub fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        if let Some(cached) = self.exit_status {
            return Ok(Some(cached));
        }
        let reason = if let Some(b) = self.bridge.as_mut() {
            // `signal_wait_timeout(_, 0)` returns immediately. Non-zero
            // wakeup_value means the bridge published `exit_reason` and
            // raised `completion_signal`; zero means "nothing pending".
            match syscall::signal_wait_timeout(b.completion_signal, 0) {
                Ok(bits) if bits != 0 => {
                    if let Some(h) = b.handle.take() {
                        let _ = h.join();
                    }
                    b.exit_reason.load(Ordering::Acquire)
                }
                Ok(_) => return Ok(None),
                Err(_) => {
                    return Err(io::Error::other(
                        "signal_wait_timeout on completion_signal failed",
                    ));
                }
            }
        } else {
            // Non-piped: `event_try_recv` returns `WouldBlock` (-6) if
            // the kernel hasn't posted yet.
            match syscall::event_try_recv(self.death_eq) {
                Ok(r) => r,
                Err(-6) => return Ok(None),
                Err(_) => {
                    return Err(io::Error::other(
                        "event_try_recv on child death queue failed",
                    ));
                }
            }
        };
        let status = ExitStatus(reason);
        self.exit_status = Some(status);
        Ok(Some(status))
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        if self.exit_status.is_none() {
            // Caller dropped Child without waiting. If the bridge is
            // running, wake it with the sentinel and join before
            // freeing caps it holds. Then tear the child down.
            if let Some(b) = self.bridge.as_mut() {
                let _ = syscall::event_post(self.death_eq, BRIDGE_SENTINEL_DROP);
                if let Some(h) = b.handle.take() {
                    let _ = h.join();
                }
            }
            if let Some(info) = crate::os::seraph::try_startup_info() {
                let ipc_ptr = info.ipc_buffer as *mut u64;
                let destroy_msg = ipc::IpcMessage::new(procmgr_labels::DESTROY_PROCESS);
                // SAFETY: `ipc_ptr` is the kernel-registered IPC buffer page.
                let _ = unsafe { ipc::ipc_call(self.process_handle, &destroy_msg, ipc_ptr) };
            }
        }
        if let Some(b) = self.bridge.as_ref() {
            let _ = syscall::cap_delete(b.completion_signal);
        }
        let _ = syscall::cap_delete(self.death_eq);
        let _ = syscall::cap_delete(self.thread_cap);
        let _ = syscall::cap_delete(self.process_handle);
    }
}

// ── Death bridge ───────────────────────────────────────────────────────────
//
// One thread per piped spawn (the bridge runs unconditionally — even
// non-piped children benefit from the `completion_signal` rendezvous,
// and the per-pipe arrays are simply empty). Receives the kernel's
// death notification on `death_eq` and translates it into:
//   * `peer_dead.store(true)` — every parent-side `Pipe` checks this
//     atom before each `signal_wait`, so the next read/write observes
//     EOF / `BrokenPipe` regardless of the ring header's `closed`
//     flag (which the child may not have set if it exited
//     abnormally).
//   * `signal_send` on each piped direction's data and space signals,
//     so any reader/writer currently parked in `signal_wait` wakes
//     and re-checks the flag.
//   * `exit_reason.store(reason)` + `signal_send(completion_signal)`
//     — the rendezvous point `Process::wait` blocks on.
//
// Bridge does NOT touch the ring memory: the parent's `Pipe::Drop`
// can run before, during, or after the bridge fires without aliasing
// concerns. The atomics live on heap-allocated `Arc`s independent of
// any frame mapping.
//
// The bridge also recognises `BRIDGE_SENTINEL_DROP` posted by
// `Process::Drop` and exits without firing any wakes — the spawner
// is discarding the child anyway.

#[derive(Clone, Copy)]
struct PipeBridgeSignals {
    data_signal: u32,
    space_signal: u32,
}

struct BridgeHandles {
    death_eq: u32,
    completion_signal: u32,
    pipe_signals: [Option<PipeBridgeSignals>; 3],
    exit_reason: Arc<AtomicU64>,
    peer_dead: Arc<AtomicBool>,
}

fn bridge_main(h: BridgeHandles) {
    let payload = match syscall::event_recv(h.death_eq) {
        Ok(p) => p,
        // event_recv error => death_eq is gone (cap_revoke from a
        // misbehaving spawner) — nothing to do, exit cleanly.
        Err(_) => return,
    };
    if payload == BRIDGE_SENTINEL_DROP {
        // Spawner is dropping the Process; do not fire any wakes.
        return;
    }
    let reason = payload & 0xFFFF_FFFF;
    h.exit_reason.store(reason, Ordering::Release);
    h.peer_dead.store(true, Ordering::Release);
    for sig in h.pipe_signals.iter().flatten() {
        // Any non-zero bits — the wake is just a kick; the reader /
        // writer re-checks `peer_dead` on its next loop turn.
        let _ = syscall::signal_send(sig.data_signal, 1);
        let _ = syscall::signal_send(sig.space_signal, 1);
    }
    // Raise the rendezvous signal last so a `wait` that wakes
    // observes `exit_reason` already published.
    let _ = syscall::signal_send(h.completion_signal, 1);
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

// ── ChildPipe ───────────────────────────────────────────────────────────────

pub type ChildPipe = crate::sys::pipe::Pipe;

/// Drain `out` and `err` to their respective vectors. Sequential v1
/// implementation: stdout first, then stderr. Children that fill the
/// stderr ring before the parent finishes draining stdout can stall —
/// signal-based wakeup unblocks them once the parent moves to stderr.
/// True deadlock is impossible because each ring is bounded and
/// `closed`-flag-aware; pathological children that depend on
/// interleaved drain semantics are not supported.
pub fn read_output(
    out: ChildPipe,
    stdout: &mut Vec<u8>,
    err: ChildPipe,
    stderr: &mut Vec<u8>,
) -> io::Result<()> {
    out.read_to_end(stdout)?;
    err.read_to_end(stderr)?;
    Ok(())
}

/// Spawn `cmd` with stdout and stderr piped, drain both to vectors,
/// wait for the child to exit, return the status and captured output.
/// Stdin defaults to no pipe (silent-drop / immediate EOF on the child
/// side); callers that need to feed stdin should use `Command::spawn`
/// directly.
pub fn output(cmd: &mut Command) -> io::Result<(ExitStatus, Vec<u8>, Vec<u8>)> {
    let (mut process, pipes) = cmd.spawn(Stdio::MakePipe, false)?;
    let mut stdout_bytes = Vec::new();
    let mut stderr_bytes = Vec::new();
    match (pipes.stdout, pipes.stderr) {
        (Some(out), Some(err)) => {
            read_output(out, &mut stdout_bytes, err, &mut stderr_bytes)?;
        }
        (Some(out), None) => {
            out.read_to_end(&mut stdout_bytes)?;
        }
        (None, Some(err)) => {
            err.read_to_end(&mut stderr_bytes)?;
        }
        (None, None) => {}
    }
    let status = process.wait()?;
    Ok((status, stdout_bytes, stderr_bytes))
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
