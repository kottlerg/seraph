// seraph-overlay: std::sys::process::seraph
//
// `std::process::Command` for Seraph: spawns the target binary via
// `CREATE_FROM_FILE` to procmgr, optionally installs shmem-backed stdio
// pipes via `CONFIGURE_PIPE`, binds a death-notification `EventQueue`
// to the child's main thread, starts it, and surfaces `Child::wait` /
// `Child::kill` on top of the resulting caps.
//
// Wire-up:
//   * Create: ipc_call(procmgr_endpoint, CREATE_FROM_FILE, ...).
//             Reply caps: [process_handle, thread_for_caller].
//   * Pipe (per piped direction): allocate (memory, data_sig, space_sig)
//             via Pipe::create_for_child; ipc_call(process_handle,
//             CONFIGURE_PIPE, data=[direction, ring_capacity],
//             caps=[memory_handoff, data_sig_handoff, space_sig_handoff]).
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
//   * `Stdio::MakePipe` — allocates a shmem SPSC ring + 2 notification caps,
//     calls CONFIGURE_PIPE, and retains the parent-side Pipe end as
//     `ChildStdin` / `ChildStdout` / `ChildStderr`.
//
// Identity:
//   * `Process::id()` returns the low 32 bits of procmgr's internal process
//     badge (unique, monotonic, nonzero). Not a POSIX pid — processes in
//     Seraph are identified by capability, not pid.
//
// Argv/env:
//   * `Command::arg(...)` accumulates into `self.args`; `Command::env_mut()`
//     tracks into `CommandEnv`. Both are serialised at `spawn` time into the
//     label + data of `CREATE_FROM_FILE` (same encoding as `CREATE_PROCESS`
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

use syscall::EXIT_KILLED;

// ── Stdio ───────────────────────────────────────────────────────────────────

pub enum Stdio {
    Inherit,
    Null,
    MakePipe,
    ParentStdout,
    ParentStderr,
    /// Constructed by the upstream `std::process::Stdio: From<fs::File>`
    /// impl. `spawn` rejects it with `ErrorKind::Unsupported`; there is no
    /// cap-native wire for handing a file off as a child's stdio yet.
    InheritFile(File),
}

impl From<crate::sys::pipe::Pipe> for Stdio {
    fn from(pipe: crate::sys::pipe::Pipe) -> Stdio {
        pipe.diverge()
    }
}

impl From<crate::boxed::Box<crate::sys::pipe::Pipe>> for Stdio {
    fn from(pipe: crate::boxed::Box<crate::sys::pipe::Pipe>) -> Stdio {
        (*pipe).diverge()
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
    /// Per-spawn override for the child's `ProcessInfo.system_root_cap`.
    /// Zero means "use the parent-inherit default" — `Command::spawn`
    /// `cap_copy`s the spawner's own `root_dir_cap()` and delivers
    /// that. Non-zero caps are delivered to procmgr via
    /// `CONFIGURE_NAMESPACE` between `CREATE_FROM_FILE` and
    /// `START_PROCESS`; the wire transfers ownership, so the slot is
    /// consumed by the spawn call (success or wire-level error).
    namespace_cap: u32,
    /// Per-spawn override for the child's `ProcessInfo.current_dir_cap`.
    /// Zero defers to the cwd source chain (`self.cwd` path walk,
    /// then `current_dir_cap()` parent inherit, then zero). Same
    /// ownership contract as `namespace_cap`.
    cwd_dir_cap: u32,
    /// When set, spawn ORs `procmgr_labels::CREATE_PINNED` into the
    /// `CREATE_FROM_FILE` label so procmgr leaves the child eager-mapped with
    /// no system pager. Set via `CommandExt::pinned`. Defaults to off — the
    /// child is demand-paged by the system default.
    pinned: bool,
    /// `CREATE_PRIORITY` label field for the next spawn. `0` (default) =
    /// procmgr's policy default, clamped to the child's band. Set via
    /// `CommandExt::priority`.
    priority: u8,
    /// `CREATE_BAND_MAX` label field for the next spawn. `0` (default) =
    /// the child inherits a copy of the spawner's band. Set via
    /// `CommandExt::sched_max`.
    sched_max: u8,
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
            namespace_cap: 0,
            cwd_dir_cap: 0,
            pinned: false,
            priority: 0,
            sched_max: 0,
        }
    }

    /// Install a per-spawn override for the child's
    /// `ProcessInfo.system_root_cap`. Called by the seraph-specific
    /// `CommandExt::namespace_cap` trait method; transfers ownership of
    /// the cap to this `Command` (consumed by the next `spawn`).
    pub fn set_namespace_cap(&mut self, cap: u32) {
        self.namespace_cap = cap;
    }

    /// Install a per-spawn override for the child's
    /// `ProcessInfo.current_dir_cap`. Called by `CommandExt::cwd_dir_cap`.
    pub fn set_cwd_dir_cap(&mut self, cap: u32) {
        self.cwd_dir_cap = cap;
    }

    /// Request a pinned (eager-mapped, no pager) child. Called by
    /// `CommandExt::pinned`.
    pub fn set_pinned(&mut self, on: bool) {
        self.pinned = on;
    }

    /// Request the child's creation priority level. Called by
    /// `CommandExt::priority`; `0` reverts to procmgr's default.
    pub fn set_priority(&mut self, level: u8) {
        self.priority = level;
    }

    /// Request the child's `SchedControl` band ceiling. Called by
    /// `CommandExt::sched_max`; `0` reverts to a copy of the spawner's band.
    pub fn set_sched_max(&mut self, level: u8) {
        self.sched_max = level;
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

        if matches!(effective_stdin, Stdio::InheritFile(_))
            || matches!(effective_stdout, Stdio::InheritFile(_))
            || matches!(effective_stderr, Stdio::InheritFile(_))
        {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Stdio::from(File) is not supported on seraph",
            ));
        }

        let path_bytes = self.program.as_encoded_bytes();
        if path_bytes.is_empty() {
            return Err(io::Error::from(io::ErrorKind::InvalidFilename));
        }
        let path_str = self.program.to_str().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "Command program path must be UTF-8")
        })?;

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

        // Walk the spawner's namespace cap to the binary node. The
        // resulting badged SEND on the owning fs driver's namespace
        // endpoint is transferred to procmgr in caps[0] of CREATE_FROM_FILE
        // — procmgr never holds a namespace cap.
        let parent_root = crate::os::seraph::root_dir_cap();
        if parent_root == 0 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Command::spawn: no root_dir_cap configured (cannot resolve binary path)",
            ));
        }
        let walked = crate::sys::fs::walk_path_to_file(parent_root, path_str, ipc_ptr)
            .map_err(|e| {
                io::Error::new(
                    e.kind(),
                    crate::format!("Command::spawn: binary lookup failed: {e}"),
                )
            })?;
        let file_cap = walked.file_cap;
        let file_size = walked.size;

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

        // Create the per-child death `EventQueue` BEFORE issuing
        // CREATE_FROM_FILE so a POST-only copy can ride along as the
        // death-relay cap. procmgr binds that copy as an address-space death
        // observer on the child, so a terminal fault in *any* of the child's
        // threads (not just the main thread) posts the fault class to this
        // queue and `wait()` returns.
        let destroy_msg = ipc::IpcMessage::new(procmgr_labels::DESTROY_PROCESS);
        let death_eq = crate::sys::alloc::seraph::object_slab_retype(88, |slab| {
            syscall::event_queue_create(slab, 4).ok()
        })
        .ok_or_else(|| {
                // The child does not exist yet; just drop the file cap we
                // would otherwise transfer to procmgr.
                let _ = syscall::cap_delete(file_cap);
                io::Error::other("event_queue_create for child failed")
            })?;

        // Derive a POST-only copy of the death queue to hand to procmgr.
        // `ipc_call` MOVES it into procmgr's CSpace, so the spawner keeps
        // `RECV` on `death_eq` for its own drain/bridge.
        let death_relay = match syscall::cap_derive(death_eq, syscall::RIGHTS_POST) {
            Ok(slot) => slot,
            Err(_) => {
                let _ = syscall::cap_delete(death_eq);
                let _ = syscall::cap_delete(file_cap);
                return Err(io::Error::other("cap_derive death-relay POST failed"));
            }
        };

        // CREATE_FROM_FILE wire: word 0 = file_size, words 1.. = argv,
        // env header, env. Caps: [file_cap, death_relay]. Command-spawned
        // children skip the creator endpoint slot; the death relay is the
        // trailing cap (flagged by `CREATE_DEATH_RELAY`).
        let argv_word_offset: usize = 1;
        let env_len_word_offset = argv_word_offset + argv_words;
        let env_blob_word_offset = env_len_word_offset + 1;

        let pinned_flag = if self.pinned {
            procmgr_labels::CREATE_PINNED
        } else {
            0
        };
        let builder = ipc::IpcMessage::builder(procmgr_labels::CREATE_FROM_FILE
            | pinned_flag
            | procmgr_labels::CREATE_DEATH_RELAY
            | procmgr_labels::create_sched_bits(self.priority, self.sched_max)
            | ((args_blob.len() as u64) << 32)
            | ((u64::from(args_count)) << 48)
            | ((u64::from(env_count)) << 56))
            .word(0, file_size)
            .cap(file_cap);
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
        // Death relay is the trailing cap (peeled off the tail procmgr-side).
        let builder = builder.cap(death_relay);
        let total_words = 1 + argv_words + env_header_words;
        let msg = builder.word_count(total_words).build();

        // SAFETY: `ipc_ptr` is the kernel-registered IPC buffer page for
        // this thread, installed at `_start` time. file_cap and death_relay
        // ownership transfer to procmgr via the IPC; procmgr cap_deletes the
        // file cap and binds-then-deletes the relay.
        let reply = unsafe { ipc::ipc_call(procmgr_ep, &msg, ipc_ptr) }
            .map_err(|_| {
                let _ = syscall::cap_delete(death_eq);
                io::Error::other("CREATE_FROM_FILE syscall failed")
            })?;
        if reply.label != procmgr_errors::SUCCESS {
            let _ = syscall::cap_delete(death_eq);
            return Err(map_procmgr_error(reply.label));
        }

        let reply_caps = reply.caps();
        if reply_caps.len() < 2 {
            let _ = syscall::cap_delete(death_eq);
            return Err(io::Error::other(
                "CREATE_FROM_FILE reply missing process_handle or thread cap",
            ));
        }
        let process_handle = reply_caps[0];
        let thread_cap = reply_caps[1];

        // Bind the death `EventQueue` to the child's main thread BEFORE start,
        // so a short-lived child cannot exit before the binding lands and
        // leave `wait()` blocked forever. Correlator 0: the spawner uses a
        // dedicated per-child EventQueue, so routing is trivial (one thread
        // per queue) and the payload stays equal to `exit_reason`.
        if syscall::thread_bind_notification(thread_cap, death_eq, 0).is_err() {
            let _ = syscall::cap_delete(death_eq);
            let _ = syscall::cap_delete(thread_cap);
            // SAFETY: `ipc_ptr` is the kernel-registered IPC buffer page.
            let _ = unsafe { ipc::ipc_call(process_handle, &destroy_msg, ipc_ptr) };
            let _ = syscall::cap_delete(process_handle);
            return Err(io::Error::other("thread_bind_notification for child failed"));
        }

        // The death observer now lives on the child's Thread object (its TCB),
        // not on the cap, so the parent's `thread_cap` is dead weight after the
        // bind. Delete it now: this frees the slot promptly and unlinks this
        // process's copy from procmgr's `child_thread` derivation subtree (procmgr
        // `cap_derive`'d the cap then IPC-MOVED it here, preserving the derivation
        // edge), so procmgr's reap-time `cap_revoke(child_thread)` need not reach
        // across the CSpace boundary into this process. Retaining it would be safe
        // regardless: were the reap-revoke to free this slot and a later spawn
        // reuse the index, `Process::drop`'s `cap_delete(self.thread_cap)` would
        // replay a stale handle, which per-slot generation handles (#349) reject
        // with `InvalidCapability` instead of tearing down the unrelated new
        // occupant (the #341 self-teardown / all-idle hang). The early delete is
        // thus hygiene and defense-in-depth; procmgr's `cap_revoke` stays
        // load-bearing for the thread-before-aspace teardown order, and the
        // kernel-side refuse-self-delete guard remains as further defense.
        let _ = syscall::cap_delete(thread_cap);
        let thread_cap = 0u32;

        // For each piped direction, allocate a parent-side `Pipe` end
        // (memory cap + 2 notification caps) and install the corresponding triple
        // into the child's CSpace via `CONFIGURE_PIPE`. Per-direction
        // calls are independent — we issue 0–3 IPC rounds depending on
        // which directions the caller piped. Errors tear the partial
        // child down before returning.
        let pipes_result = (|| -> io::Result<(
            Option<ChildPipe>,
            Option<ChildPipe>,
            Option<ChildPipe>,
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
                let completion_notification =
                    crate::sys::alloc::seraph::object_slab_retype(120, |slab| {
                        syscall::cap_create_notification(slab).ok()
                    })
                    .ok_or_else(|| {
                        io::Error::other("cap_create_notification for completion failed")
                    })?;
                let exit_reason = Arc::new(AtomicU64::new(0));
                let peer_dead = Arc::new(AtomicBool::new(false));

                let mut pipe_notifications: [Option<PipeBridgeNotifications>; 3] = [None, None, None];
                for (slot, pipe) in pipe_notifications.iter_mut().zip([
                    child_stdin_pipe.as_mut(),
                    child_stdout_pipe.as_mut(),
                    child_stderr_pipe.as_mut(),
                ]) {
                    if let Some(p) = pipe {
                        p.set_peer_dead(peer_dead.clone());
                        *slot = Some(PipeBridgeNotifications {
                            data_notification: p.data_notification_cap(),
                            space_notification: p.space_notification_cap(),
                            ring_release: p.arm_ring_release(),
                        });
                    }
                }

                let handles = BridgeHandles {
                    death_eq,
                    completion_notification,
                    pipe_notifications,
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
                    completion_notification,
                    handle: Some(handle),
                    exit_reason,
                })
            })();
            match bridge_setup {
                Ok(b) => Some(b),
                Err(e) => {
                    // No bridge thread exists (its spawn is the last
                    // fallible step), but the releases may already be
                    // armed; mark the peer dead so the pipe drops below
                    // return the ring grants. Safe in any state: before
                    // arming the mark is a no-op and Drop releases via
                    // the no-peer path.
                    mark_spawn_failure_pipes(
                        child_stdin_pipe.as_deref(),
                        child_stdout_pipe.as_deref(),
                        child_stderr_pipe.as_deref(),
                    );
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

        // Hand the child its namespace caps via `CONFIGURE_NAMESPACE`
        // BEFORE start so they appear in `ProcessInfo.system_root_cap`
        // and `ProcessInfo.current_dir_cap` at `_start`.
        //
        // Root cap source priority:
        //   1. Explicit override via `CommandExt::namespace_cap`.
        //   2. Parent-inherit default: `cap_copy` of `root_dir_cap()`.
        //
        // Cwd cap source priority:
        //   1. Explicit override via `CommandExt::cwd_dir_cap`.
        //   2. Walk parent's root to `self.cwd` (path-based override).
        //   3. Parent-inherit default: `cap_copy` of `current_dir_cap()`.
        //   4. Zero (child has no cwd cap).
        //
        // procmgr consumes both caps on the IPC regardless of reply label.
        let ns_cap_to_send: u32 = if self.namespace_cap != 0 {
            let cap = self.namespace_cap;
            self.namespace_cap = 0;
            cap
        } else {
            match syscall::cap_copy(parent_root, info.self_cspace, syscall::RIGHTS_SEND) {
                Ok(slot) => slot,
                Err(_) => 0,
            }
        };
        let cwd_resolution: io::Result<u32> = if self.cwd_dir_cap != 0 {
            let cap = self.cwd_dir_cap;
            self.cwd_dir_cap = 0;
            Ok(cap)
        } else if let Some(cwd_os) = self.cwd.as_ref() {
            match cwd_os.to_str() {
                None => Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Command::cwd: path must be UTF-8",
                )),
                Some(cwd_str) => crate::sys::fs::walk_path_to_dir(parent_root, cwd_str, ipc_ptr)
                    .map(|walked| walked.dir_cap)
                    .map_err(|e| {
                        io::Error::new(
                            e.kind(),
                            crate::format!("Command::cwd: walk failed: {e}"),
                        )
                    }),
            }
        } else {
            let parent_cwd = crate::os::seraph::current_dir_cap();
            if parent_cwd != 0 {
                Ok(
                    match syscall::cap_copy(parent_cwd, info.self_cspace, syscall::RIGHTS_SEND) {
                        Ok(slot) => slot,
                        Err(_) => 0,
                    },
                )
            } else {
                Ok(0)
            }
        };
        let cwd_cap_to_send: u32 = match cwd_resolution {
            Ok(c) => c,
            Err(e) => {
                if ns_cap_to_send != 0 {
                    let _ = syscall::cap_delete(ns_cap_to_send);
                }
                if let Some(b) = bridge {
                    let _ = syscall::event_post(death_eq, BRIDGE_SENTINEL_DROP);
                    if let Some(h) = b.handle {
                        let _ = h.join();
                    }
                    let _ = syscall::cap_delete(b.completion_notification);
                }
                mark_spawn_failure_pipes(
                    child_stdin_pipe.as_deref(),
                    child_stdout_pipe.as_deref(),
                    child_stderr_pipe.as_deref(),
                );
                let _ = syscall::cap_delete(death_eq);
                let _ = syscall::cap_delete(thread_cap);
                // SAFETY: `ipc_ptr` is the kernel-registered IPC buffer page.
                let _ = unsafe { ipc::ipc_call(process_handle, &destroy_msg, ipc_ptr) };
                let _ = syscall::cap_delete(process_handle);
                return Err(e);
            }
        };
        if ns_cap_to_send == 0 && cwd_cap_to_send != 0 {
            // Cwd without a root is rejected by procmgr (root is the
            // mandatory cap). Drop the orphan slot and skip the IPC.
            let _ = syscall::cap_delete(cwd_cap_to_send);
        }
        if ns_cap_to_send != 0 {
            let ns_cap = ns_cap_to_send;
            let mut ns_builder = ipc::IpcMessage::builder(procmgr_labels::CONFIGURE_NAMESPACE)
                .cap(ns_cap);
            if cwd_cap_to_send != 0 {
                ns_builder = ns_builder.cap(cwd_cap_to_send);
            }
            let ns_msg = ns_builder.build();
            // SAFETY: `ipc_ptr` is the kernel-registered IPC buffer page.
            let ns_reply = unsafe { ipc::ipc_call(process_handle, &ns_msg, ipc_ptr) };
            // The caps were transferred by ipc_call regardless of the
            // reply label; clear our slot indices unconditionally.
            let _ = syscall::cap_delete(ns_cap);
            if cwd_cap_to_send != 0 {
                let _ = syscall::cap_delete(cwd_cap_to_send);
            }
            match ns_reply {
                Ok(reply) if reply.label == procmgr_errors::SUCCESS => {}
                Ok(reply) => {
                    if let Some(b) = bridge {
                        let _ = syscall::event_post(death_eq, BRIDGE_SENTINEL_DROP);
                        if let Some(h) = b.handle {
                            let _ = h.join();
                        }
                        let _ = syscall::cap_delete(b.completion_notification);
                    }
                    mark_spawn_failure_pipes(
                        child_stdin_pipe.as_deref(),
                        child_stdout_pipe.as_deref(),
                        child_stderr_pipe.as_deref(),
                    );
                    let _ = syscall::cap_delete(death_eq);
                    let _ = syscall::cap_delete(thread_cap);
                    // SAFETY: `ipc_ptr` is the kernel-registered IPC buffer page.
                    let _ = unsafe { ipc::ipc_call(process_handle, &destroy_msg, ipc_ptr) };
                    let _ = syscall::cap_delete(process_handle);
                    return Err(map_procmgr_error(reply.label));
                }
                Err(_) => {
                    if let Some(b) = bridge {
                        let _ = syscall::event_post(death_eq, BRIDGE_SENTINEL_DROP);
                        if let Some(h) = b.handle {
                            let _ = h.join();
                        }
                        let _ = syscall::cap_delete(b.completion_notification);
                    }
                    mark_spawn_failure_pipes(
                        child_stdin_pipe.as_deref(),
                        child_stdout_pipe.as_deref(),
                        child_stderr_pipe.as_deref(),
                    );
                    let _ = syscall::cap_delete(death_eq);
                    let _ = syscall::cap_delete(thread_cap);
                    // SAFETY: `ipc_ptr` is the kernel-registered IPC buffer page.
                    let _ = unsafe { ipc::ipc_call(process_handle, &destroy_msg, ipc_ptr) };
                    let _ = syscall::cap_delete(process_handle);
                    return Err(io::Error::other("CONFIGURE_NAMESPACE syscall failed"));
                }
            }
        }

        // Kick the child off.
        let start_msg = ipc::IpcMessage::new(procmgr_labels::START_PROCESS);
        // SAFETY: `ipc_ptr` is the kernel-registered IPC buffer page.
        let start_result = unsafe { ipc::ipc_call(process_handle, &start_msg, ipc_ptr) };
        let start_error = match &start_result {
            Ok(reply) if reply.label == procmgr_errors::SUCCESS => None,
            Ok(reply) => Some(map_procmgr_error(reply.label)),
            Err(_) => Some(io::Error::other("START_PROCESS syscall failed")),
        };
        if let Some(e) = start_error {
            // If a bridge is running, wake it with the sentinel so it
            // joins cleanly before we delete the caps it holds.
            if let Some(b) = bridge {
                let _ = syscall::event_post(death_eq, BRIDGE_SENTINEL_DROP);
                if let Some(h) = b.handle {
                    let _ = h.join();
                }
                let _ = syscall::cap_delete(b.completion_notification);
            }
            mark_spawn_failure_pipes(
                child_stdin_pipe.as_deref(),
                child_stdout_pipe.as_deref(),
                child_stderr_pipe.as_deref(),
            );
            let _ = syscall::cap_delete(death_eq);
            let _ = syscall::cap_delete(thread_cap);
            // SAFETY: `ipc_ptr` is the kernel-registered IPC buffer page.
            let _ = unsafe { ipc::ipc_call(process_handle, &destroy_msg, ipc_ptr) };
            let _ = syscall::cap_delete(process_handle);
            return Err(e);
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

/// Mark every parent-side pipe end's ring grant releasable on a
/// spawn-failure path. The child is destroyed without ever running, but
/// the releases were already armed for a bridge that exits via the drop
/// sentinel without reporting a death; without this call the grants
/// would strand in memmgr until the spawner exits.
fn mark_spawn_failure_pipes(
    stdin: Option<&crate::sys::pipe::seraph::Pipe>,
    stdout: Option<&crate::sys::pipe::seraph::Pipe>,
    stderr: Option<&crate::sys::pipe::seraph::Pipe>,
) {
    for p in [stdin, stdout, stderr].into_iter().flatten() {
        p.mark_peer_never_ran();
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
) -> io::Result<ChildPipe> {
    use crate::sys::pipe::seraph::{Pipe, RING_CAPACITY};
    let (parent, caps) = Pipe::create_for_child(parent_role)?;
    // Pin to heap before any further moves; see `ChildPipe` alias.
    let parent = crate::boxed::Box::new(parent);
    let cap_msg = ipc::IpcMessage::builder(procmgr_labels::CONFIGURE_PIPE)
        .word(0, direction)
        .word(1, u64::from(RING_CAPACITY))
        .cap(caps.memory)
        .cap(caps.data_notification)
        .cap(caps.space_notification)
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
/// directly — no notification cap, no Arcs, no extra thread.
struct Bridge {
    /// Bridge → `wait` rendezvous. Bridge `notification_send`s once after
    /// publishing `exit_reason`; `wait` `notification_wait`s.
    completion_notification: u32,
    /// Bridge thread handle. Taken by `wait` (after completion fires)
    /// or `Drop` (after sentinel post).
    handle: Option<JoinHandle<()>>,
    /// Exit reason published by the bridge before raising
    /// `completion_notification`. Read by `wait` after the wake.
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
    /// atomic + pipe-notification wakes that unblock any blocked
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
            // Bridge raises `completion_notification` exactly once after
            // publishing `exit_reason`. Loop on zero-bit wakes
            // (e.g. spurious / timeout) until real bits arrive.
            loop {
                let bits = syscall::notification_wait(b.completion_notification)
                    .map_err(|_| io::Error::other("notification_wait on completion_notification failed"))?;
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
            // `notification_wait_timeout(_, 0)` returns immediately. Non-zero
            // wakeup_value means the bridge published `exit_reason` and
            // raised `completion_notification`; zero means "nothing pending".
            match syscall::notification_wait_timeout(b.completion_notification, 0) {
                Ok(bits) if bits != 0 => {
                    if let Some(h) = b.handle.take() {
                        let _ = h.join();
                    }
                    b.exit_reason.load(Ordering::Acquire)
                }
                Ok(_) => return Ok(None),
                Err(_) => {
                    return Err(io::Error::other(
                        "notification_wait_timeout on completion_notification failed",
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
            let _ = syscall::cap_delete(b.completion_notification);
        }
        let _ = syscall::cap_delete(self.death_eq);
        let _ = syscall::cap_delete(self.thread_cap);
        let _ = syscall::cap_delete(self.process_handle);
    }
}

// ── Death bridge ───────────────────────────────────────────────────────────
//
// One thread per piped spawn (the bridge runs unconditionally — even
// non-piped children benefit from the `completion_notification` rendezvous,
// and the per-pipe arrays are simply empty). Receives the kernel's
// death notification on `death_eq` and translates it into:
//   * `peer_dead.store(true)` — fired on every child death, clean exit
//     included. Every parent-side `Pipe` checks this atom before each
//     ring drain; a reader reports EOF only when a drain performed after
//     observing the flag comes back empty, and a writer reports
//     `BrokenPipe`. This covers the abnormal-exit case where the child
//     never ran `Pipe::Drop` to mark the ring header `closed`.
//   * `notification_send` on each piped direction's data and space notifications,
//     so any reader/writer currently parked in `notification_wait` wakes
//     and re-checks the flag.
//   * `RingRelease::on_peer_death` per piped direction — returns the
//     direction's ring-page grant to memmgr when the parent end is
//     already dropped; otherwise the parent's later `Pipe::Drop` sends
//     the release. Exactly-once by the shared state machine.
//   * `exit_reason.store(reason)` + `notification_send(completion_notification)`
//     — the rendezvous point `Process::wait` blocks on.
//
// Bridge does NOT touch the ring memory: the parent's `Pipe::Drop`
// can run before, during, or after the bridge fires without aliasing
// concerns. The atomics live on heap-allocated `Arc`s independent of
// any page mapping.
//
// The bridge also recognises `BRIDGE_SENTINEL_DROP` posted by
// `Process::Drop` and exits without firing any wakes — the spawner
// is discarding the child anyway. A discarded child's ring grants are
// never released by the bridge (the child may still be running and
// writing); they stay accounted to the spawner until it exits, the
// same bound that applied to every pipe before grants were returned
// at all.

struct PipeBridgeNotifications {
    data_notification: u32,
    space_notification: u32,
    /// Shared ring-grant release state for this direction's parent end;
    /// the bridge reports the child's death and sends the release when
    /// the parent end is already dropped.
    ring_release: Option<Arc<crate::sys::pipe::seraph::RingRelease>>,
}

struct BridgeHandles {
    death_eq: u32,
    completion_notification: u32,
    pipe_notifications: [Option<PipeBridgeNotifications>; 3],
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
    for sig in h.pipe_notifications.iter().flatten() {
        // Any non-zero bits — the wake is just a kick; the reader /
        // writer re-checks `peer_dead` on its next loop turn.
        let _ = syscall::notification_send(sig.data_notification, 1);
        let _ = syscall::notification_send(sig.space_notification, 1);
    }
    // Report the child's death to each direction's ring-grant release
    // state; send the release for ends the parent already dropped.
    // Kicks first: waking blocked readers/writers must not wait on the
    // memmgr round-trips below.
    for sig in h.pipe_notifications.iter().flatten() {
        if let Some(rr) = &sig.ring_release {
            if rr.on_peer_death() {
                crate::sys::alloc::seraph::slab_release_fresh(rr.phys());
            }
        }
    }
    // Raise the rendezvous notification last so a `wait` that wakes
    // observes `exit_reason` already published.
    let _ = syscall::notification_send(h.completion_notification, 1);
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
        // exit_reason is a voluntary exit code (`0` clean, or `1..0x1000` from
        // `process::exit`/`ExitCode`) or a kernel fault encoding (`0x1000 +
        // vector`). The voluntary code is the reason value itself, so widening
        // to i32 yields it directly; callers distinguish "clean" via `.exit_ok()`
        // and "fault" via the `>= 0x1000` range (see `Display`).
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

// Heap-allocated so the `Pipe` itself never relocates after
// construction. `ChildPipe` is moved repeatedly through `StdioPipes`,
// `Child`, and into caller stacks; copying just the `Box` pointer
// (single 8-byte atomic store) keeps the `Pipe` field block stable so
// concurrent observers of a partial cross-CPU memcpy of those bytes
// cannot see a half-populated layout.
pub type ChildPipe = crate::boxed::Box<crate::sys::pipe::Pipe>;

/// Drain `out` and `err` to their respective vectors. Sequential v1
/// implementation: stdout first, then stderr. Children that fill the
/// stderr ring before the parent finishes draining stdout can stall —
/// notification-based wakeup unblocks them once the parent moves to stderr.
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
        procmgr_errors::INVALID_BADGE => {
            io::Error::new(io::ErrorKind::InvalidInput, "INVALID_BADGE")
        }
        procmgr_errors::ALREADY_STARTED => {
            io::Error::new(io::ErrorKind::AlreadyExists, "ALREADY_STARTED")
        }
        procmgr_errors::INVALID_ARGUMENT => {
            io::Error::new(io::ErrorKind::InvalidInput, "INVALID_ARGUMENT")
        }
        procmgr_errors::FILE_NOT_FOUND => {
            io::Error::new(io::ErrorKind::NotFound, "FILE_NOT_FOUND")
        }
        procmgr_errors::IO_ERROR => io::Error::other("IO_ERROR"),
        procmgr_errors::MAP_FAILED => io::Error::other("MAP_FAILED"),
        procmgr_errors::INSUFFICIENT_RIGHTS => {
            io::Error::new(io::ErrorKind::PermissionDenied, "INSUFFICIENT_RIGHTS")
        }
        procmgr_errors::UNKNOWN_OPCODE => io::Error::other("UNKNOWN_OPCODE"),
        other => io::Error::other(format!("procmgr error {other}")),
    }
}
