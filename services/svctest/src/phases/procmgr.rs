// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/procmgr.rs

//! procmgr / `std::process::Command` surface.
//!
//! Hosts the child-mode entries `cwd_child_main` (spawned by
//! `command_cwd_inherit_phase`), `blobs_fill_child_main` (spawned by
//! `command_blobs_fill_message_phase`), `park_child_main` (spawned by
//! `command_from_spawned_thread_phase`), and `undeliverable_reply_child_main`
//! (spawned by `procmgr_refusals_phase`).

use std::os::seraph::startup_info;

use syscall_abi::MSG_DATA_WORDS_MAX;

use crate::bootstrap::Caps;
use crate::runner::Phase;

/// `spawn_phase` runs before the namespace cluster.
pub fn spawn_only() -> &'static [Phase]
{
    &[Phase {
        name: "spawn",
        run: spawn_phase,
    }]
}

/// The init-reap release check. Registered late (see [`super::all`]) so
/// init's reap has almost always run; the phase polls for it in any case.
pub fn init_reap() -> &'static [Phase]
{
    &[Phase {
        name: "init_cspace_released",
        run: init_cspace_released_phase,
    }]
}

/// Wait for init's reap, then assert that it released init's `CSpace`:
/// procmgr's release probe, an endpoint it moved into init's `CSpace` just
/// before deleting its last cap on that `CSpace`, must have been freed with
/// it (`QUERY_INIT_REAP` reports `INIT_REAP_PROBE_RELEASED`; see
/// `services/procmgr/docs/ipc-interface.md` § `QUERY_INIT_REAP`). A kernel
/// that kept init's `CSpace` alive past its last capability reports
/// `INIT_REAP_PROBE_HELD`. The reap waits for init-logd's exit after
/// real-logd's handover, which races svctest's startup, so the phase polls.
pub fn init_cspace_released_phase(_: &Caps)
{
    use ipc::{IpcMessage, procmgr_errors, procmgr_labels};

    const POLL_INTERVAL_MS: u64 = 10;
    // 30 s: far past the handover on every CI cell, short enough to fail
    // rather than hang when the reap never runs.
    const MAX_POLLS: u32 = 3000;

    let procmgr = startup_info().procmgr_endpoint;
    let query = IpcMessage::builder(procmgr_labels::QUERY_INIT_REAP).build();
    for _ in 0..MAX_POLLS
    {
        // SAFETY: `current_ipc_buf` is this thread's registered IPC buffer page.
        let reply = unsafe { ipc::ipc_call(procmgr, &query, std::os::seraph::current_ipc_buf()) }
            .unwrap_or_else(|e| panic!("QUERY_INIT_REAP: ipc_call failed ({e})"));
        assert_eq!(
            reply.label,
            procmgr_errors::SUCCESS,
            "QUERY_INIT_REAP: procmgr replied {}",
            reply.label
        );
        if reply.word(0) != 0
        {
            assert_eq!(
                reply.word(1),
                procmgr_labels::INIT_REAP_PROBE_RELEASED,
                "init's CSpace was not released at its reap (probe outcome {})",
                reply.word(1)
            );
            std::os::seraph::log!("init_cspace_released passed");
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(POLL_INTERVAL_MS));
    }
    panic!("init_cspace_released: init's reap did not run within the poll budget");
}

/// `command_*`, `stdio_file_unsupported`, and `procmgr_refusals` run after
/// the namespace cluster has established attenuation invariants.
pub fn command_phases() -> &'static [Phase]
{
    &[
        Phase {
            name: "command_cwd_inherit",
            run: command_cwd_inherit_phase,
        },
        Phase {
            name: "command_cwd_missing",
            run: command_cwd_missing_phase,
        },
        Phase {
            name: "command_invalid_elf_loop",
            run: command_invalid_elf_loop_phase,
        },
        Phase {
            name: "command_blobs_over_message",
            run: command_blobs_over_message_phase,
        },
        Phase {
            name: "command_blobs_fill_message",
            run: command_blobs_fill_message_phase,
        },
        Phase {
            name: "command_non_utf8_refused",
            run: command_non_utf8_refused_phase,
        },
        Phase {
            name: "command_from_spawned_thread",
            run: command_from_spawned_thread_phase,
        },
        Phase {
            name: "stdio_file_unsupported",
            run: stdio_file_unsupported_phase,
        },
        Phase {
            name: "procmgr_refusals",
            run: procmgr_refusals_phase,
        },
    ]
}

/// Child-mode dispatch for argv tokens this module owns. Matching
/// arms diverge: each child function exits through `std::process::exit`,
/// except `park-child`'s, which parks until its spawner tears it down. On
/// a miss control returns to the caller.
pub fn reentry_main(role: &str)
{
    if role == "cwd-child"
    {
        cwd_child_main();
    }
    if role == BLOBS_FILL_ROLE
    {
        blobs_fill_child_main();
    }
    if role == PARK_ROLE
    {
        park_child_main();
    }
    if role == UNDELIVERABLE_ROLE
    {
        undeliverable_reply_child_main();
    }
}

/// argv[1] of a child that parks until it is torn down; the
/// `command_from_spawned_thread` cells kill and drop it.
const PARK_ROLE: &str = "park-child";

fn park_child_main() -> !
{
    loop
    {
        std::thread::park();
    }
}

fn cwd_child_main() -> !
{
    if std::os::seraph::current_dir_cap() == 0
    {
        std::process::exit(4);
    }
    match std::fs::File::open("test.txt")
    {
        Ok(_) => std::process::exit(0),
        Err(_) => std::process::exit(5),
    }
}

pub fn spawn_phase(_: &Caps)
{
    use std::process::Command;

    let mut child = Command::new("/programs/hello")
        .arg("one")
        .arg("two")
        .env("SPAWNED_BY", "svctest")
        .spawn()
        .expect("spawn /programs/hello failed");

    let id = child.id();
    std::os::seraph::log!("spawned /programs/hello handle={id:#x}");

    {
        let ipc_buf = std::os::seraph::current_ipc_buf();
        let id = child.id();
        let query = ipc::IpcMessage::new(ipc::procmgr_labels::QUERY_PROCESS);
        // SAFETY: `ipc_buf` is the kernel-registered IPC buffer page.
        let reply =
            unsafe { ipc::ipc_call(id, &query, ipc_buf) }.expect("QUERY_PROCESS call failed");
        assert_eq!(
            reply.label,
            ipc::procmgr_errors::SUCCESS,
            "QUERY_PROCESS non-success label"
        );
        let state = reply.word(0);
        let exit_reason = reply.word(1);
        match state
        {
            s if s == ipc::procmgr_process_state::ALIVE =>
            {
                assert_eq!(exit_reason, 0, "ALIVE process must report exit_reason=0");
            }
            s if s == ipc::procmgr_process_state::EXITED =>
            {
                assert_eq!(
                    exit_reason, 0,
                    "clean child must report exit_reason=0, got {exit_reason:#x}"
                );
            }
            other => panic!("expected ALIVE or EXITED, got {other}"),
        }
        std::os::seraph::log!("query_process pre-wait passed (state={state})");
    }

    let status = child.wait().expect("child wait failed");
    std::os::seraph::log!("child exited: {status}");
    assert!(
        status.success(),
        "child /programs/hello did not exit cleanly: {status}"
    );

    let again = child.try_wait().expect("try_wait after wait failed");
    assert!(
        again.is_some(),
        "try_wait after wait must surface cached status"
    );
    std::os::seraph::log!("try_wait phase passed");

    {
        let ipc_buf = std::os::seraph::current_ipc_buf();
        let query = ipc::IpcMessage::new(ipc::procmgr_labels::QUERY_PROCESS);
        // SAFETY: `ipc_buf` is the kernel-registered IPC buffer page.
        let reply =
            unsafe { ipc::ipc_call(id, &query, ipc_buf) }.expect("QUERY_PROCESS call failed");
        assert_eq!(
            reply.label,
            ipc::procmgr_errors::SUCCESS,
            "QUERY_PROCESS non-success label after auto-reap"
        );
        let state = reply.word(0);
        let exit_reason = reply.word(1);
        assert_eq!(
            state,
            ipc::procmgr_process_state::EXITED,
            "expected EXITED after auto-reap, got {state}"
        );
        assert_eq!(
            exit_reason, 0,
            "clean child must report exit_reason=0, got {exit_reason:#x}"
        );
        std::os::seraph::log!("auto_reap (EXITED) passed");
    }

    std::os::seraph::log!("spawn phase passed");
}

pub fn command_cwd_inherit_phase(_: &Caps)
{
    use std::process::Command;

    let mut child = Command::new("/tests/svctest")
        .arg("cwd-child")
        .current_dir("/data")
        .spawn()
        .expect("Command::cwd(/data) must spawn cleanly");
    let status = child.wait().expect("wait on cwd-inherit child failed");
    let code = status.code().unwrap_or(-1);
    assert_eq!(
        code, 0,
        "cwd-inherit child exit code {code}: \
         4=current_dir_cap zero, 5=relative open failed (see cwd_child_main)"
    );
    std::os::seraph::log!("command_cwd_inherit phase passed");
}

pub fn command_cwd_missing_phase(_: &Caps)
{
    use std::process::Command;

    let err = Command::new("/tests/svctest")
        .arg("cwd-child")
        .current_dir("/this/does/not/exist")
        .spawn()
        .expect_err("Command::cwd on unreachable path must fail");
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::NotFound,
        "expected NotFound from cwd walk failure, got {err:?}",
    );
    std::os::seraph::log!("command_cwd_missing phase passed");
}

pub fn command_invalid_elf_loop_phase(_: &Caps)
{
    use std::process::Command;

    for i in 0..16
    {
        let err = Command::new("/data/test.txt")
            .spawn()
            .expect_err("spawning a non-ELF path must fail");
        let _ = i;
        let _ = err;
    }

    let mut child = Command::new("/programs/hello")
        .spawn()
        .expect("legitimate spawn after invalid-ELF loop failed");
    let status = child.wait().expect("wait on hello after loop failed");
    assert_eq!(
        status.code().unwrap_or(-1),
        0,
        "hello after invalid-ELF loop exited non-zero",
    );
    std::os::seraph::log!("command_invalid_elf_loop phase passed");
}

/// Fixture the blob-size cells spawn: svctest itself, re-entered through
/// [`reentry_main`] as [`BLOBS_FILL_ROLE`] so the child can check what
/// reached it. Its path is argv[0] on the wire.
const BLOB_FIXTURE: &str = "/tests/svctest";
/// argv[1] of the blob-size cells' child; dispatches to
/// `blobs_fill_child_main`.
const BLOBS_FILL_ROLE: &str = "blobs-fill-child";
/// Key of the single env entry the blob-size cells deliver.
const BLOBS_ENV_KEY: &str = "K";
/// Exit code of the blob-fill child when argv is not what the parent packed.
const BLOBS_CHILD_BAD_ARGV: i32 = 6;
/// Exit code of the blob-fill child when env is not what the parent packed.
const BLOBS_CHILD_BAD_ENV: i32 = 7;

/// Length of the filler token that brings the packed argv blob (argv[0],
/// the role, and the filler, each NUL-terminated) to exactly
/// `ipc::ARGS_BLOB_MAX` bytes.
fn blobs_filler_len() -> usize
{
    ipc::ARGS_BLOB_MAX - (BLOB_FIXTURE.len() + 1) - (BLOBS_FILL_ROLE.len() + 1) - 1
}

/// Length of the value whose `K=<v...>` entry packs to `env_bytes` bytes
/// including the `=` and the NUL.
fn blobs_env_value_len(env_bytes: usize) -> usize
{
    env_bytes - BLOBS_ENV_KEY.len() - 2
}

/// Env blob size that fills the `CREATE_FROM_FILE` data area exactly behind
/// a full argv blob: the file-size word, the argv words, the env header,
/// and the env words sum to `MSG_DATA_WORDS_MAX`. Packed with `div_ceil`,
/// as std packs the blobs.
fn blobs_fill_env_bytes() -> usize
{
    (MSG_DATA_WORDS_MAX - 2 - ipc::ARGS_BLOB_MAX.div_ceil(8)) * 8
}

/// A `Command` for [`BLOB_FIXTURE`] whose packed argv blob is exactly
/// `ipc::ARGS_BLOB_MAX` bytes (argv[0], the role, and one filler token,
/// each NUL-terminated) and whose packed env blob is one `K=<v...>` entry
/// of `env_bytes` bytes including its NUL. `env_clear` keeps svctest's own
/// `SERAPH_*` entries out of the count.
fn command_with_packed_blobs(env_bytes: usize) -> std::process::Command
{
    let filler = "a".repeat(blobs_filler_len());
    let value = "v".repeat(blobs_env_value_len(env_bytes));
    let mut cmd = std::process::Command::new(BLOB_FIXTURE);
    cmd.arg(BLOBS_FILL_ROLE)
        .arg(filler)
        .env_clear()
        .env(BLOBS_ENV_KEY, value);
    cmd
}

/// Child main of the blob-fill cell. Exits `0` only when argv and env
/// reproduce the lengths and content [`command_with_packed_blobs`] packed
/// for [`blobs_fill_env_bytes`]; a blob procmgr silently degraded to empty
/// would otherwise still look like a clean exit to the parent.
fn blobs_fill_child_main() -> !
{
    let args: Vec<String> = std::env::args().collect();
    let filler = "a".repeat(blobs_filler_len());
    let argv_intact = args.len() == 3
        && args[0] == BLOB_FIXTURE
        && args[1] == BLOBS_FILL_ROLE
        && args[2] == filler;
    if !argv_intact
    {
        let lens: Vec<usize> = args.iter().map(String::len).collect();
        std::os::seraph::log!("blobs-fill-child: argv mismatch, token lengths {lens:?}");
        std::process::exit(BLOBS_CHILD_BAD_ARGV);
    }
    let vars: Vec<(String, String)> = std::env::vars().collect();
    let value = "v".repeat(blobs_env_value_len(blobs_fill_env_bytes()));
    let env_intact = vars.len() == 1 && vars[0].0 == BLOBS_ENV_KEY && vars[0].1 == value;
    if !env_intact
    {
        let lens: Vec<(usize, usize)> = vars.iter().map(|(k, v)| (k.len(), v.len())).collect();
        std::os::seraph::log!("blobs-fill-child: env mismatch, entry lengths {lens:?}");
        std::process::exit(BLOBS_CHILD_BAD_ENV);
    }
    std::process::exit(0);
}

/// argv and env each at `ARGS_BLOB_MAX` pack to 1 + 32 + 1 + 32 words, two
/// past the data area: std must refuse with `ArgumentListTooLong` before
/// the binary is looked up or any cap is minted.
pub fn command_blobs_over_message_phase(_: &Caps)
{
    let err = command_with_packed_blobs(ipc::ARGS_BLOB_MAX)
        .spawn()
        .expect_err("argv and env jointly over the message must not spawn");
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::ArgumentListTooLong,
        "joint blob overflow must surface as ArgumentListTooLong, got {err:?}"
    );
    std::os::seraph::log!("command_blobs_over_message phase passed");
}

/// The process ABI defines argv and env as UTF-8 strings, so std refuses a
/// non-UTF-8 argument or env value with `InvalidInput` before any child is
/// created.
pub fn command_non_utf8_refused_phase(_: &Caps)
{
    // SAFETY: safe Rust cannot build a non-UTF-8 `OsString` here, since
    // `std::os::seraph` offers no `OsStringExt::from_vec`. This target's
    // `OsStr` uses std's byte-string encoding, which accepts every byte
    // sequence, so `[0xFF]` is a validly encoded `OsStr` on it.
    let invalid = unsafe { std::ffi::OsString::from_encoded_bytes_unchecked(vec![0xFF]) };

    let err = std::process::Command::new(BLOB_FIXTURE)
        .arg(&invalid)
        .spawn()
        .expect_err("a non-UTF-8 argument must not spawn");
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::InvalidInput,
        "a non-UTF-8 argument must surface as InvalidInput, got {err:?}"
    );

    let err = std::process::Command::new(BLOB_FIXTURE)
        .env("SVCTEST_NON_UTF8", &invalid)
        .spawn()
        .expect_err("a non-UTF-8 env value must not spawn");
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::InvalidInput,
        "a non-UTF-8 env value must surface as InvalidInput, got {err:?}"
    );
    std::os::seraph::log!("command_non_utf8_refused phase passed");
}

/// `Command::spawn`, `Child::kill`, and dropping an unwaited `Child` each
/// call procmgr through the calling thread's IPC buffer, so all three must
/// work from a spawned thread as from main. The kill and drop cells use an
/// unpiped child, which has no death bridge to tear it down instead, and
/// check through procmgr that the child is gone.
pub fn command_from_spawned_thread_phase(_: &Caps)
{
    use ipc::procmgr_process_state::{EXITED, UNKNOWN};
    use std::process::Command;

    let spawner = std::thread::Builder::new()
        .name("command_spawner".into())
        .spawn(|| {
            let output = Command::new("/programs/hello")
                .output()
                .expect("Command::output from a spawned thread failed");
            assert!(
                output.status.success(),
                "hello spawned from a thread did not exit cleanly: {}",
                output.status
            );
            assert!(
                !output.stdout.is_empty(),
                "hello spawned from a thread produced no stdout"
            );

            let mut child = Command::new("/tests/svctest")
                .arg(PARK_ROLE)
                .spawn()
                .expect("spawning the park child to kill failed");
            child
                .kill()
                .expect("Child::kill from a spawned thread failed");
            let status = child.wait().expect("wait on the killed park child failed");
            assert_eq!(
                status.to_string(),
                "killed",
                "a killed child must report killed, got {status}"
            );
            let state = process_state(child.id());
            assert!(
                matches!(state, UNKNOWN | EXITED),
                "Child::kill from a spawned thread left the child in state {state}"
            );

            let unwaited = Command::new("/tests/svctest")
                .arg(PARK_ROLE)
                .spawn()
                .expect("spawning the park child to drop failed");
            let handle = syscall::cap_derive(unwaited.id(), syscall::RIGHTS_ALL)
                .expect("copying the unwaited child's process handle failed");
            drop(unwaited);
            let state = process_state(handle);
            let _ = syscall::cap_delete(handle);
            assert!(
                matches!(state, UNKNOWN | EXITED),
                "dropping an unwaited Child on a spawned thread left the child in state {state}"
            );
        })
        .expect("command_from_spawned_thread spawn failed");
    spawner
        .join()
        .expect("command_from_spawned_thread child panicked");
    std::os::seraph::log!("command_from_spawned_thread phase passed");
}

/// The `procmgr_process_state` value procmgr reports for the process
/// behind `handle`, asked through the calling thread's IPC buffer. After
/// teardown procmgr still answers on the handle, with `UNKNOWN` (or
/// `EXITED` while the badge is in its recent-exits ring), so a failed call
/// or a refusal is a test failure, not a sign the process is gone.
fn process_state(handle: u32) -> u64
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let query = ipc::IpcMessage::new(ipc::procmgr_labels::QUERY_PROCESS);
    // SAFETY: `ipc_buf` is this thread's registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(handle, &query, ipc_buf) }
        .expect("QUERY_PROCESS on the child's process handle failed");
    assert_eq!(
        reply.label,
        ipc::procmgr_errors::SUCCESS,
        "QUERY_PROCESS refused the child's process handle"
    );
    reply.word(0)
}

/// `file_size` word + 32 argv words + env header + 30 env words = 64: the
/// data area exactly full, which must still spawn, and the child
/// (`blobs_fill_child_main`) must see both blobs intact — it exits
/// [`BLOBS_CHILD_BAD_ARGV`] or [`BLOBS_CHILD_BAD_ENV`] when either was
/// degraded or truncated on the way.
pub fn command_blobs_fill_message_phase(_: &Caps)
{
    let mut child = command_with_packed_blobs(blobs_fill_env_bytes())
        .spawn()
        .expect("argv and env filling the message exactly must spawn");
    let status = child.wait().expect("wait on blob-fill child failed");
    assert_eq!(
        status.code(),
        Some(0),
        "blob-fill child exit {status}: {BLOBS_CHILD_BAD_ARGV}=argv mismatch, \
         {BLOBS_CHILD_BAD_ENV}=env mismatch (see blobs_fill_child_main)"
    );
    std::os::seraph::log!("command_blobs_fill_message phase passed");
}

pub fn stdio_file_unsupported_phase(_: &Caps)
{
    use std::fs::File;
    use std::io::ErrorKind;
    use std::process::{Command, Stdio};

    let file = File::open("/data/test.txt").expect("open /data/test.txt for stdio probe");
    let err = Command::new("/programs/hello")
        .stdout(Stdio::from(file))
        .spawn()
        .expect_err("Stdio::from(File) must surface as Unsupported on seraph");
    assert_eq!(
        err.kind(),
        ErrorKind::Unsupported,
        "Stdio::from(File) spawn error must be Unsupported, got {err:?}"
    );
    std::os::seraph::log!("stdio_file_unsupported phase passed");
}

/// Rounds of each refused request in [`procmgr_refusals_phase`]: the phase
/// repeats every request, as a client flooding procmgr would.
const REFUSAL_ROUNDS: usize = 16;

/// A cap to attach to a request: a SEND copy of svctest's own procmgr cap,
/// which the call moves into procmgr's `CSpace`.
fn spare_cap() -> u32
{
    syscall::cap_derive(startup_info().procmgr_endpoint, syscall::RIGHTS_EP_SEND)
        .expect("deriving a spare cap to attach failed")
}

/// Call `target` with `msg` and assert procmgr replies `want`.
fn expect_reply(target: u32, msg: &ipc::IpcMessage, want: u64, what: &str)
{
    // SAFETY: `current_ipc_buf` is this thread's registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(target, msg, std::os::seraph::current_ipc_buf()) }
        .unwrap_or_else(|e| panic!("{what}: ipc_call failed ({e})"));
    assert_eq!(reply.label, want, "{what}: procmgr replied {}", reply.label);
}

/// Look up `/programs/hello` and return `(file_cap, size)`.
fn hello_file() -> (u32, u64)
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let root = std::os::seraph::root_dir_cap();
    let (programs, _, _) = crate::ipc_util::ns::ns_lookup(root, b"programs", 0xFFFF, ipc_buf)
        .expect("ns_lookup /programs failed");
    let (file, _, size) = crate::ipc_util::ns::ns_lookup(programs, b"hello", 0xFFFF, ipc_buf)
        .expect("ns_lookup /programs/hello failed");
    let _ = syscall::cap_delete(programs);
    (file, size)
}

/// procmgr refuses requests whose sender or shape its wire contract does not
/// admit, and deletes every cap they carried (see
/// `services/procmgr/docs/ipc-interface.md` § Capability Transfer):
/// `REGISTER_DEATH_EQ` from a sender without the `DEATH_EQ_AUTHORITY` badge,
/// the init-reap labels (`REGISTER_INIT_TEARDOWN`, `INIT_TEARDOWN_DONE`) from
/// any badged sender, an unknown opcode, a `CREATE_FROM_FILE` that sets
/// `CREATE_DEATH_RELAY` on a message whose only cap is the file cap, and a
/// `CONFIGURE_PIPE` with an unknown direction or for a direction already
/// configured. Each refused request carries caps. procmgr's slot count is not
/// observable from a client, so each cell asserts the refusal reply, and a
/// spawn afterwards shows procmgr still serves. The phase then checks that
/// procmgr destroys a child whose create reply it cannot deliver
/// ([`undeliverable_reply_child_main`]).
pub fn procmgr_refusals_phase(_: &Caps)
{
    use ipc::{IpcMessage, procmgr_errors, procmgr_labels};

    let procmgr = startup_info().procmgr_endpoint;
    for _ in 0..REFUSAL_ROUNDS
    {
        expect_reply(
            procmgr,
            &IpcMessage::builder(procmgr_labels::REGISTER_DEATH_EQ)
                .cap(spare_cap())
                .build(),
            procmgr_errors::UNAUTHORIZED,
            "REGISTER_DEATH_EQ without DEATH_EQ_AUTHORITY",
        );
        expect_reply(
            procmgr,
            &IpcMessage::builder(procmgr_labels::REGISTER_INIT_TEARDOWN)
                .word(0, 1)
                .cap(spare_cap())
                .cap(spare_cap())
                .cap(spare_cap())
                .cap(spare_cap())
                .build(),
            procmgr_errors::UNAUTHORIZED,
            "REGISTER_INIT_TEARDOWN first round from a badged sender",
        );
        expect_reply(
            procmgr,
            &IpcMessage::builder(procmgr_labels::REGISTER_INIT_TEARDOWN)
                .word(0, 0)
                .cap(spare_cap())
                .build(),
            procmgr_errors::UNAUTHORIZED,
            "REGISTER_INIT_TEARDOWN donation round from a badged sender",
        );
        expect_reply(
            procmgr,
            &IpcMessage::builder(procmgr_labels::INIT_TEARDOWN_DONE)
                .cap(spare_cap())
                .build(),
            procmgr_errors::UNAUTHORIZED,
            "INIT_TEARDOWN_DONE from a badged sender",
        );
        expect_reply(
            procmgr,
            &IpcMessage::builder(3).cap(spare_cap()).build(),
            procmgr_errors::UNKNOWN_OPCODE,
            "unassigned label 3",
        );
        let (file, size) = hello_file();
        expect_reply(
            procmgr,
            &IpcMessage::builder(
                procmgr_labels::CREATE_FROM_FILE | procmgr_labels::CREATE_DEATH_RELAY,
            )
            .word(0, size)
            .cap(file)
            .build(),
            procmgr_errors::INVALID_ARGUMENT,
            "CREATE_FROM_FILE with the relay flag and only the file cap",
        );
    }

    configure_pipe_refusals();

    let status = std::process::Command::new("/programs/hello")
        .status()
        .expect("spawn after the refused requests failed");
    assert!(
        status.success(),
        "hello after the refused requests exited {status}"
    );

    let status = std::process::Command::new("/tests/svctest")
        .arg(UNDELIVERABLE_ROLE)
        .status()
        .expect("spawning the undeliverable-reply child failed");
    assert_eq!(
        status.code(),
        Some(0),
        "undeliverable-reply child exit {status}: {UNDELIVERABLE_LOOKUP_FAILED}=lookup failed, \
         {UNDELIVERABLE_REPLY_DELIVERED}=create reply delivered or not refused, \
         {UNDELIVERABLE_POOL_QUERY_FAILED}=pool query failed, \
         {UNDELIVERABLE_NEVER_RECLAIMED}=the child's pages were never reclaimed, \
         {UNDELIVERABLE_CALL_FAILED}=the create call failed"
    );
    std::os::seraph::log!("procmgr_refusals phase passed");
}

/// `CONFIGURE_PIPE` cells on a child created (and never started) through raw
/// `CREATE_FROM_FILE`: an unknown direction is refused, the first stdout
/// configuration succeeds, and a second one for stdout is refused, since an
/// installed triple cannot be replaced. procmgr does not check the caps'
/// types, so spare caps stand in for the shmem page and notifications.
fn configure_pipe_refusals()
{
    use ipc::{IpcMessage, procmgr_errors, procmgr_labels};

    let (file, size) = hello_file();
    let create = IpcMessage::builder(procmgr_labels::CREATE_FROM_FILE)
        .word(0, size)
        .cap(file)
        .build();
    // SAFETY: `current_ipc_buf` is this thread's registered IPC buffer page.
    let reply = unsafe {
        ipc::ipc_call(
            startup_info().procmgr_endpoint,
            &create,
            std::os::seraph::current_ipc_buf(),
        )
    }
    .expect("raw CREATE_FROM_FILE call failed");
    assert_eq!(
        reply.label,
        procmgr_errors::SUCCESS,
        "raw CREATE_FROM_FILE refused"
    );
    let (handle, thread) = match reply.caps()
    {
        &[handle, thread] => (handle, thread),
        other => panic!("CREATE_FROM_FILE replied {} caps", other.len()),
    };
    let pipe = |direction: u64| {
        IpcMessage::builder(procmgr_labels::CONFIGURE_PIPE)
            .word(0, direction)
            .word(1, 0)
            .cap(spare_cap())
            .cap(spare_cap())
            .cap(spare_cap())
            .build()
    };
    expect_reply(
        handle,
        &pipe(7),
        procmgr_errors::INVALID_ARGUMENT,
        "CONFIGURE_PIPE with an unknown direction",
    );
    expect_reply(
        handle,
        &pipe(procmgr_labels::PIPE_DIR_STDOUT),
        procmgr_errors::SUCCESS,
        "first CONFIGURE_PIPE for stdout",
    );
    expect_reply(
        handle,
        &pipe(procmgr_labels::PIPE_DIR_STDOUT),
        procmgr_errors::INVALID_ARGUMENT,
        "second CONFIGURE_PIPE for stdout",
    );
    expect_reply(
        handle,
        &IpcMessage::new(procmgr_labels::DESTROY_PROCESS),
        procmgr_errors::SUCCESS,
        "DESTROY_PROCESS of the never-started child",
    );
    let _ = syscall::cap_delete(thread);
    let _ = syscall::cap_delete(handle);
}

/// argv[1] of the child that checks procmgr destroys a child whose create
/// reply it cannot deliver; see [`undeliverable_reply_child_main`].
const UNDELIVERABLE_ROLE: &str = "undeliverable-reply-child";
/// Exit code: a namespace lookup failed.
const UNDELIVERABLE_LOOKUP_FAILED: i32 = 2;
/// Exit code: the create reply reached the child, or procmgr refused the
/// create, instead of the reply transfer failing.
const UNDELIVERABLE_REPLY_DELIVERED: i32 = 3;
/// Exit code: a `QUERY_POOL_STATUS` call to memmgr failed.
const UNDELIVERABLE_POOL_QUERY_FAILED: i32 = 4;
/// Exit code: memmgr's free pool never returned to its level before the
/// create, in any window, so the created child's pages stayed accounted.
const UNDELIVERABLE_NEVER_RECLAIMED: i32 = 5;
/// Exit code: the `CREATE_FROM_FILE` call itself failed.
const UNDELIVERABLE_CALL_FAILED: i32 = 6;
/// Sample windows the child retries: memmgr's free-pool size is system-wide,
/// and other processes (crasher shares the boot) can move it inside one.
const UNDELIVERABLE_WINDOWS: u32 = 8;
/// Pool queries per window while procmgr's teardown of the created child
/// reaches memmgr.
const UNDELIVERABLE_POLLS: u32 = 256;

/// Child role: exhaust this process's `CSpace` so procmgr's two-cap create
/// reply cannot land, issue `CREATE_FROM_FILE`, and check that the reply
/// transfer fails and that procmgr then destroys the child it created —
/// memmgr's free pool returns to its level before the create, which it does
/// not while the suspended child holds its pages. Runs without heap
/// allocation after the exhaustion, since a heap refill needs a free slot.
fn undeliverable_reply_child_main() -> !
{
    use ipc::{IpcMessage, procmgr_labels};

    let info = startup_info();
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let lookup = |dir: u32, name: &[u8]| {
        crate::ipc_util::ns::ns_lookup(dir, name, 0xFFFF, ipc_buf)
            .unwrap_or_else(|_| std::process::exit(UNDELIVERABLE_LOOKUP_FAILED))
    };
    let (programs, _, _) = lookup(std::os::seraph::root_dir_cap(), b"programs");
    let (mut file, _, size) = lookup(programs, b"hello");

    // Fill every free slot. The create call then moves the file cap out,
    // freeing one slot, and the reply's two caps cannot both land.
    while syscall::cap_derive(info.procmgr_endpoint, syscall::RIGHTS_EP_SEND).is_ok()
    {}

    for window in 0..UNDELIVERABLE_WINDOWS
    {
        if window > 0
        {
            // The slot the previous create freed takes the new file cap.
            file = lookup(programs, b"hello").0;
        }
        let Some(before) = std::os::seraph::memmgr_pool_free_bytes()
        else
        {
            std::process::exit(UNDELIVERABLE_POOL_QUERY_FAILED);
        };
        let create = IpcMessage::builder(procmgr_labels::CREATE_FROM_FILE)
            .word(0, size)
            .cap(file)
            .build();
        // SAFETY: `ipc_buf` is the kernel-registered IPC buffer page.
        match unsafe { ipc::ipc_call(info.procmgr_endpoint, &create, ipc_buf) }
        {
            Ok(reply) if reply.label == syscall::IPC_REPLY_TRANSFER_FAILED =>
            {}
            Ok(_) => std::process::exit(UNDELIVERABLE_REPLY_DELIVERED),
            Err(_) => std::process::exit(UNDELIVERABLE_CALL_FAILED),
        }
        for _ in 0..UNDELIVERABLE_POLLS
        {
            match std::os::seraph::memmgr_pool_free_bytes()
            {
                Some(now) if now == before => std::process::exit(0),
                Some(_) => std::thread::yield_now(),
                None => std::process::exit(UNDELIVERABLE_POOL_QUERY_FAILED),
            }
        }
    }
    std::process::exit(UNDELIVERABLE_NEVER_RECLAIMED);
}
