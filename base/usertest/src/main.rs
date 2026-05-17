// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// base/usertest/src/main.rs

//! Generic userspace test driver.
//!
//! First std-built consumer of the `ruststd` overlay. Exercises the full
//! std bring-up path end-to-end: the `_start` entry in `std::os::seraph`,
//! `std::os::seraph::log!` through the log endpoint, the `System` allocator over a
//! procmgr-mapped heap, and (P4) `std::thread::spawn` + `std::sync::Mutex`
//! across two worker threads. Failures trigger a panic — our overlay's
//! panic handler exits the thread cleanly, making them visible in the log.
//!
//! Kept deliberately open-ended so new userspace checks can be added here
//! during ongoing work without minting a fresh service each time.

// The `seraph` target is not in rustc's recognised-OS list, so `std` is
// `restricted_std`-gated for downstream bins. Every std-built service on
// seraph carries this preamble; RUSTC_BOOTSTRAP=1 (set by xtask for StdUser
// builds) lets the attribute compile without a nightly-tagged toolchain.
#![feature(restricted_std)]
#![feature(thread_local)]
// usertest is an integration test harness: a standalone binary that panics
// on failure so faults surface in the log. `expect`/`unwrap` are the
// intended idiom here (coding-standards §D permits them in test code and §E
// permits narrowly-justified blanket allows).
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::cell::Cell;
use std::collections::BTreeMap;
use std::os::seraph::startup_info;
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

// Native TLS probe statics. `TLS_INIT` is const-initialised (lives in
// `.tdata` of the PT_TLS template) so readback of the initial value
// exercises the template-copy path in procmgr/alloc_thread_tls. `TLS_BSS`
// has no initialiser on the RHS (lives in `.tbss`) so readback exercises
// the zero-fill tail past filesz up to memsz. `TLS_COUNTER` is a Cell so
// we can exercise writes through `%fs:TPOFF`.
#[thread_local]
static TLS_INIT: u64 = 0xDEAD_BEEF_CAFE_BABE;
#[thread_local]
static TLS_BSS: u64 = 0;
#[thread_local]
static TLS_COUNTER: Cell<u32> = Cell::new(0);

fn main()
{
    std::os::seraph::log::register_name(b"usertest");

    // Re-entry hook: the parent's ns_sandbox_phase respawns this
    // binary with a single `sandbox-child` argv to verify a
    // CONFIGURE_NAMESPACE-installed attenuated cap propagates into
    // ProcessInfo.system_root_cap and is observable by std::fs.
    let mut argv = std::env::args();
    let _self = argv.next();
    match argv.next().as_deref()
    {
        Some("sandbox-child") => sandbox_child_main(),
        Some("cwd-child") => cwd_child_main(),
        _ =>
        {}
    }

    // std::os::seraph::_start wires stdout cap + heap from ProcessInfo,
    // so `std::os::seraph::log!` and the System allocator are live on
    // entry. init's terminal bootstrap round carries:
    //   caps[0]: tokened SEND on fatfs's namespace endpoint at
    //            NodeId::ROOT (zero when vfsd was unable to mint one)
    //   caps[1]: SHUTDOWN_AUTHORITY-tokened SEND on pwrmgr's service
    //            endpoint (zero when pwrmgr was not started)
    //   caps[2]: SEND on pwrmgr's service endpoint WITHOUT the
    //            SHUTDOWN_AUTHORITY token bit (zero when pwrmgr was not
    //            started). Used by pwrmgr_cap_deny_phase to verify the
    //            authority gate rejects un-tokened callers.
    // We consume the round so the creator does not hang on a pending
    // REQUEST.
    let info = startup_info();
    let mut fatfs_root_cap: u32 = 0;
    let mut pwrmgr_auth_cap: u32 = 0;
    let mut pwrmgr_noauth_cap: u32 = 0;
    if info.creator_endpoint != 0
    {
        // cast_ptr_alignment: IPC buffer is page-aligned (4 KiB), satisfying u64 alignment.
        #[allow(clippy::cast_ptr_alignment)]
        let ipc_buf = info.ipc_buffer.cast::<u64>();
        // SAFETY: IPC buffer is registered by `_start` and page-aligned by
        // the boot protocol.
        if let Ok(round) = unsafe { ipc::bootstrap::request_round(info.creator_endpoint, ipc_buf) }
        {
            if round.cap_count >= 1
            {
                fatfs_root_cap = round.caps[0];
            }
            if round.cap_count >= 2
            {
                pwrmgr_auth_cap = round.caps[1];
            }
            if round.cap_count >= 3
            {
                pwrmgr_noauth_cap = round.caps[2];
            }
        }
    }

    std::os::seraph::log!("starting");

    args_phase();
    env_phase();
    stack_envelope_phase();
    tls_main_phase();
    alloc_phase();
    churn_phase();
    alloc_grow_phase();
    threading_phase();
    stdio_spawned_phase();
    alloc_spawned_phase();
    tls_macro_phase();
    timeout_phase();
    spawn_phase();
    stack_overflow_phase();
    shmem_phase();
    pipes_phase();
    pipe_fault_eof_phase();
    ns_phase(fatfs_root_cap);
    ns_system_root_phase();
    ns_mount_boundary_phase();
    fs_open_phase();
    fs_release_on_close_phase();
    fs_crossover_bench_phase();
    fs_rights_attenuation_phase();
    ns_multi_component_phase();
    ns_sandbox_phase();
    ns_fallthrough_attenuation_phase();
    command_cwd_inherit_phase();
    command_cwd_missing_phase();
    command_invalid_elf_loop_phase();
    stdio_file_unsupported_phase();
    env_cwd_unset_phase();
    // Keep `fs_open_relative_phase` last: it installs a process-global
    // `current_dir_cap()` that persists across phases. Subsequent
    // phases that walk the same fs with high cap pressure (e.g.
    // back-to-back `File::open` on the same path) can hit transient
    // cap-derivation pressure on TCG-emulated arches.
    fs_open_relative_phase();
    pwrmgr_cap_deny_phase(pwrmgr_noauth_cap);
    system_time_phase();

    std::os::seraph::log!("ALL TESTS PASSED");

    pwrmgr_shutdown_phase(pwrmgr_auth_cap);
}

/// Verify pwrmgr's cap-gating rejects un-tokened callers.
///
/// Sends `pwrmgr_labels::SHUTDOWN` through a SEND cap on pwrmgr's
/// service endpoint that lacks the `SHUTDOWN_AUTHORITY` token bit.
/// pwrmgr's handler MUST reply `pwrmgr_errors::UNAUTHORIZED` rather
/// than execute the platform shutdown sequence; a different reply (or
/// no reply / actual shutdown) panics the phase.
///
/// `pwrmgr_noauth_cap == 0` indicates pwrmgr was not started (or init
/// chose not to hand out a no-authority cap); the phase logs and
/// returns.
fn pwrmgr_cap_deny_phase(pwrmgr_noauth_cap: u32)
{
    if pwrmgr_noauth_cap == 0
    {
        std::os::seraph::log!("pwrmgr cap-deny phase skipped: no no-authority cap");
        return;
    }

    let info = startup_info();
    // cast_ptr_alignment: IPC buffer is page-aligned (4 KiB).
    #[allow(clippy::cast_ptr_alignment)]
    let ipc_buf = info.ipc_buffer.cast::<u64>();

    let msg = ipc::IpcMessage::new(ipc::pwrmgr_labels::SHUTDOWN);
    // SAFETY: ipc_buf is the registered IPC buffer.
    let reply = unsafe { ipc::ipc_call(pwrmgr_noauth_cap, &msg, ipc_buf) }
        .expect("pwrmgr SHUTDOWN ipc_call (no-auth) must return a reply");
    assert_eq!(
        reply.label,
        ipc::pwrmgr_errors::UNAUTHORIZED,
        "pwrmgr SHUTDOWN through no-authority cap must reply UNAUTHORIZED (got {:#x})",
        reply.label
    );
    std::os::seraph::log!("pwrmgr cap-deny phase passed (UNAUTHORIZED reply)");
}

/// `std::time::SystemTime::now()` end-to-end through the per-process
/// `service_registry_cap` → svcmgr `QUERY_ENDPOINT` → timed
/// `GET_WALL_TIME` → kernel monotonic clock + offset against
/// `rtc.primary`. Closes issues #2 and #4 by asserting:
///
/// * the wall-clock returned is plausibly post-2024 and pre-2100 (rules
///   out the `UNIX_EPOCH` degraded path and stuck clocks);
/// * two `SystemTime::now()` reads bracketing a known `Instant::now()`
///   delay agree on elapsed within 10 ms — `Instant` reads the kernel
///   monotonic counter directly and `SystemTime` adds `offset`, so the
///   deltas must match to within a few jiffies of IPC latency.
///
/// On boards where the wall-clock chain failed to come up (init logged
/// a publish failure; `timed` is in `WALL_CLOCK_UNAVAILABLE` mode),
/// `SystemTime::now()` returns `UNIX_EPOCH` and this phase logs +
/// returns rather than panicking — `UNIX_EPOCH` is the documented
/// degraded-mode contract.
// 2024-01-01 00:00:00 UTC = 1 704 067 200 s.
const SYSTEM_TIME_AFTER_2024_SECS: u64 = 1_704_067_200;
// 2100-01-01 00:00:00 UTC = 4 102 444 800 s. Sanity ceiling.
const SYSTEM_TIME_BEFORE_2100_SECS: u64 = 4_102_444_800;

fn system_time_phase()
{
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    let t0 = SystemTime::now();
    let i0 = Instant::now();
    let since_epoch = t0
        .duration_since(UNIX_EPOCH)
        .expect("SystemTime::now must be at or after UNIX_EPOCH");
    if since_epoch == Duration::ZERO
    {
        std::os::seraph::log!("SystemTime phase skipped: timed unavailable (UNIX_EPOCH reply)");
        return;
    }

    let secs = since_epoch.as_secs();
    assert!(
        secs >= SYSTEM_TIME_AFTER_2024_SECS,
        "SystemTime returned {secs}s, before 2024-01-01 — \
         timed offset miswired or RTC clock not running",
    );
    assert!(
        secs < SYSTEM_TIME_BEFORE_2100_SECS,
        "SystemTime returned {secs}s, after 2100-01-01 — overflow or junk read",
    );

    // Busy-loop on Instant to bracket a known elapsed against
    // SystemTime. timed adds `offset + ElapsedUs`, so the two clocks
    // must agree.
    let target = Duration::from_millis(50);
    while i0.elapsed() < target
    {
        core::hint::spin_loop();
    }

    let t1 = SystemTime::now();
    let i1 = Instant::now();
    let sys_delta = t1
        .duration_since(t0)
        .expect("SystemTime monotonicity (wall clock did not run backwards)");
    let mono_delta = i1.duration_since(i0);
    let diff = sys_delta.abs_diff(mono_delta);
    assert!(
        diff < Duration::from_millis(10),
        "SystemTime/Instant delta divergence: sys={sys_delta:?} mono={mono_delta:?} diff={diff:?}",
    );

    std::os::seraph::log!(
        "SystemTime phase passed (epoch_s={secs}, sys_delta={sys_delta:?}, mono_delta={mono_delta:?})"
    );
}

/// Terminal phase: invoke pwrmgr SHUTDOWN through the
/// `SHUTDOWN_AUTHORITY`-tokened SEND cap delivered by init in the
/// bootstrap round. On the success path the platform powers off and
/// QEMU exits, ending naked `cargo xtask run` cleanly. A reply arrives
/// only on the failure path (pwrmgr could not power off the platform
/// or the cap is missing the authority token); in that case usertest
/// logs and falls through to its normal `thread_exit`, leaving the
/// system idle.
///
/// `pwrmgr_auth_cap == 0` indicates init did not start pwrmgr; the
/// phase logs and returns so the usertest run still reports a clean
/// pass marker on environments without a pwrmgr.
fn pwrmgr_shutdown_phase(pwrmgr_auth_cap: u32)
{
    if pwrmgr_auth_cap == 0
    {
        std::os::seraph::log!("pwrmgr shutdown phase skipped: no authority cap");
        return;
    }

    let info = startup_info();
    // cast_ptr_alignment: IPC buffer is page-aligned (4 KiB).
    #[allow(clippy::cast_ptr_alignment)]
    let ipc_buf = info.ipc_buffer.cast::<u64>();

    let msg = ipc::IpcMessage::new(ipc::pwrmgr_labels::SHUTDOWN);
    // SAFETY: ipc_buf is the registered IPC buffer.
    let reply = unsafe { ipc::ipc_call(pwrmgr_auth_cap, &msg, ipc_buf) };
    // A reply means pwrmgr could not power off the platform (caller
    // lacks authority, or the mechanism failed). Log and return.
    match reply
    {
        Ok(r) => std::os::seraph::log!(
            "pwrmgr SHUTDOWN returned unexpectedly (label={:#x})",
            r.label
        ),
        Err(_) => std::os::seraph::log!("pwrmgr SHUTDOWN ipc_call failed"),
    }
}

/// Re-entry path used by `ns_sandbox_phase` (parent). The child runs
/// here when invoked with argv `["usertest", "sandbox-child"]` and
/// uses its `ProcessInfo.system_root_cap` (delivered via procmgr's
/// `CONFIGURE_NAMESPACE` override) to attempt `std::fs::File::open`
/// of a path that the attenuated cap MUST refuse.
///
/// Exit-reason convention (recovered by the parent via the death
/// queue):
/// * `0` — saw the expected `PermissionDenied` from
///   `std::fs::File::open`.
/// * `1` — `open` unexpectedly succeeded → attenuation did not
///   propagate.
/// * `2` — `open` failed with a different error.
/// * `3` — child has no `system_root_cap` at all (procmgr install
///   regression).
fn sandbox_child_main() -> !
{
    let root = std::os::seraph::root_dir_cap();
    if root == 0
    {
        std::process::exit(3);
    }
    match std::fs::File::open("/srv/test.txt")
    {
        Ok(_) => std::process::exit(1),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => std::process::exit(0),
        Err(_) => std::process::exit(2),
    }
}

/// Re-entry path used by `command_cwd_inherit_phase` (parent). The
/// parent spawns this binary with `Command::cwd("/srv")`. Procmgr
/// installs a directory cap addressing `/srv` into the child's
/// `ProcessInfo.current_dir_cap`; std's `_start` reads it and
/// `current_dir_cap()` returns non-zero.
///
/// Exit-reason convention (recovered by the parent via the death
/// queue):
/// * `0` — `current_dir_cap()` is non-zero and a relative
///   `File::open("test.txt")` succeeds.
/// * `4` — `current_dir_cap()` is zero (cwd-cap delivery regressed).
/// * `5` — relative `File::open` failed (cwd cap addresses the wrong
///   directory or relative-path anchoring regressed).
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

/// Exercise the cap-as-namespace surface against the fatfs root cap
/// delivered through init's bootstrap round.
///
/// Walks `NS_LOOKUP` against the root, runs `NS_STAT` on the resulting
/// node cap, walks one nested level, runs `NS_READDIR` on a known
/// directory, and verifies the two negative paths required by the
/// vfs-cap-native-reshape plan §3.1: `NOT_FOUND` for an absent name
/// and `PERMISSION_DENIED` when the caller's cap is missing the
/// `LOOKUP` rights bit.
///
/// `fatfs_root_cap == 0` indicates vfsd was unable to mint a root cap
/// (or the bootstrap round did not carry one); the phase logs and
/// returns without asserting in that case rather than failing the
/// usertest run on environment that does not yet plumb the cap.
// clippy::too_many_lines: ns_phase folds six sequential namespace
// checks (LOOKUP, STAT, READDIR + LFN assertions, nested LOOKUP,
// negative LOOKUP, rights-attenuated LOOKUP) into one driver because
// each step's assertions reference state minted by the previous
// step. Splitting would require threading the bin_cap and ipc_buf
// through helper boundaries with no clarity gain.
#[allow(clippy::too_many_lines)]
fn ns_phase(fatfs_root_cap: u32)
{
    use namespace_protocol::{NamespaceRights, rights};

    if fatfs_root_cap == 0
    {
        std::os::seraph::log!("ns phase skipped: no fatfs root cap delivered");
        return;
    }

    let info = startup_info();
    // cast_ptr_alignment: IPC buffer is page-aligned (4 KiB).
    #[allow(clippy::cast_ptr_alignment)]
    let ipc_buf = info.ipc_buffer.cast::<u64>();

    // ── 1. NS_LOOKUP(root, "bin") with full rights ────────────────────
    let bin_cap = match ns_lookup(fatfs_root_cap, b"bin", 0xFFFF, ipc_buf)
    {
        Ok((cap, kind, _size)) =>
        {
            assert_eq!(kind, 1, "expected /bin to be a directory (kind=1)");
            cap
        }
        Err(code) => panic!("NS_LOOKUP(root, \"bin\") failed: code={code}"),
    };
    std::os::seraph::log!("ns: NS_LOOKUP /bin ok");

    // ── 2. NS_STAT on the resulting cap ───────────────────────────────
    let (size, _mtime, kind) = ns_stat(bin_cap, ipc_buf).expect("NS_STAT on /bin must succeed");
    assert_eq!(kind, 1, "/bin stat: kind must be Dir");
    let _ = size;
    std::os::seraph::log!("ns: NS_STAT /bin ok");

    // ── 3. NS_READDIR on /bin ─────────────────────────────────────────
    //
    // FAT readdir MUST surface long file names verbatim (lowercase
    // preserved) — the SFN aliases like `PIPEFA~1` are a fallback
    // path only. The disk-image populator (xtask/src/disk.rs) emits
    // LFN entries for every lowercase name, so the canonical bytes
    // landing here are exactly the host filenames.
    let mut readdir_names: Vec<Vec<u8>> = Vec::new();
    for idx in 0..32u64
    {
        match ns_readdir(bin_cap, idx, ipc_buf)
        {
            Ok(Some((entry_kind, name))) =>
            {
                std::os::seraph::log!(
                    "ns: readdir[{idx}] kind={entry_kind} name={:?}",
                    core::str::from_utf8(&name).unwrap_or("<non-utf8>")
                );
                readdir_names.push(name);
            }
            Ok(None) => break,
            Err(code) => panic!("NS_READDIR(/bin, {idx}) failed: code={code}"),
        }
    }
    for expected in [
        &b"usertest"[..],
        &b"pipefault"[..],
        &b"stackoverflow"[..],
        &b"stdiotest"[..],
    ]
    {
        assert!(
            readdir_names.iter().any(|n| n.as_slice() == expected),
            "NS_READDIR did not surface {:?} verbatim under /bin (LFN-canonical regression — \
             saw {:?})",
            core::str::from_utf8(expected).unwrap(),
            readdir_names
                .iter()
                .map(|n| core::str::from_utf8(n).unwrap_or("<non-utf8>"))
                .collect::<Vec<_>>(),
        );
    }
    std::os::seraph::log!("ns: NS_READDIR /bin saw lowercase LFN-canonical names");

    // ── 4. NS_LOOKUP nested: /bin/USERTEST ────────────────────────────
    let usertest_cap = match ns_lookup(bin_cap, b"USERTEST", 0xFFFF, ipc_buf)
    {
        Ok((cap, kind, _size)) =>
        {
            assert_eq!(kind, 0, "expected /bin/USERTEST to be a file (kind=0)");
            cap
        }
        Err(code) => panic!("NS_LOOKUP(/bin, \"USERTEST\") failed: code={code}"),
    };
    let _ = ns_stat(usertest_cap, ipc_buf).expect("NS_STAT on USERTEST must succeed");
    let _ = syscall::cap_delete(usertest_cap);
    std::os::seraph::log!("ns: NS_LOOKUP /bin/USERTEST ok");

    // ── 5. NS_LOOKUP for nonexistent name → NOT_FOUND ─────────────────
    match ns_lookup(fatfs_root_cap, b"nonexistent_xyz", 0xFFFF, ipc_buf)
    {
        Ok(_) => panic!("NS_LOOKUP for nonexistent name unexpectedly succeeded"),
        Err(code) =>
        {
            assert_eq!(
                code,
                namespace_protocol::NsError::NotFound.as_label(),
                "expected NOT_FOUND for nonexistent lookup, got {code}"
            );
        }
    }
    std::os::seraph::log!("ns: NS_LOOKUP nonexistent → NOT_FOUND");

    // ── 6. NS_LOOKUP without LOOKUP right → PERMISSION_DENIED ─────────
    // First mint a child cap with STAT only (no LOOKUP), via a request
    // that intersects against the parent's rights. Then attempt
    // NS_LOOKUP through it — must fail.
    let stat_only = NamespaceRights::from_raw(rights::STAT).raw();
    let limited_cap = match ns_lookup(fatfs_root_cap, b"bin", u64::from(stat_only), ipc_buf)
    {
        Ok((cap, _kind, _size)) => cap,
        Err(code) => panic!("NS_LOOKUP for limited /bin cap failed: code={code}"),
    };
    match ns_lookup(limited_cap, b"USERTEST", 0xFFFF, ipc_buf)
    {
        Ok(_) => panic!("NS_LOOKUP through STAT-only cap unexpectedly succeeded"),
        Err(code) =>
        {
            assert_eq!(
                code,
                namespace_protocol::NsError::PermissionDenied.as_label(),
                "expected PERMISSION_DENIED for STAT-only cap lookup, got {code}"
            );
        }
    }
    let _ = syscall::cap_delete(limited_cap);
    std::os::seraph::log!("ns: NS_LOOKUP without LOOKUP right → PERMISSION_DENIED");

    // Cleanup.
    let _ = syscall::cap_delete(bin_cap);

    std::os::seraph::log!("ns phase passed");
}

/// Exercise vfsd's synthetic system-root cap, sourced through the
/// `ProcessInfo.system_root_cap` slot.
///
/// Integration check for the system-root cap delivery path:
///
/// - init, after the cmdline-driven root mount completes, requests a
///   seed system-root cap from vfsd via
///   `vfsd_labels::GET_SYSTEM_ROOT_CAP`.
/// - For every Phase-3 spawn, init `cap_copy`s its seed cap and hands
///   it to procmgr via `procmgr_labels::CONFIGURE_NAMESPACE`.
/// - procmgr installs the per-spawn cap into the child's
///   `ProcessInfo.system_root_cap` at `START_PROCESS` time.
/// - std's `_start` reads the slot and stashes it for
///   `std::os::seraph::root_dir_cap()`.
///
/// usertest fetches the cap via `std::os::seraph::root_dir_cap()`. A
/// zero cap here means one of those steps lost the cap; the phase
/// fails loudly so the regression surfaces at the test boundary
/// instead of silently degrading the rest of the std fs surface.
///
/// Asserts:
///   1. `root_dir_cap() != 0` — the cap reached us.
///   2. `NS_LOOKUP(system_root, "esp")` succeeds with kind=Dir.
///   3. `NS_STAT` on the returned cap succeeds (the cap reaches the
///      underlying fatfs driver's namespace endpoint and is not a
///      dangling slot).
///   4. `NS_LOOKUP(system_root, "<absent>")` returns `NOT_FOUND`.
fn ns_system_root_phase()
{
    let system_root_cap = std::os::seraph::root_dir_cap();
    assert!(
        system_root_cap != 0,
        "root_dir_cap() returned 0 — ProcessInfo.system_root_cap was \
         not delivered (init→procmgr→child plumbing regression)"
    );
    std::os::seraph::log!("ns_system_root: root_dir_cap()={system_root_cap:#x}");

    let info = startup_info();
    // cast_ptr_alignment: IPC buffer is page-aligned (4 KiB).
    #[allow(clippy::cast_ptr_alignment)]
    let ipc_buf = info.ipc_buffer.cast::<u64>();

    // ── 1. NS_LOOKUP(system_root, "esp") ──────────────────────────────
    let esp_cap = match ns_lookup(system_root_cap, b"esp", 0xFFFF, ipc_buf)
    {
        Ok((cap, kind, _size)) =>
        {
            assert_eq!(
                kind, 1,
                "expected /esp to be a directory through the synthetic root"
            );
            cap
        }
        Err(code) => panic!("NS_LOOKUP(system_root, \"esp\") failed: code={code}"),
    };
    std::os::seraph::log!("ns_system_root: NS_LOOKUP esp ok");

    // ── 2. NS_STAT through the External-derived cap ───────────────────
    let (_size, _mtime, kind) =
        ns_stat(esp_cap, ipc_buf).expect("NS_STAT on /esp synthetic-root cap must succeed");
    assert_eq!(kind, 1, "/esp stat: kind must be Dir");
    std::os::seraph::log!("ns_system_root: NS_STAT esp ok");

    // ── 3. NS_LOOKUP(system_root, "<absent>") → NOT_FOUND ─────────────
    match ns_lookup(system_root_cap, b"nonexistent_xyz", 0xFFFF, ipc_buf)
    {
        Ok(_) => panic!("NS_LOOKUP through synthetic root for absent name unexpectedly succeeded"),
        Err(code) =>
        {
            assert_eq!(
                code,
                namespace_protocol::NsError::NotFound.as_label(),
                "expected NOT_FOUND for absent synthetic-root name, got {code}"
            );
        }
    }
    std::os::seraph::log!("ns_system_root: absent → NOT_FOUND");

    let _ = syscall::cap_delete(esp_cap);
    std::os::seraph::log!("ns_system_root phase passed");
}

/// Exercise both kinds of mount-boundary `NS_LOOKUP` against the
/// system-root cap (cap-native reshape plan §3.6).
///
/// Two boundary shapes coexist on the synthetic root:
///
/// 1. **Named mount-point entry.** `/esp` is a row in
///    [`VfsdRootBackend`]; `NS_LOOKUP("esp")` returns an
///    `EntryTarget::External` cap on the /esp fatfs's namespace
///    endpoint via `cap_derive` against the captured mount root cap.
///
/// 2. **Transparent root delegation.** `/config` is *not* its own
///    mount — it lives inside the root fatfs. vfsd's namespace
///    dispatcher detects the unmatched name, forwards the request
///    verbatim to the root mount's namespace endpoint, and the
///    fatfs driver mints the child cap directly. From the caller's
///    perspective the result is indistinguishable from a local
///    lookup.
///
/// Asserts that:
///  * `NS_LOOKUP("config")` succeeds and returns kind=Dir
///    (transparent delegation works).
///  * A second `NS_LOOKUP("mounts.conf")` on the returned cap
///    succeeds with kind=File (the cap is real and addresses the
///    root fatfs's namespace state, not a vfsd-internal proxy).
///  * `NS_STAT` on the file cap reports a non-zero size.
///
/// Provides regression coverage for the `try_forward_to_root_mount`
/// path in `vfsd::namespace_loop`: a regression that broke
/// transparent delegation would silently degrade to `NotFound` for
/// every non-mount-point name, which the higher-level `fs_open` and
/// procmgr `CREATE_FROM_FILE` paths would also fail on, but with
/// less targeted diagnostics than this phase.
fn ns_mount_boundary_phase()
{
    let system_root_cap = std::os::seraph::root_dir_cap();
    assert!(
        system_root_cap != 0,
        "ns_mount_boundary: root_dir_cap() returned 0"
    );

    let info = startup_info();
    // cast_ptr_alignment: IPC buffer is page-aligned (4 KiB).
    #[allow(clippy::cast_ptr_alignment)]
    let ipc_buf = info.ipc_buffer.cast::<u64>();

    // ── Transparent root delegation: NS_LOOKUP("config") ────────────────
    let (config_cap, kind, _size) = ns_lookup(system_root_cap, b"config", 0xFFFF, ipc_buf)
        .expect("ns_mount_boundary: NS_LOOKUP(system_root, \"config\") failed");
    assert_eq!(
        kind, 1,
        "ns_mount_boundary: /config must be Dir (transparent root delegation regression?)"
    );
    std::os::seraph::log!("ns_mount_boundary: NS_LOOKUP /config (delegated) ok");

    // ── Second hop on the delegated cap: NS_LOOKUP("mounts.conf") ──────
    let (file_cap, kind, size_hint) = ns_lookup(config_cap, b"mounts.conf", 0xFFFF, ipc_buf)
        .expect("ns_mount_boundary: NS_LOOKUP(config, \"mounts.conf\") failed");
    assert_eq!(
        kind, 0,
        "ns_mount_boundary: /config/mounts.conf must be File"
    );
    std::os::seraph::log!("ns_mount_boundary: NS_LOOKUP mounts.conf ok (size_hint={size_hint})");

    // ── NS_STAT on the file cap ─────────────────────────────────────────
    let (size, _mtime, kind) =
        ns_stat(file_cap, ipc_buf).expect("ns_mount_boundary: NS_STAT mounts.conf failed");
    assert_eq!(kind, 0, "ns_mount_boundary: stat kind must be File");
    assert!(size > 0, "ns_mount_boundary: mounts.conf size must be > 0");

    let _ = syscall::cap_delete(file_cap);
    let _ = syscall::cap_delete(config_cap);
    std::os::seraph::log!("ns_mount_boundary phase passed");
}

/// End-to-end exercise of the cap-native `std::fs::File::open` walk
/// (cap-native reshape plan §3.4).
///
/// Opens `/esp/EFI/seraph/boot.conf` via `std::fs::File::open` and
/// reads it. The path crosses a mount boundary at the first
/// component (`/esp` is an `EntryTarget::External` entry installed
/// in vfsd's `VfsdRootBackend`, returning a cap on fatfs's namespace
/// endpoint) and three further fatfs `NS_LOOKUP` hops. Asserts:
///
/// 1. `File::open` succeeds.
/// 2. The read returns non-zero bytes containing the marker line
///    `# Seraph bootloader configuration`, which is invariant across
///    `init=init` and `init=ktest` modes of `boot.conf`.
/// 3. Open of a path containing a non-existent component returns
///    `io::ErrorKind::NotFound` (the `ns_error_to_io` mapping for
///    `NsError::NotFound`).
///
/// File reads stay on the inline `FS_READ` path (boot.conf is well
/// under 504 bytes); the cap-native `NS_READ_FRAME` path is a
/// follow-up. The fatfs side branches on token shape and routes
/// node-cap `FS_READ` to a `NodeId`-resolved reader; `NS_READ_FRAME`
/// against a node cap stays unsupported in §3.4.
fn fs_open_phase()
{
    use std::io::Read;

    let mut file = match std::fs::File::open("/esp/EFI/seraph/boot.conf")
    {
        Ok(f) => f,
        Err(e) => panic!("fs_open: open /esp/EFI/seraph/boot.conf failed: {e}"),
    };
    let mut buf = Vec::new();
    let n = file
        .read_to_end(&mut buf)
        .expect("fs_open: read_to_end failed");
    assert!(n > 0, "fs_open: read returned 0 bytes");

    let body = String::from_utf8_lossy(&buf);
    assert!(
        body.contains("Seraph bootloader configuration"),
        "fs_open: marker line missing from boot.conf body: {body:?}"
    );
    std::os::seraph::log!("fs_open: read {n} bytes from /esp/EFI/seraph/boot.conf");

    // Negative path: a non-existent component must surface as NotFound
    // through ns_error_to_io.
    match std::fs::File::open("/esp/no_such_directory/missing.txt")
    {
        Ok(_) => panic!("fs_open: nonexistent path unexpectedly opened"),
        Err(e) => assert_eq!(
            e.kind(),
            std::io::ErrorKind::NotFound,
            "fs_open: nonexistent path expected NotFound, got {e:?}"
        ),
    }
    std::os::seraph::log!("fs_open: nonexistent path → NotFound");
    std::os::seraph::log!("fs_open phase passed");
}

/// Exercise the cooperative-release wire shape introduced for
/// `FS_READ_FRAME` in the cap-native VFS reshape: the per-process
/// release-endpoint SEND now travels in `caps[0]` of the first
/// `FS_READ_FRAME` for each opened file. The fs records it on the
/// lazy `OpenFile` slot and, critically, must `cap_delete` it from
/// its own `CSpace` at `FS_CLOSE` time — otherwise every opened
/// file accumulates a stale SEND in fs's `CSpace` and the driver's
/// slot table fills after a few hundred opens.
///
/// The fixture `/usertest/large.bin` is 16 KiB so each `read` call
/// trips the inline-vs-frame branch in
/// `runtime/ruststd/src/sys/fs/seraph.rs::File::read` (`want > 504`)
/// and uses the frame path. Each iteration opens, frame-reads,
/// drops, and the next iteration opens again — a release-endpoint
/// leak would manifest as an open failure (fs `CSpace` exhaustion)
/// or a content-mismatch (cache slot held by stale outstanding).
///
/// Out of scope: forced eviction under cache pressure (would need
/// 128+ outstanding pages to engineer deterministically). The
/// uncooperative-watchdog branch — fs sends `FS_RELEASE_FRAME`,
/// client never acks, fs hard-revokes after 100 ms — is exercised
/// by production cache pressure but has no deterministic test here
/// yet.
fn fs_release_on_close_phase()
{
    use std::io::Read;

    let path = "/usertest/large.bin";

    // Iteration count is bounded by fatfs's `MAX_NODES = 64` ceiling
    // — every NS_LOOKUP allocates a fresh NodeId and the table is
    // append-only today; nodes are not recycled on close.
    // Earlier phases consume ~20 NodeIds; 8 iterations × 2 hops
    // (`usertest`, `large.bin`) keeps headroom.
    for iter in 0..8u32
    {
        let mut f = std::fs::File::open(path)
            .unwrap_or_else(|e| panic!("fs_release_on_close: open #{iter} failed: {e}"));

        // 4 KiB read at offset 0 → want > INLINE_MAX (504), takes
        // the FS_READ_FRAME path; first iteration delivers the
        // release-endpoint SEND in caps[0].
        let mut buf = vec![0u8; 4096];
        let n = f
            .read(&mut buf)
            .unwrap_or_else(|e| panic!("fs_release_on_close: read #{iter} failed: {e}"));
        assert!(
            n > 0,
            "fs_release_on_close: iter #{iter} read returned 0 bytes"
        );

        // First iteration also content-checks: PAGE_00_ marker
        // confirms the frame cap covered the file's first page and
        // the data made it through the mem_map / memcpy / release
        // sequence intact.
        if iter == 0
        {
            let prefix: &[u8] = b"PAGE_00_";
            assert!(
                buf.starts_with(prefix),
                "fs_release_on_close: first-page content mismatch (got {:?})",
                core::str::from_utf8(&buf[..prefix.len()]).unwrap_or("<non-utf8>"),
            );
        }
        // Drop f → File::drop sends FS_CLOSE; fs's
        // handle_close_node_cap deletes the recorded
        // release_endpoint_cap from its CSpace.
    }

    std::os::seraph::log!("fs_release_on_close phase passed (8 cycles)");
}

/// Spawn `/bin/fsbench` and surface its per-(size, path) cycle counts in
/// the boot log. fsbench measures the cost of reading `/usertest/bench.bin`
/// via the inline `FS_READ` path versus the zero-copy `FS_READ_FRAME` path
/// across the size grid called out in issue #10. The numbers inform the
/// `READ_INLINE_THRESHOLD` constant at
/// `runtime/ruststd/src/sys/fs/seraph.rs`.
///
/// Asserts on child exit status only; the actual measurements appear in
/// the serial log under the `[fsbench]` name.
fn fs_crossover_bench_phase()
{
    use std::process::Command;

    let mut child = Command::new("/bin/fsbench")
        .spawn()
        .expect("spawn /bin/fsbench failed");
    let status = child.wait().expect("fsbench wait failed");
    assert!(status.success(), "fsbench did not exit cleanly: {status}");
    std::os::seraph::log!("fs_crossover_bench phase passed");
}

/// Verify F2: fatfs node-cap handlers enforce namespace rights bits.
///
/// A `STAT`-only file cap MUST NOT yield bytes via `FS_READ` or
/// `FS_READ_FRAME`. Issues each label directly at the IPC layer
/// (bypassing `std::fs`, which walks paths with full rights and so
/// would never observe the gate). Positive control: a full-rights cap
/// on the same file reads bytes successfully.
///
/// Test fixture: `/srv/test.txt` (root-fs file reached via fall-through
/// past the synthetic `/srv` intermediate; same fixture as
/// `ns_multi_component_phase`).
fn fs_rights_attenuation_phase()
{
    use namespace_protocol::rights;

    let system_root_cap = std::os::seraph::root_dir_cap();
    assert!(
        system_root_cap != 0,
        "fs_rights_attenuation: root_dir_cap() returned 0"
    );

    let info = startup_info();
    // cast_ptr_alignment: IPC buffer is page-aligned (4 KiB).
    #[allow(clippy::cast_ptr_alignment)]
    let ipc_buf = info.ipc_buffer.cast::<u64>();

    let (srv_cap, _kind, _) = ns_lookup(system_root_cap, b"srv", 0xFFFF, ipc_buf)
        .expect("fs_rights_attenuation: NS_LOOKUP /srv failed");

    // ── Negative: STAT-only file cap rejects FS_READ ────────────────
    let stat_only = u64::from(rights::STAT);
    let (stat_cap, _kind, _) = ns_lookup(srv_cap, b"test.txt", stat_only, ipc_buf)
        .expect("fs_rights_attenuation: NS_LOOKUP /srv/test.txt (STAT) failed");

    let read_msg = ipc::IpcMessage::builder(ipc::fs_labels::FS_READ)
        .word(0, 0)
        .word(1, 4)
        .build();
    // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
    let read_reply = unsafe { ipc::ipc_call(stat_cap, &read_msg, ipc_buf) }
        .expect("fs_rights_attenuation: FS_READ ipc_call failed");
    assert_eq!(
        read_reply.label,
        ipc::fs_errors::PERMISSION_DENIED,
        "fs_rights_attenuation: FS_READ on STAT-only cap returned {} (expected PERMISSION_DENIED={})",
        read_reply.label,
        ipc::fs_errors::PERMISSION_DENIED,
    );
    std::os::seraph::log!("fs_rights_attenuation: FS_READ rejected on STAT-only cap");

    // ── Negative: same cap rejects FS_READ_FRAME ────────────────────
    let frame_msg = ipc::IpcMessage::builder(ipc::fs_labels::FS_READ_FRAME)
        .word(0, 0)
        .word(1, 1)
        .build();
    // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
    let frame_reply = unsafe { ipc::ipc_call(stat_cap, &frame_msg, ipc_buf) }
        .expect("fs_rights_attenuation: FS_READ_FRAME ipc_call failed");
    assert_eq!(
        frame_reply.label,
        ipc::fs_errors::PERMISSION_DENIED,
        "fs_rights_attenuation: FS_READ_FRAME on STAT-only cap returned {} (expected PERMISSION_DENIED={})",
        frame_reply.label,
        ipc::fs_errors::PERMISSION_DENIED,
    );
    std::os::seraph::log!("fs_rights_attenuation: FS_READ_FRAME rejected on STAT-only cap");

    // ── Negative: unknown tokened opcode → UNKNOWN_OPCODE ───────────
    let unknown_msg = ipc::IpcMessage::new(0x9999);
    // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
    let unknown_reply = unsafe { ipc::ipc_call(stat_cap, &unknown_msg, ipc_buf) }
        .expect("fs_rights_attenuation: unknown-opcode ipc_call failed");
    assert_eq!(
        unknown_reply.label,
        ipc::fs_errors::UNKNOWN_OPCODE,
        "fs_rights_attenuation: unknown opcode 0x9999 returned {} (expected UNKNOWN_OPCODE={})",
        unknown_reply.label,
        ipc::fs_errors::UNKNOWN_OPCODE,
    );
    std::os::seraph::log!("fs_rights_attenuation: unknown tokened label rejected");

    let _ = syscall::cap_delete(stat_cap);

    // ── Negative: empty-rights cap rejects FS_RELEASE_FRAME ─────────
    let (empty_cap, _kind, _) = ns_lookup(srv_cap, b"test.txt", 0, ipc_buf)
        .expect("fs_rights_attenuation: NS_LOOKUP /srv/test.txt (empty) failed");
    let release_msg = ipc::IpcMessage::builder(ipc::fs_labels::FS_RELEASE_FRAME)
        .word(0, 1)
        .build();
    // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
    let release_reply = unsafe { ipc::ipc_call(empty_cap, &release_msg, ipc_buf) }
        .expect("fs_rights_attenuation: FS_RELEASE_FRAME ipc_call failed");
    assert_eq!(
        release_reply.label,
        ipc::fs_errors::PERMISSION_DENIED,
        "fs_rights_attenuation: FS_RELEASE_FRAME on empty-rights cap returned {} (expected \
         PERMISSION_DENIED={})",
        release_reply.label,
        ipc::fs_errors::PERMISSION_DENIED,
    );
    std::os::seraph::log!("fs_rights_attenuation: FS_RELEASE_FRAME rejected on empty-rights cap");
    let _ = syscall::cap_delete(empty_cap);

    // ── Positive control: full-rights cap reads bytes ───────────────
    let (full_cap, _kind, _) = ns_lookup(srv_cap, b"test.txt", 0xFFFF, ipc_buf)
        .expect("fs_rights_attenuation: NS_LOOKUP /srv/test.txt (full) failed");

    let read_msg = ipc::IpcMessage::builder(ipc::fs_labels::FS_READ)
        .word(0, 0)
        .word(1, 8)
        .build();
    // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
    let read_reply = unsafe { ipc::ipc_call(full_cap, &read_msg, ipc_buf) }
        .expect("fs_rights_attenuation: FS_READ (full) ipc_call failed");
    assert_eq!(
        read_reply.label,
        ipc::fs_errors::SUCCESS,
        "fs_rights_attenuation: FS_READ on full-rights cap returned {}",
        read_reply.label,
    );
    let bytes_read = read_reply.word(0);
    assert!(
        bytes_read > 0,
        "fs_rights_attenuation: FS_READ returned 0 bytes on full-rights cap"
    );

    let _ = syscall::cap_delete(full_cap);
    let _ = syscall::cap_delete(srv_cap);
    std::os::seraph::log!("fs_rights_attenuation phase passed");
}

/// Exercise vfsd's tree-shaped synthetic root: a multi-component
/// mount path (`/srv/data`) walks through a synthetic intermediate
/// (`/srv`), and unshadowed root-fs entries under that intermediate
/// (`/srv/test.txt`) remain reachable via fall-through to the root
/// mount.
///
/// Test fixture (rootfs): `srv/test.txt` exists in the root fs; the
/// `mounts.conf` line `UUID=<uuid> /srv/data fat` mounts the same
/// partition's root at `/srv/data`. vfsd creates a synthetic
/// intermediate node for `/srv`, captures a fall-through cap to
/// `root_mount.NS_LOOKUP("srv")` at install time, and the dispatcher
/// forwards lookups under `/srv` that miss any local child.
///
/// Coverage:
/// 1. `NS_LOOKUP(/, "srv")` returns a directory cap on the synthetic
///    intermediate (Local entry, vfsd-issued cap).
/// 2. `NS_LOOKUP(/srv, "data")` returns a directory cap on the mount
///    terminal (External entry, fatfs-issued cap). Walking that cap
///    reaches the partition's root (e.g. `/srv/data/config` exists).
/// 3. `NS_LOOKUP(/srv, "test.txt")` falls through to the root mount
///    (`/srv/test.txt` in the root fs), returns a file cap.
/// 4. `std::fs::read_to_string("/srv/test.txt")` walks all three
///    `NS_LOOKUP` hops and reads the marker content end-to-end.
fn ns_multi_component_phase()
{
    let system_root_cap = std::os::seraph::root_dir_cap();
    assert!(
        system_root_cap != 0,
        "ns_multi_component: root_dir_cap() returned 0"
    );

    let info = startup_info();
    // cast_ptr_alignment: IPC buffer is page-aligned (4 KiB).
    #[allow(clippy::cast_ptr_alignment)]
    let ipc_buf = info.ipc_buffer.cast::<u64>();

    // ── Synthetic intermediate: NS_LOOKUP("srv") at root ────────────────
    let (srv_cap, kind, _) = ns_lookup(system_root_cap, b"srv", 0xFFFF, ipc_buf)
        .expect("ns_multi_component: NS_LOOKUP(/, srv) failed");
    assert_eq!(
        kind, 1,
        "ns_multi_component: /srv must be Dir (synthetic intermediate)"
    );
    std::os::seraph::log!("ns_multi_component: NS_LOOKUP /srv (synthetic) ok");

    // ── Terminal mount: NS_LOOKUP("data") on synthetic /srv ────────────
    let (data_cap, kind, _) = ns_lookup(srv_cap, b"data", 0xFFFF, ipc_buf)
        .expect("ns_multi_component: NS_LOOKUP(/srv, data) failed");
    assert_eq!(
        kind, 1,
        "ns_multi_component: /srv/data must be Dir (mount terminal)"
    );
    // Walk one hop into the terminal to confirm it points at a real
    // fatfs partition root.
    let (cfg_cap, kind, _) = ns_lookup(data_cap, b"config", 0xFFFF, ipc_buf)
        .expect("ns_multi_component: NS_LOOKUP(/srv/data, config) failed");
    assert_eq!(kind, 1, "ns_multi_component: /srv/data/config must be Dir");
    let _ = syscall::cap_delete(cfg_cap);
    std::os::seraph::log!("ns_multi_component: NS_LOOKUP /srv/data (terminal) ok");

    // ── Fall-through: NS_LOOKUP("test.txt") on synthetic /srv ──────────
    let (txt_cap, kind, _) = ns_lookup(srv_cap, b"test.txt", 0xFFFF, ipc_buf)
        .expect("ns_multi_component: NS_LOOKUP(/srv, test.txt) failed (fall-through regression?)");
    assert_eq!(
        kind, 0,
        "ns_multi_component: /srv/test.txt must be File (root-fs fall-through)"
    );
    let (size, _mtime, kind) =
        ns_stat(txt_cap, ipc_buf).expect("ns_multi_component: NS_STAT /srv/test.txt failed");
    assert_eq!(kind, 0, "ns_multi_component: stat kind must be File");
    assert!(
        size > 0,
        "ns_multi_component: /srv/test.txt size must be > 0"
    );
    let _ = syscall::cap_delete(txt_cap);
    let _ = syscall::cap_delete(data_cap);
    let _ = syscall::cap_delete(srv_cap);
    std::os::seraph::log!("ns_multi_component: NS_LOOKUP /srv/test.txt (fall-through) ok");

    // ── End-to-end: std::fs reads the same file via the cap-native walk
    let body = std::fs::read_to_string("/srv/test.txt")
        .expect("ns_multi_component: std::fs::read_to_string(/srv/test.txt) failed");
    assert!(
        body.contains("srv-test-marker"),
        "ns_multi_component: marker missing from /srv/test.txt body: {body:?}"
    );
    std::os::seraph::log!("ns_multi_component phase passed");
}

/// Exercise procmgr's `CONFIGURE_NAMESPACE` wire end-to-end:
///
/// 1. Walk the system root cap to a sub-cap addressing `/srv` with
///    `STAT`-only namespace rights — no `LOOKUP`, no `READ`.
/// 2. Spawn `/bin/usertest sandbox-child` with the attenuated cap
///    handed to procmgr via the seraph `CommandExt::namespace_cap`
///    extension (which issues `CONFIGURE_NAMESPACE` between
///    `CREATE_FROM_FILE` and `START_PROCESS`, overriding the
///    parent-inherit default). The procmgr-side deferred `cap_copy`
///    at start time installs the cap into the child's
///    `ProcessInfo.system_root_cap`.
/// 3. The child (`sandbox_child_main`) tries
///    `std::fs::File::open("/srv/test.txt")`, which decomposes into a
///    per-component `NS_LOOKUP` walk against its system root. The
///    first hop fails with `PermissionDenied` because the cap lacks
///    the `LOOKUP` bit — the child encodes that outcome as exit
///    code 0.
/// 4. Parent waits and asserts the child exited with status 0.
fn ns_sandbox_phase()
{
    use namespace_protocol::{NamespaceRights, rights};
    use std::os::seraph::process::CommandExt;

    let root = std::os::seraph::root_dir_cap();
    if root == 0
    {
        std::os::seraph::log!("ns_sandbox phase skipped: no root_dir_cap");
        return;
    }

    let info = startup_info();
    // cast_ptr_alignment: IPC buffer is page-aligned (4 KiB).
    #[allow(clippy::cast_ptr_alignment)]
    let ipc_buf = info.ipc_buffer.cast::<u64>();

    let stat_only = NamespaceRights::from_raw(rights::STAT).raw();
    let attenuated = match ns_lookup(root, b"srv", u64::from(stat_only), ipc_buf)
    {
        Ok((cap, _kind, _size)) => cap,
        Err(code) => panic!("ns_sandbox: walk-attenuate /srv failed: code={code}"),
    };

    let mut cmd = std::process::Command::new("/bin/usertest");
    cmd.arg("sandbox-child");
    cmd.namespace_cap(attenuated);
    let status = cmd
        .status()
        .expect("ns_sandbox: spawn /bin/usertest sandbox-child failed");

    assert!(
        status.success(),
        "ns_sandbox: child exit status {status:?}; expected exit code 0 (PermissionDenied \
         observed). 1 = open succeeded (attenuation failed), 2 = different error, 3 = no \
         system_root_cap delivered to child"
    );
    std::os::seraph::log!("ns_sandbox phase passed");
}

/// Verify F1: vfsd's fall-through forwarder repacks the request body
/// to honour the caller's parent rights.
///
/// `/srv/data` is a mount point, which makes `/srv` a synthetic
/// intermediate. `/srv/test.txt` is a file in the *root* filesystem
/// reachable through that intermediate's `fallthrough_cap`. The
/// fall-through cap was minted by vfsd at full namespace rights, so
/// without F1's repack a holder of an attenuated `/srv` cap could
/// obtain a `/srv/test.txt` cap with rights exceeding its parent's.
///
/// 1. Walk `root → /srv` requesting `LOOKUP|STAT` only — `LOOKUP` is
///    required for the second walk to reach the fall-through path at
///    all (otherwise `gate` rejects before forwarding).
/// 2. From the attenuated cap, walk for `test.txt` requesting `0xFFFF`
///    ("everything I'm allowed"). This is the request that lands in
///    `try_forward_lookup_fallthrough`.
/// 3. The lookup must succeed. The returned cap MUST carry only the
///    intersection of the parent's rights and the entry's
///    `max_rights` — at most `LOOKUP|STAT`, never `READ`. Verify by
///    issuing `FS_READ` against the returned cap and asserting
///    `PERMISSION_DENIED`.
///
/// Pre-fix the returned cap carries `READ` (laundered through the
/// fall-through cap's full-rights token) and `FS_READ` succeeds —
/// the assertion fires.
fn ns_fallthrough_attenuation_phase()
{
    use namespace_protocol::{NamespaceRights, rights};

    let root = std::os::seraph::root_dir_cap();
    if root == 0
    {
        std::os::seraph::log!("ns_fallthrough_attenuation phase skipped: no root_dir_cap");
        return;
    }

    let info = startup_info();
    // cast_ptr_alignment: IPC buffer is page-aligned (4 KiB).
    #[allow(clippy::cast_ptr_alignment)]
    let ipc_buf = info.ipc_buffer.cast::<u64>();

    let lookup_stat = NamespaceRights::from_raw(rights::LOOKUP | rights::STAT).raw();
    let (srv_cap, _kind, _) = ns_lookup(root, b"srv", u64::from(lookup_stat), ipc_buf)
        .expect("ns_fallthrough_attenuation: walk-attenuate /srv (LOOKUP|STAT) failed");

    // Cross the fall-through with the `0xFFFF` sentinel. The fix
    // intersects this against `srv_cap`'s parent rights (LOOKUP|STAT);
    // the laundered pre-fix path would yield READ from the fall-through
    // cap's full-rights token.
    let (file_cap, _kind, _) = ns_lookup(srv_cap, b"test.txt", 0xFFFF, ipc_buf)
        .expect("ns_fallthrough_attenuation: NS_LOOKUP /srv/test.txt across fall-through failed");

    let read_msg = ipc::IpcMessage::builder(ipc::fs_labels::FS_READ)
        .word(0, 0)
        .word(1, 4)
        .build();
    // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
    let read_reply = unsafe { ipc::ipc_call(file_cap, &read_msg, ipc_buf) }
        .expect("ns_fallthrough_attenuation: FS_READ ipc_call failed");
    assert_eq!(
        read_reply.label,
        ipc::fs_errors::PERMISSION_DENIED,
        "ns_fallthrough_attenuation: FS_READ on cap walked under LOOKUP|STAT-only parent \
         returned {} (expected PERMISSION_DENIED={}) — the fall-through forwarder is \
         laundering authority through the synthetic intermediate's full-rights cap",
        read_reply.label,
        ipc::fs_errors::PERMISSION_DENIED,
    );

    let _ = syscall::cap_delete(file_cap);
    let _ = syscall::cap_delete(srv_cap);
    std::os::seraph::log!("ns_fallthrough_attenuation phase passed");
}

/// Issue a single `NS_LOOKUP` against `dir_cap` and decode the reply.
///
/// Returns `(child_cap, kind, size_hint)` on success or the wire
/// `NsError` code on failure.
fn ns_lookup(
    dir_cap: u32,
    name: &[u8],
    requested_rights: u64,
    ipc_buf: *mut u64,
) -> Result<(u32, u64, u64), u64>
{
    let label = ipc::ns_labels::NS_LOOKUP | ((name.len() as u64) << 16);
    let msg = ipc::IpcMessage::builder(label)
        .word(0, requested_rights)
        .bytes(1, name)
        .build();
    // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(dir_cap, &msg, ipc_buf) }
        .map_err(|_| namespace_protocol::NsError::IoError.as_label())?;
    if reply.label != 0
    {
        return Err(reply.label);
    }
    let kind = reply.word(0);
    let size = reply.word(1);
    let cap = *reply.caps().first().ok_or(0u64)?;
    Ok((cap, kind, size))
}

/// Issue `NS_STAT` against `node_cap`.
fn ns_stat(node_cap: u32, ipc_buf: *mut u64) -> Result<(u64, u64, u64), u64>
{
    let msg = ipc::IpcMessage::new(ipc::ns_labels::NS_STAT);
    // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(node_cap, &msg, ipc_buf) }
        .map_err(|_| namespace_protocol::NsError::IoError.as_label())?;
    if reply.label != 0
    {
        return Err(reply.label);
    }
    Ok((reply.word(0), reply.word(1), reply.word(2)))
}

/// Issue `NS_READDIR(idx)` against `dir_cap`. Returns `Ok(None)` on
/// `END_OF_DIR`, `Ok(Some((kind, name)))` for a populated entry, and
/// `Err(code)` on protocol error.
fn ns_readdir(dir_cap: u32, idx: u64, ipc_buf: *mut u64) -> Result<Option<(u64, Vec<u8>)>, u64>
{
    let msg = ipc::IpcMessage::builder(ipc::ns_labels::NS_READDIR)
        .word(0, idx)
        .build();
    // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(dir_cap, &msg, ipc_buf) }
        .map_err(|_| namespace_protocol::NsError::IoError.as_label())?;
    if reply.label == ipc::fs_labels::END_OF_DIR
    {
        return Ok(None);
    }
    if reply.label != 0
    {
        return Err(reply.label);
    }
    let kind = reply.word(0);
    // Name length is bounded by namespace_protocol::MAX_NAME_LEN (255);
    // truncating to usize is safe on every supported target.
    #[allow(clippy::cast_possible_truncation)]
    let len = reply.word(1) as usize;
    let bytes = reply.data_bytes();
    // Name bytes start at byte 16 (after words 0 and 1).
    let start = 16usize;
    let end = start.saturating_add(len).min(bytes.len());
    Ok(Some((kind, bytes[start..end].to_vec())))
}

/// Verify the main-thread stack guard page. Spawns `/bin/stackoverflow`
/// (a deliberate recursive stack consumer), waits for death, and asserts
/// the kernel reported a fault exit reason (`>= 0x1000`, the
/// `EXIT_FAULT_BASE` encoding used by both arches). Confirms that stack
/// overflow lands on `PROCESS_STACK_GUARD_VA` rather than corrupting
/// adjacent mappings.
// cast_sign_loss: ExitStatus::code() returns i32; exit_reason is always
// non-negative in practice (kernel-set 0, clean-exit 0, fault 0x1000+vec,
// killed 0x2000). Casting to u64 is safe.
#[allow(clippy::cast_sign_loss)]
fn stack_overflow_phase()
{
    use std::process::Command;

    // `EXIT_FAULT_BASE` from `syscall_abi` — any fault reports
    // `EXIT_FAULT_BASE + vector`. x86-64 page fault = 0x100E;
    // RISC-V store page fault = 0x100F; load page fault = 0x100D.
    // Accept any fault in the 0x1000..0x2000 range.
    const EXIT_FAULT_BASE: u64 = 0x1000;
    const EXIT_KILLED: u64 = 0x2000;

    let mut child = Command::new("/bin/stackoverflow")
        .spawn()
        .expect("spawn /bin/stackoverflow failed");

    let id = child.id();
    std::os::seraph::log!("spawned /bin/stackoverflow handle={id:#x}");

    let status = child.wait().expect("stackoverflow wait failed");
    std::os::seraph::log!("stackoverflow exited: {status}");

    assert!(
        !status.success(),
        "stackoverflow child must not exit cleanly: {status}"
    );

    let raw = status
        .code()
        .expect("stackoverflow ExitStatus must carry a code") as u64;
    assert!(
        (EXIT_FAULT_BASE..EXIT_KILLED).contains(&raw),
        "expected fault exit_reason in 0x1000..0x2000, got {raw:#x}"
    );

    // Auto-reap verification on the fault path. Procmgr's recent-exits
    // ring must record the same fault reason the spawner observed,
    // confirming `dispatch_death` runs on fault-exit observers as well as
    // clean-exit observers (both come from the same kernel
    // `post_death_notification` walk).
    {
        let info = startup_info();
        // cast_ptr_alignment: IPC buffer is page-aligned (4 KiB).
        #[allow(clippy::cast_ptr_alignment)]
        let ipc_buf = info.ipc_buffer.cast::<u64>();
        let query = ipc::IpcMessage::new(ipc::procmgr_labels::QUERY_PROCESS);
        // SAFETY: `ipc_buf` is the kernel-registered IPC buffer page.
        let reply = unsafe { ipc::ipc_call(id, &query, ipc_buf) }
            .expect("QUERY_PROCESS call after fault failed");
        assert_eq!(reply.label, ipc::procmgr_errors::SUCCESS);
        let state = reply.word(0);
        let exit_reason = reply.word(1);
        assert_eq!(
            state,
            ipc::procmgr_process_state::EXITED,
            "expected EXITED for faulted child, got {state}"
        );
        assert_eq!(
            exit_reason, raw,
            "auto-reap exit_reason {exit_reason:#x} does not match spawner-observed {raw:#x}"
        );
        std::os::seraph::log!("auto_reap_fault (EXITED) passed");
    }

    std::os::seraph::log!("stack_overflow phase passed (exit_reason={raw:#x})");
}

/// Sanity-check the `shmem::SpscRing` in-process: build a ring over a
/// stack-owned byte buffer, push a pattern, pop it back, assert equality.
/// Cross-process integration (pipes) is out of scope; this exercises only
/// the producer/consumer math and the atomic header.
fn shmem_phase()
{
    use shmem::{SpscHeader, SpscReader, SpscWriter};

    const CAP: usize = 64;
    #[repr(C, align(8))]
    struct Buf
    {
        header: SpscHeader,
        body: [u8; CAP],
    }
    #[allow(clippy::cast_possible_truncation)]
    let mut buf = Buf {
        header: SpscHeader {
            head: core::sync::atomic::AtomicU32::new(0),
            tail: core::sync::atomic::AtomicU32::new(0),
            capacity: CAP as u32,
            closed: core::sync::atomic::AtomicU32::new(0),
        },
        body: [0u8; CAP],
    };

    let region_vaddr = &raw mut buf as u64;
    // SAFETY: `buf` lives for the whole phase; header is pre-initialised by
    // the `Buf` literal above, so Init's job is already done.
    let (mut writer, mut reader): (SpscWriter<'_>, SpscReader<'_>) =
        unsafe { shmem::spsc_pair(region_vaddr) };

    let payload: [u8; 10] = [0xDE, 0xAD, 0xBE, 0xEF, 1, 2, 3, 4, 5, 6];
    let n = writer.write(&payload);
    assert_eq!(n, payload.len(), "writer.write full payload");

    let mut out = [0u8; 10];
    let m = reader.read(&mut out);
    assert_eq!(m, payload.len(), "reader.read full payload");
    assert_eq!(out, payload, "shmem round-trip mismatch");
    assert!(reader.is_empty(), "ring must be empty after full drain");

    // Fill-to-capacity and confirm further writes return zero.
    let big = [0xAAu8; CAP + 8];
    let pushed = writer.write(&big);
    assert_eq!(pushed, CAP, "writer must cap at ring capacity");
    assert_eq!(writer.write(&[0x11]), 0, "writer must reject when full");

    // Drain fully and re-check empty.
    let mut sink = [0u8; CAP];
    let drained = reader.read(&mut sink);
    assert_eq!(drained, CAP, "reader must drain capacity");
    assert!(sink.iter().all(|&b| b == 0xAA), "drained bytes mismatch");

    std::os::seraph::log!("shmem phase passed");
}

/// Exercise `Stdio::piped()` and `Command::output()` end-to-end.
///
/// Three sub-checks:
///   1. Spawn `/bin/hello` with `Stdio::piped()` on stdout. Drain the
///      ring to EOF, assert the captured bytes match what hello prints,
///      re-emit each line through `seraph::log!` so the boot log
///      surfaces hello's output indirectly under `[usertest]`.
///   2. Spawn `/bin/stdiotest` with all three streams piped. Write
///      `b"hello\n"` to its stdin (drop `ChildStdin` to flag EOF on the
///      child's `read_line`), drain its stdout to EOF, assert the
///      uppercased echo, re-emit through the log.
///   3. Run `Command::new("/bin/hello").output()` — round-trips through
///      the symmetric pipe + stdout-capture path. Assert clean exit
///      and matching captured stdout.
// pipes_phase orchestrates three sub-checks against a single
// `Stdio::piped()` integration; splitting hides the round-trip rather
// than clarifying it.
#[allow(clippy::too_many_lines)]
fn pipes_phase()
{
    use std::io::{Read, Write};
    use std::process::{Command, Stdio};

    // ── (1) hello capture ─────────────────────────────────────────────
    {
        let mut child = Command::new("/bin/hello")
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn /bin/hello (piped) failed");
        let mut stdout_bytes = Vec::new();
        {
            let mut out = child
                .stdout
                .take()
                .expect("piped child must have stdout handle");
            out.read_to_end(&mut stdout_bytes)
                .expect("read_to_end on hello stdout failed");
        }
        let body = String::from_utf8_lossy(&stdout_bytes);
        for line in body.lines()
        {
            std::os::seraph::log!("hello: {line}");
        }
        assert!(
            !stdout_bytes.is_empty(),
            "hello produced no stdout bytes — pipe wiring broken"
        );
        let status = child.wait().expect("hello wait failed");
        assert!(status.success(), "hello did not exit cleanly: {status}");
        std::os::seraph::log!("pipes: hello capture ok ({} bytes)", stdout_bytes.len());
    }

    // ── (2) stdiotest round-trip ──────────────────────────────────────
    {
        let mut child = Command::new("/bin/stdiotest")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn /bin/stdiotest (piped) failed");

        // Feed the input line, then drop ChildStdin so the child's
        // BufReader::read_line observes EOF and returns.
        {
            let mut stdin = child
                .stdin
                .take()
                .expect("piped child must have stdin handle");
            stdin
                .write_all(b"hello\n")
                .expect("write to stdiotest stdin failed");
        }

        let mut stdout_bytes = Vec::new();
        {
            let mut out = child
                .stdout
                .take()
                .expect("piped child must have stdout handle");
            out.read_to_end(&mut stdout_bytes)
                .expect("read_to_end on stdiotest stdout failed");
        }
        let body = String::from_utf8_lossy(&stdout_bytes);
        for line in body.lines()
        {
            std::os::seraph::log!("stdiotest: {line}");
        }
        // stdiotest's `read_line` counts include the trailing newline,
        // so 6 bytes for `b"hello\n"`.
        assert!(
            body.contains("got 6 bytes"),
            "stdiotest stdout missing byte-count line: {body:?}"
        );
        assert!(
            body.contains("shouted: HELLO"),
            "stdiotest stdout missing shout line: {body:?}"
        );
        assert!(
            body.contains("PASS"),
            "stdiotest stdout missing PASS marker: {body:?}"
        );

        // Drain stderr too (stdiotest only writes to stderr on
        // unexpected error paths; expected to be empty).
        if let Some(mut err) = child.stderr.take()
        {
            let mut stderr_bytes = Vec::new();
            err.read_to_end(&mut stderr_bytes)
                .expect("read_to_end on stdiotest stderr failed");
            if !stderr_bytes.is_empty()
            {
                let body = String::from_utf8_lossy(&stderr_bytes);
                for line in body.lines()
                {
                    std::os::seraph::log!("stdiotest.err: {line}");
                }
            }
        }

        let status = child.wait().expect("stdiotest wait failed");
        assert!(status.success(), "stdiotest did not exit cleanly: {status}");
        std::os::seraph::log!("pipes: stdiotest round-trip ok");
    }

    // ── (3) Command::output() round-trip ──────────────────────────────
    {
        let output = Command::new("/bin/hello")
            .output()
            .expect("Command::output on hello failed");
        assert!(
            output.status.success(),
            "hello via output() did not exit cleanly: {}",
            output.status
        );
        assert!(
            !output.stdout.is_empty(),
            "Command::output captured zero stdout bytes"
        );
        std::os::seraph::log!(
            "pipes: Command::output ok ({} stdout, {} stderr)",
            output.stdout.len(),
            output.stderr.len(),
        );
    }

    std::os::seraph::log!("pipes phase passed");
}

/// Spawn `/bin/pipefault` with `Stdio::piped()` on stdout. The child
/// writes `b"prefix\n"`, flushes, and faults — `Pipe::Drop` never
/// runs, so the ring header's `closed` flag is never set. Without
/// the death-bridge the parent's `read_to_end` would park forever in
/// `signal_wait` after draining the prefix. With the bridge, the
/// kernel posts the fault on the spawner's death-EQ, the bridge
/// translates it into `peer_dead.store(true)` plus a kick on the
/// data signal, and the next `Pipe::read` returns EOF.
///
/// Asserts:
///   * `read_to_end` returns Ok with the prefix bytes (no hang).
///   * `child.wait()` returns a fault `exit_reason` in
///     `EXIT_FAULT_BASE..EXIT_KILLED`.
///   * `QUERY_PROCESS` reports `EXITED` with the same `exit_reason`
///     (auto-reap from §7 still works through the new bridge).
// cast_sign_loss: ExitStatus::code() returns i32; exit_reason is always
// non-negative in practice (clean=0, fault 0x1000+vec, killed 0x2000).
#[allow(clippy::cast_sign_loss)]
fn pipe_fault_eof_phase()
{
    use std::io::Read;
    use std::process::{Command, Stdio};

    const EXIT_FAULT_BASE: u64 = 0x1000;
    const EXIT_KILLED: u64 = 0x2000;

    let mut child = Command::new("/bin/pipefault")
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn /bin/pipefault failed");

    let id = child.id();
    std::os::seraph::log!("spawned /bin/pipefault handle={id:#x}");

    let mut stdout = child.stdout.take().expect("piped stdout missing");
    let mut bytes = Vec::new();
    let n = stdout
        .read_to_end(&mut bytes)
        .expect("read_to_end on pipefault stdout failed");
    assert_eq!(
        n,
        bytes.len(),
        "read_to_end length mismatch ({n} vs {})",
        bytes.len()
    );
    assert!(
        bytes.starts_with(b"prefix\n"),
        "pipefault stdout missing prefix: {:?}",
        String::from_utf8_lossy(&bytes)
    );
    std::os::seraph::log!(
        "pipe_fault_eof: drained {} bytes, EOF observed without hang",
        bytes.len()
    );

    let status = child.wait().expect("pipefault wait failed");
    let raw = status
        .code()
        .expect("pipefault ExitStatus must carry a code") as u64;
    assert!(
        (EXIT_FAULT_BASE..EXIT_KILLED).contains(&raw),
        "expected pipefault fault exit_reason in 0x1000..0x2000, got {raw:#x}"
    );

    // Auto-reap mirror check.
    {
        let info = startup_info();
        // cast_ptr_alignment: IPC buffer is page-aligned (4 KiB).
        #[allow(clippy::cast_ptr_alignment)]
        let ipc_buf = info.ipc_buffer.cast::<u64>();
        let query = ipc::IpcMessage::new(ipc::procmgr_labels::QUERY_PROCESS);
        // SAFETY: `ipc_buf` is the kernel-registered IPC buffer page.
        let reply = unsafe { ipc::ipc_call(id, &query, ipc_buf) }
            .expect("QUERY_PROCESS for pipefault failed");
        assert_eq!(reply.label, ipc::procmgr_errors::SUCCESS);
        let state = reply.word(0);
        let exit_reason = reply.word(1);
        assert_eq!(
            state,
            ipc::procmgr_process_state::EXITED,
            "expected EXITED for faulted piped child, got {state}"
        );
        assert_eq!(
            exit_reason, raw,
            "auto-reap exit_reason {exit_reason:#x} disagrees with spawner-observed {raw:#x}"
        );
    }

    std::os::seraph::log!("pipe_fault_eof phase passed (exit_reason={raw:#x})");
}

/// Verify `std::env::args()` returns exactly what init wrote into the
/// `CREATE_PROCESS` argv blob: `["usertest", "run"]`. Exercises the
/// end-to-end argv plumbing (init → procmgr → `ProcessInfo` page →
/// `_start` → `std::env::args`).
fn args_phase()
{
    let collected: Vec<String> = std::env::args().collect();
    for (i, a) in collected.iter().enumerate()
    {
        std::os::seraph::log!("argv[{i}]={a:?}");
    }
    assert_eq!(
        collected.len(),
        2,
        "expected 2 args, got {}",
        collected.len()
    );
    assert_eq!(collected[0], "usertest", "argv[0] mismatch");
    assert_eq!(collected[1], "run", "argv[1] mismatch");
    std::os::seraph::log!("args phase passed");
}

/// Exercise `std::env::{var, vars, set_var, remove_var}`.
///
/// Init seeds the env blob with `SERAPH_TEST=1` and `SERAPH_MODE=boot`; the
/// first half of the phase asserts both are visible straight from startup,
/// proving the `ProcessInfo` → `_start::env_blob` → `BTreeMap` seed path.
/// The second half exercises in-process mutation (`set_var`, overwrite,
/// `remove_var`) on top of that seed.
fn env_phase()
{
    use std::env;

    // Init-seeded values — must be visible without any set_var call.
    assert_eq!(
        env::var("SERAPH_TEST").unwrap_or_default(),
        "1",
        "init-seeded SERAPH_TEST missing"
    );
    assert_eq!(
        env::var("SERAPH_MODE").unwrap_or_default(),
        "boot",
        "init-seeded SERAPH_MODE missing"
    );
    assert!(
        env::var("SERAPH_NOPE").is_err(),
        "unset key must return Err"
    );
    assert_eq!(env::vars().count(), 2, "expected 2 seeded entries");

    // In-process mutation on top of seed.
    // SAFETY: usertest is single-threaded at this point in main.
    unsafe {
        env::set_var("FOO", "bar");
        env::set_var("BAZ", "qux");
    }
    assert_eq!(env::var("FOO").unwrap_or_default(), "bar");
    assert_eq!(env::var("BAZ").unwrap_or_default(), "qux");

    // Overwrite semantics on a seeded key.
    // SAFETY: still single-threaded.
    unsafe {
        env::set_var("SERAPH_MODE", "test");
    }
    assert_eq!(env::var("SERAPH_MODE").unwrap_or_default(), "test");

    // Iterator must enumerate all current entries.
    let all: Vec<(String, String)> = env::vars().collect();
    assert_eq!(all.len(), 4, "expected 4 entries, got {}", all.len());

    // SAFETY: single-threaded.
    unsafe {
        env::remove_var("FOO");
    }
    assert!(env::var("FOO").is_err(), "removed key must return Err");
    assert_eq!(env::vars().count(), 3, "three entries must remain");

    std::os::seraph::log!("env phase passed");
}

/// Verify the main-thread stack envelope reported through `ProcessInfo`.
///
/// usertest declares no `.note.seraph.stack` note, so it inherits
/// `DEFAULT_PROCESS_STACK_PAGES = 8`. Reads the envelope from the
/// `StartupInfo` populated by `_start` and asserts the page count and
/// stack-top VA match the loader-side defaults. Also walks down through
/// the stack with a probing local to confirm the live mapping really
/// covers the declared range.
fn stack_envelope_phase()
{
    let info = startup_info();
    assert_eq!(
        info.stack_pages, 8,
        "usertest declares no stack note; expected default of 8 pages, got {}",
        info.stack_pages
    );
    assert_eq!(
        info.stack_top_vaddr, 0x0000_7FFF_FFFF_E000,
        "stack_top_vaddr {:#x} does not match PROCESS_STACK_TOP",
        info.stack_top_vaddr
    );

    // SP at this point sits inside the live stack range. The reported
    // envelope must contain it — proves loader and child agree on the
    // mapping.
    let sp_probe = 0u64;
    let sp = core::ptr::addr_of!(sp_probe) as u64;
    let stack_base = info.stack_top_vaddr - u64::from(info.stack_pages) * 4096;
    assert!(
        (stack_base..info.stack_top_vaddr).contains(&sp),
        "SP {sp:#x} outside reported stack range \
         [{stack_base:#x}, {top:#x})",
        top = info.stack_top_vaddr
    );

    std::os::seraph::log!(
        "stack envelope phase passed (pages={}, top={:#x})",
        info.stack_pages,
        info.stack_top_vaddr
    );
}

/// Verify the main thread sees the template-initialised value of a
/// `#[thread_local]` `.tdata` static, a zero for a `.tbss` static, and
/// can write through a `Cell<u32>` in TLS. Runs before any spawn so the
/// only TLS setup exercised is procmgr's main-thread block.
fn tls_main_phase()
{
    let init = TLS_INIT;
    let bss = TLS_BSS;
    std::os::seraph::log!("TLS_INIT ={init:#018x}");
    std::os::seraph::log!("TLS_BSS  ={bss:#018x}");
    assert_eq!(init, 0xDEAD_BEEF_CAFE_BABE, "TLS_INIT tdata readback");
    assert_eq!(bss, 0, "TLS_BSS tbss readback");
    for i in 1..=4u32
    {
        TLS_COUNTER.set(i);
        assert_eq!(TLS_COUNTER.get(), i, "TLS_COUNTER set/get");
    }
    std::os::seraph::log!("TLS main-thread phase passed");
}

/// Exercise the allocator across the canonical collection types.
fn alloc_phase()
{
    let boxed: Box<u64> = Box::new(0xDEAD_BEEF_CAFE_BABE);
    std::os::seraph::log!("Box<u64>={:#018x}", *boxed);

    let mut v: Vec<u64> = Vec::new();
    for i in 0u64..64
    {
        v.push(i);
    }
    let sum: u64 = v.iter().sum();
    std::os::seraph::log!("Vec sum(0..64)={sum:#018x}");
    let popped = v.pop().unwrap_or(0);
    std::os::seraph::log!("Vec::pop={popped:#018x}");

    let mut s = String::new();
    for _ in 0..8
    {
        s.push_str("seraph ");
    }
    std::os::seraph::log!("String::len={:#018x}", s.len() as u64);

    let mut m: BTreeMap<u64, u64> = BTreeMap::new();
    for k in 0u64..16
    {
        m.insert(k, k * 100);
    }
    std::os::seraph::log!("BTreeMap::len={:#018x}", m.len() as u64);
    if let Some(&v10) = m.get(&10)
    {
        std::os::seraph::log!("BTreeMap[10]={v10:#018x}");
    }

    drop(boxed);
    drop(v);
    drop(s);
    drop(m);
    std::os::seraph::log!("dealloc churn complete");
}

/// Stress-test the free-list allocator across many alloc/dealloc pairs at
/// varying non-multiple-of-`NODE_ALIGN` sizes. Guards against regression of
/// the `Heap::alloc` split-remainder alignment fix: without
/// `align_up(want, NODE_ALIGN)`, `Vec::push`-driven grows on `Vec<u8>`
/// tripped `ptr::write`'s alignment precondition under build-std debug and
/// silently aborted.
fn churn_phase()
{
    const ITERS: u32 = 10_000;
    let mut seed: u32 = 0x1337_BEEF;
    let mut keep: Vec<Vec<u8>> = Vec::with_capacity(8);
    for i in 0..ITERS
    {
        // xorshift32 — deterministic and free of allocation.
        seed ^= seed << 13;
        seed ^= seed >> 17;
        seed ^= seed << 5;
        let size: usize = match seed & 0xF
        {
            0 => 1,
            1 => 5,
            2 => 10,
            3 => 17,
            4 => 23,
            5 => 31,
            6 => 63,
            7 => 77,
            8 => 128,
            9 => 200,
            10 => 500,
            11 => 777,
            _ => ((seed >> 4) & 0x3FF) as usize + 1,
        };
        // Start from a smaller capacity so `push` exercises `grow_amortized`
        // with odd-size Layouts — that is the precise path that exposed the
        // alignment bug.
        let mut v: Vec<u8> = Vec::with_capacity(size / 2 + 1);
        for b in 0..size
        {
            #[allow(clippy::cast_possible_truncation)]
            v.push((b & 0xFF) as u8);
        }
        assert_eq!(v.len(), size, "push count mismatch at iter {i}");
        if i.trailing_zeros() >= 3
        {
            keep.push(v);
            if keep.len() > 8
            {
                // Drop-from-front exercises frees interleaved with the live
                // set, so coalescing has to reunite non-adjacent blocks.
                let _ = keep.remove(0);
            }
        }
    }
    drop(keep);
    std::os::seraph::log!("churn phase passed ({ITERS} iters)");
}

/// Exercise the allocator's grow-on-failure path. Allocates a buffer
/// larger than `HEAP_INITIAL_PAGES * PAGE_SIZE`, forcing the first-fit
/// search to fail and the retry in `System::alloc` to request fresh
/// frames from procmgr, map them above `mapped_end`, extend the free
/// list, and re-serve the allocation. Without the grow path this
/// allocation aborts the process before reaching `ALL TESTS PASSED`.
// cast_possible_truncation: index-to-u8 casts use `& 0xFF` or small counts;
// truncation is the intended identity fingerprint for spot-checks.
#[allow(clippy::cast_possible_truncation)]
fn alloc_grow_phase()
{
    // Initial heap is 128 pages (512 KiB). Allocate 600 KiB — large
    // enough to miss first-fit against the initial heap and force the
    // allocator's grow path, small enough to stay within one
    // `GROW_MAX_PAGES` increment (64 pages = 256 KiB) and well within
    // the usertest CSpace's remaining cap-slot headroom. Pushing the
    // upper bound higher exposes the CSpace-exhaustion wedge documented
    // in `ruststd/src/sys/alloc/seraph.rs` at the grow-path comment.
    const BIG: usize = 600 * 1024;

    let mut big: Vec<u8> = Vec::with_capacity(BIG);
    for i in 0..BIG
    {
        big.push((i & 0xFF) as u8);
    }
    assert_eq!(big.len(), BIG, "grow-path push count mismatch");

    // Spot-check a handful of indices to catch any corruption in the
    // grown region (e.g. misaligned free-list insert).
    for &idx in &[0, 1, 4095, 4096, 65_535, 65_536, BIG / 2, BIG - 1]
    {
        let expected = (idx & 0xFF) as u8;
        assert_eq!(big[idx], expected, "grow buffer[{idx}] mismatch");
    }

    // Interleave smaller allocations against the live big buffer so
    // coalescing across a grow-boundary has to work.
    let mut small: Vec<Vec<u8>> = Vec::with_capacity(8);
    for k in 0..8usize
    {
        small.push(vec![k as u8; 1024]);
    }
    for (k, v) in small.iter().enumerate()
    {
        assert_eq!(v.len(), 1024);
        assert_eq!(v[0], k as u8);
    }

    drop(small);
    drop(big);

    // Heap must still be usable after the grow + drop cycle.
    let post: Vec<u32> = (0..4096u32).collect();
    assert_eq!(post.last().copied(), Some(4095));

    std::os::seraph::log!("alloc_grow phase passed ({BIG} bytes + 8 KiB interleaved)");
}

/// Minimum-viable threading test: two workers each increment a shared
/// `Mutex<u32>` `ITERS` times; joined total must equal `2 * ITERS`. Folded
/// into usertest rather than a dedicated crate because usertest is the
/// generic test driver — a second crate for one assertion is churn.
fn threading_phase()
{
    const ITERS: u32 = 1_000;
    let counter = Arc::new(Mutex::new(0u32));

    let handles: Vec<_> = (0..2)
        .map(|_| {
            let c = counter.clone();
            thread::spawn(move || {
                for _ in 0..ITERS
                {
                    let mut guard = c.lock().expect("mutex poisoned");
                    *guard += 1;
                }
            })
        })
        .collect();

    for h in handles
    {
        h.join().expect("worker thread panicked");
    }

    let final_value = *counter.lock().expect("mutex poisoned");
    std::os::seraph::log!(
        "threading workers joined, counter={:#018x} expected={:#018x}",
        u64::from(final_value),
        u64::from(2 * ITERS),
    );
    assert_eq!(
        final_value,
        2 * ITERS,
        "threading test: counter mismatch (expected {})",
        2 * ITERS
    );
    std::os::seraph::log!("threading phase passed");
}

/// Regression guard for the per-thread stdio IPC buffer invariant.
/// Pre-fix, stdio cached the main thread's IPC buffer VA in a
/// process-global pointer; a `std::os::seraph::log!` on a spawned thread wrote into
/// that page while the kernel serviced `SYS_IPC_CALL` by reading the
/// spawned thread's registered buffer (`tcb.ipc_buffer`). The message
/// was silently dropped. This phase spawns a thread that calls
/// `std::os::seraph::log!` from the spawned thread and joins; the assertion is that
/// the operation does not panic, hang, or crash — the actual payload
/// landing in the log is confirmed by the harness grepping for the
/// marker line.
fn stdio_spawned_phase()
{
    let handle = thread::spawn(|| {
        std::os::seraph::log!("stdio_spawned marker line");
    });
    handle.join().expect("stdio_spawned worker thread panicked");
    std::os::seraph::log!("stdio_spawned phase passed");
}

/// Regression guard for the per-thread IPC buffer invariant in the
/// allocator. Pre-fix, `Heap::grow_exact` issued its `REQUEST_FRAMES`
/// IPC to procmgr using the main thread's IPC buffer VA, while the
/// kernel read the calling thread's registered buffer. On a spawned
/// thread the call silently produced a zero-label reply (stale buffer
/// contents), `grow` returned false, and the alloc aborted via
/// `handle_alloc_error`. This phase spawns a thread and pushes enough
/// bytes to exhaust the post-bootstrap free list and force at least
/// one grow round. If grow is wired through the per-thread TLS buffer,
/// the push completes and join succeeds.
// cast_possible_truncation: index-to-u8 casts use `& 0xFF` as a
// deliberate identity fingerprint, matching `alloc_grow_phase`.
#[allow(clippy::cast_possible_truncation)]
fn alloc_spawned_phase()
{
    // Same sizing reasoning as `alloc_grow_phase` — large enough to
    // miss first-fit, small enough to stay within one grow increment
    // and well within CSpace headroom.
    const BIG: usize = 600 * 1024;

    let handle = thread::spawn(|| {
        let mut v: Vec<u8> = Vec::with_capacity(BIG);
        for i in 0..BIG
        {
            v.push((i & 0xFF) as u8);
        }
        assert_eq!(v.len(), BIG, "spawned-grow push count mismatch");
        // Spot-check a few indices past the first grow boundary.
        for &idx in &[0, 4095, 4096, 65_535, BIG / 2, BIG - 1]
        {
            let expected = (idx & 0xFF) as u8;
            assert_eq!(v[idx], expected, "spawned-grow buffer[{idx}] mismatch");
        }
    });
    handle.join().expect("alloc_spawned worker thread panicked");
    std::os::seraph::log!("alloc_spawned phase passed ({BIG} bytes)");
}

/// Exercise the `thread_local!` macro. This drives the `LazyStorage` +
/// `destructors::register` path (unlike the raw `#[thread_local]` statics in
/// `tls_main_phase`, which skip the lazy wrapper). The inner type is `Drop`
/// so every access triggers first-time destructor registration against
/// `DTORS: #[thread_local] RefCell<Vec<_, System>>`, which was the specific
/// failure mode during the native-TLS bring-up.
fn tls_macro_phase()
{
    std::thread_local! {
        static COUNTER: Cell<Vec<u32>> = const { Cell::new(Vec::new()) };
    }

    COUNTER.with(|c| {
        let mut v = c.take();
        for i in 0..8u32
        {
            v.push(i);
        }
        c.set(v);
    });
    let sum: u32 = COUNTER.with(|c| {
        let v = c.take();
        let s = v.iter().sum();
        c.set(v);
        s
    });
    std::os::seraph::log!("thread_local! Vec<u32> sum(0..8)={sum:#018x}");
    assert_eq!(sum, 28, "thread_local! macro sum mismatch");

    let handle = thread::spawn(|| {
        COUNTER.with(|c| {
            let v = c.take();
            // Fresh thread → fresh thread_local → empty Vec.
            let was_empty = v.is_empty();
            let mut w = v;
            w.push(0xAAu32);
            w.push(0xBBu32);
            c.set(w);
            let got: u32 = COUNTER.with(|c2| {
                let v2 = c2.take();
                let s = v2.iter().sum();
                c2.set(v2);
                s
            });
            (was_empty, got)
        })
    });
    let (was_empty, got) = handle.join().expect("tls_macro child panicked");
    assert!(was_empty, "child thread_local! should start empty");
    assert_eq!(got, 0xAAu32 + 0xBBu32, "child thread_local! sum mismatch");
    std::os::seraph::log!("thread_local! child sum={got:#018x}");
    std::os::seraph::log!("thread_local! macro phase passed");
}

/// Exercise `Condvar::wait_timeout` over the kernel's `SYS_SIGNAL_WAIT`
/// timeout path. Two sub-checks:
///
/// 1. A wait on a `Condvar` that nobody notifies returns after the full
///    timeout and reports `timed_out() == true`.
/// 2. A wait that a second thread notifies partway through returns
///    early with `timed_out() == false` — proves the signal path still
///    wakes the waiter before the timer fires.
fn timeout_phase()
{
    // (1) True timeout — no notifier.
    let cv = Condvar::new();
    let m = Mutex::new(());
    let guard = m.lock().expect("mutex poisoned");
    let t0 = Instant::now();
    let (_guard, result) = cv
        .wait_timeout(guard, Duration::from_millis(50))
        .expect("wait_timeout failed");
    let elapsed = t0.elapsed();
    assert!(result.timed_out(), "expected timeout but got early wake");
    assert!(
        elapsed >= Duration::from_millis(40),
        "timeout returned too early: {elapsed:?}",
    );
    std::os::seraph::log!(
        "wait_timeout: timed_out after {:#x} us",
        u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX)
    );

    // (2) Early wake — a notifier fires inside the timeout window.
    let pair: Arc<(Mutex<bool>, Condvar)> = Arc::new((Mutex::new(false), Condvar::new()));
    let pair2 = pair.clone();
    let _notifier = thread::spawn(move || {
        thread::sleep(Duration::from_millis(50));
        let (lock, cv) = &*pair2;
        let mut flag = lock.lock().expect("mutex poisoned");
        *flag = true;
        cv.notify_one();
    });

    let (lock, cv) = &*pair;
    let flag = lock.lock().expect("mutex poisoned");
    let t0 = Instant::now();
    let (flag, result) = cv
        .wait_timeout_while(flag, Duration::from_secs(1), |f| !*f)
        .expect("wait_timeout_while failed");
    let elapsed = t0.elapsed();
    assert!(*flag, "notifier flag not set on wake");
    assert!(
        !result.timed_out(),
        "wait woke but wait_timeout_while reports timeout",
    );
    assert!(
        elapsed < Duration::from_millis(500),
        "notify did not wake early: {elapsed:?}",
    );
    std::os::seraph::log!(
        "wait_timeout: notified after {:#x} us",
        u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX)
    );
    std::os::seraph::log!("timeout phase passed");
}

/// Exercise `std::process::Command::spawn` + `Child::wait`.
///
/// Spawns `/bin/hello` (a minimal cap-oblivious tier-2 binary that prints a
/// line and exits), then blocks on `wait()`. Kernel posts the child's exit
/// reason to a death-notification `EventQueue` procmgr bound at spawn time;
/// `wait()` dequeues it and reports it as an `ExitStatus`. Clean thread
/// exit (`SYS_THREAD_EXIT`) surfaces as reason 0 ⇒ `status.success()`.
///
/// Also passes a non-empty argv and env so the `CREATE_FROM_FILE` wire
/// format (which mirrors `CREATE_PROCESS`'s argv/env encoding) is
/// exercised end-to-end. `hello` ignores its argv/env — we only assert a
/// clean exit here; the packing + procmgr parsing path is what's under
/// test, not the receiving side.
fn spawn_phase()
{
    use std::process::Command;

    // Exercises the full spawn wire: argv blob + env blob end up in the
    // child's ProcessInfo page. /bin/hello ignores them and exits cleanly;
    // assertion here is on the spawn-side round-trip (no crash, clean
    // exit), not on the child's receipt.
    let mut child = Command::new("/bin/hello")
        .arg("one")
        .arg("two")
        .env("SPAWNED_BY", "usertest")
        .spawn()
        .expect("spawn /bin/hello failed");

    let id = child.id();
    std::os::seraph::log!("spawned /bin/hello handle={id:#x}");

    // Exercise procmgr's QUERY_PROCESS IPC before `wait()`. Two valid
    // outcomes: `ALIVE` (we won the race against the child's exit + the
    // auto-reap drain) or `EXITED` (auto-reap already saw the death and
    // moved the entry to the recent-exits ring). `/bin/hello` exits in
    // microseconds; either result indicates the IPC plumbing works.
    {
        let info = startup_info();
        // cast_ptr_alignment: IPC buffer is page-aligned (4 KiB), satisfying u64 alignment.
        #[allow(clippy::cast_ptr_alignment)]
        let ipc_buf = info.ipc_buffer.cast::<u64>();
        let id = child.id();
        let query = ipc::IpcMessage::new(ipc::procmgr_labels::QUERY_PROCESS);
        // SAFETY: `ipc_buf` is the kernel-registered, page-aligned IPC
        // buffer page installed by `_start`.
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
        "child /bin/hello did not exit cleanly: {status}"
    );

    // After wait() has consumed the exit, try_wait must surface the cached
    // status non-blockingly (Ok(Some(_))).
    let again = child.try_wait().expect("try_wait after wait failed");
    assert!(
        again.is_some(),
        "try_wait after wait must surface cached status"
    );
    std::os::seraph::log!("try_wait phase passed");

    // Auto-reap verification. Procmgr's `dispatch_death` runs on the next
    // service-endpoint wakeup; the child's death event was posted to
    // procmgr's shared `death_eq` when the kernel wrote `Exited`, and
    // procmgr drains the queue at the top of every iteration. By the time
    // this `QUERY_PROCESS` lands, procmgr has already consumed the death
    // event, removed the table entry, and stashed the exit reason in the
    // recent-exits ring — so the reply must be `EXITED` with
    // `exit_reason == 0` (clean voluntary exit).
    {
        let info = startup_info();
        // cast_ptr_alignment: IPC buffer is page-aligned (4 KiB).
        #[allow(clippy::cast_ptr_alignment)]
        let ipc_buf = info.ipc_buffer.cast::<u64>();
        let query = ipc::IpcMessage::new(ipc::procmgr_labels::QUERY_PROCESS);
        // SAFETY: `ipc_buf` is the kernel-registered, page-aligned IPC
        // buffer page installed by `_start`.
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

/// `Command::cwd("/srv")` resolves the path against the spawner's
/// `root_dir_cap()` to a directory cap that is then delivered to the
/// child via `procmgr_labels::CONFIGURE_NAMESPACE` (`caps[1]`,
/// alongside the inherited root cap in `caps[0]`). The child's
/// `std::os::seraph::current_dir_cap()` must become non-zero and
/// address `/srv` such that a relative `File::open("test.txt")`
/// succeeds.
///
/// Asserts the positive case end-to-end by respawning `/bin/usertest
/// cwd-child` with `.cwd("/srv")`. The child path encodes its
/// observations into the exit code (see [`cwd_child_main`]); any
/// failure mode produces a distinct non-zero code so the regression
/// surface is identifiable.
fn command_cwd_inherit_phase()
{
    use std::process::Command;

    let mut child = Command::new("/bin/usertest")
        .arg("cwd-child")
        .current_dir("/srv")
        .spawn()
        .expect("Command::cwd(/srv) must spawn cleanly");
    let status = child.wait().expect("wait on cwd-inherit child failed");
    let code = status.code().unwrap_or(-1);
    assert_eq!(
        code, 0,
        "cwd-inherit child exit code {code}: \
         4=current_dir_cap zero, 5=relative open failed (see cwd_child_main)"
    );
    std::os::seraph::log!("command_cwd_inherit phase passed");
}

/// `Command::cwd` with an unreachable path must fail loudly via
/// `spawn()` rather than silently delivering `cwd=0` to the child.
/// The walk error from `walk_path_to_dir` propagates through
/// `io::Error` and the partial child is torn down before `spawn`
/// returns.
fn command_cwd_missing_phase()
{
    use std::process::Command;

    let err = Command::new("/bin/usertest")
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

/// Spawning a non-ELF path must reject the request without leaking the
/// caller-transferred file cap into procmgr or the fs-side open-file
/// slot. With the leak intact, the fatfs `MAX_OPEN_FILES` ceiling
/// exhausts after a small number of failed spawns; with the fix, the
/// loop completes and a legitimate spawn afterwards still succeeds.
fn command_invalid_elf_loop_phase()
{
    use std::process::Command;

    for i in 0..16
    {
        let err = Command::new("/srv/test.txt")
            .spawn()
            .expect_err("spawning a non-ELF path must fail");
        let _ = i;
        let _ = err;
    }

    let mut child = Command::new("/bin/hello")
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

/// Cap-native cwd surface: `set_current_dir` walks `root_dir_cap()` to
/// a path and installs the resulting directory cap as
/// `current_dir_cap()`. Subsequent `File::open` of a relative path
/// anchors at that cap rather than the root. Asserts both the install
/// and the relative open succeed.
fn fs_open_relative_phase()
{
    use std::fs::File;
    use std::io::Read;

    // Pre-condition: no cwd cap installed (children inherit zero by
    // default unless the spawner set one). Relative open should fail
    // with Unsupported.
    assert_eq!(
        std::os::seraph::current_dir_cap(),
        0,
        "fs_open_relative_phase pre-condition: cwd cap should start zero",
    );
    let pre_err = File::open("test.txt").expect_err("relative open without cwd must fail");
    assert_eq!(pre_err.kind(), std::io::ErrorKind::Unsupported);

    // Install /srv as cwd via the cap-native primitive. The walk goes
    // through vfsd's synthetic root.
    std::os::seraph::set_current_dir("/srv").expect("set_current_dir(/srv) failed");
    assert_ne!(std::os::seraph::current_dir_cap(), 0);

    // Cap-native `set_current_dir` also records the path string under
    // the same Mutex as the cap, so `std::env::current_dir` sees `/srv`
    // immediately afterwards. The two writers (cap-native and std-env)
    // converge on the same backing store.
    assert_eq!(
        std::env::current_dir().expect("std::env::current_dir after cap-native set"),
        std::path::PathBuf::from("/srv"),
        "std::env::current_dir disagrees with cap-native set_current_dir",
    );

    // The std-portable `std::env::set_current_dir` path: same lockstep
    // result, observable through both surfaces. Re-target /srv (same
    // directory) so we can compare against the prior assertions
    // without disturbing the cap-pressure expectations of subsequent
    // assertions in this phase.
    std::env::set_current_dir("/srv").expect("std::env::set_current_dir(/srv) failed");
    assert_ne!(std::os::seraph::current_dir_cap(), 0);
    assert_eq!(
        std::env::current_dir().expect("std::env::current_dir after std-env set"),
        std::path::PathBuf::from("/srv"),
    );

    // Relative open now succeeds and reads the same bytes the absolute
    // path would yield.
    let mut f = File::open("test.txt").expect("relative open after set_current_dir failed");
    let mut buf = String::new();
    f.read_to_string(&mut buf).expect("relative read failed");
    assert!(!buf.is_empty(), "relative open returned empty file");

    // Absolute paths still anchor at root_dir_cap(), unaffected by cwd.
    let abs_meta = File::open("/srv/test.txt")
        .expect("absolute open after set_current_dir failed")
        .metadata()
        .expect("absolute metadata failed");
    assert_eq!(
        abs_meta.len(),
        buf.len() as u64,
        "absolute and relative opens disagree on size",
    );

    std::os::seraph::log!("fs_open_relative phase passed");
}

/// `std::env::current_dir` returns `Unsupported` until something calls
/// `set_current_dir` in this process. The startup cap installed from
/// `ProcessInfo.current_dir_cap` does not carry a path string, and the
/// namespace protocol forbids `..` / `.` as name components
/// (`shared/namespace-protocol/src/name.rs`), so seraph has no
/// FS-walking way to recover a string from a bare cap. The shape
/// surfaces as `io::ErrorKind::Unsupported` rather than `NotFound`
/// because the cwd directory *exists*; only its string label is
/// absent.
///
/// MUST run before `fs_open_relative_phase`: that phase installs the
/// path string permanently via `set_current_dir("/srv")`.
fn env_cwd_unset_phase()
{
    assert_eq!(
        std::os::seraph::current_dir_cap(),
        0,
        "env_cwd_unset_phase pre-condition: cwd cap should still be zero",
    );
    let err = std::env::current_dir()
        .expect_err("std::env::current_dir() with no recorded path must fail");
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::Unsupported,
        "std::env::current_dir() pre-set should be Unsupported, got {err:?}",
    );
    std::os::seraph::log!("env_cwd_unset phase passed");
}

/// `Stdio::from(File)` is rejected at spawn on seraph rather than
/// silently producing a child with default stdio. Asserts the
/// loud-failure shape on the stdout slot.
fn stdio_file_unsupported_phase()
{
    use std::fs::File;
    use std::io::ErrorKind;
    use std::process::{Command, Stdio};

    let file = File::open("/srv/test.txt").expect("open /srv/test.txt for stdio probe");
    let err = Command::new("/bin/hello")
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
