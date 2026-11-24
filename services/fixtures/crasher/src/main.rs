// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/fixtures/crasher/src/main.rs

//! Deliberate-crash fixture validating svcmgr's restart path.
//!
//! Three roles, chosen by `argv[1]`: `selftest` checks its restart surfaces and
//! faults its main thread; `worker-fault` serves `ipc::restart_probe_labels`
//! and, on request, faults a worker thread; `boot-fault` faults its main
//! thread before its bootstrap request when it finds a token file, and is
//! `worker-fault` otherwise. Gating, the surface checks, the fail rules, and
//! the capability slots are defined in `services/fixtures/crasher/README.md`.

use std::os::seraph::startup_info;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use ipc::{IpcMessage, restart_probe_labels};

fn main()
{
    std::os::seraph::log::register_name(b"crasher");
    let info = startup_info();

    let role = std::env::args().nth(1);
    if matches!(role.as_deref(), Some("worker-fault" | "boot-fault"))
    {
        #[expect(
            clippy::cast_ptr_alignment,
            reason = "the IPC buffer is page-aligned (4 KiB), satisfying u64 alignment"
        )]
        let ipc_buf = info.ipc_buffer.cast::<u64>();
        if role.as_deref() == Some("boot-fault")
        {
            take_boot_fault_token();
        }
        worker_fault_role(info.creator_endpoint, ipc_buf);
    }

    // Assert the recipe surfaces are present on THIS spawn — first launch
    // and every restart. Each logs `<surface> ok` or a `FATAL:` mismatch.
    check_argv();
    check_env();
    check_cwd();

    let (svcmgr_cap, second_cap, cap_count) =
        bootstrap_caps(info.creator_endpoint, info.ipc_buffer);
    check_seeds(svcmgr_cap, second_cap, cap_count);

    std::os::seraph::log!("alive (bootstrap caps={cap_count})");

    if svcmgr_cap != 0
    {
        probe_svcmgr(svcmgr_cap, info.ipc_buffer);
    }

    // Brief settle so the surface assertions land before the fault report.
    // Co-staged with svctest, crasher's bounded faults finish long before
    // svctest's terminal marker, so the kernel fault dump never clobbers it.
    thread::sleep(Duration::from_millis(500));

    std::os::seraph::log!("triggering fault");
    fault_main()
}

/// Fault the calling thread: a write to the null pointer.
/// x86-64: #PF (vector 14) for unmapped page.
/// RISC-V: store page fault (scause 15).
fn fault_main() -> !
{
    // SAFETY: deliberately invalid — this is the point.
    unsafe {
        core::ptr::write_volatile(core::ptr::null_mut::<u8>(), 0x42);
    }

    // SAFETY: unreachable — the write above faults and the kernel kills this thread.
    unsafe { core::hint::unreachable_unchecked() }
}

/// The `boot-fault` role's token, in its namespace (`/data/crasher-boot` in
/// its recipe, `rootfs/config/svcmgr/tests/crasher-boot.svc`). The data
/// partition ships it (`rootfs/data/crasher-boot/die-early`), and svctest's
/// `svcmgr_boot_death` phase writes it again.
const BOOT_FAULT_TOKEN: &str = "/die-early";

/// The `boot-fault` role's first step: when [`BOOT_FAULT_TOKEN`] is there,
/// remove it and fault the main thread before the bootstrap request, so
/// svcmgr's wait for the request ends at this instance's death; return when it
/// is not, the instance then serving as `worker-fault`. Removing the token
/// makes one instance die so per token. A namespace that cannot be read logs
/// `FATAL:`.
fn take_boot_fault_token()
{
    match std::fs::remove_file(BOOT_FAULT_TOKEN)
    {
        Ok(()) =>
        {
            std::os::seraph::log!("boot-fault: token taken; faulting before the bootstrap request");
            fault_main()
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound =>
        {}
        Err(e) =>
        {
            std::os::seraph::log!("FATAL: boot-fault: token not removed: {e}");
            syscall::thread_exit();
        }
    }
}

/// Assert argv survived the (re)spawn: the recipe declares
/// `argv = crasher selftest`.
fn check_argv()
{
    let args: Vec<String> = std::env::args().collect();
    if let [program, mode] = args.as_slice()
        && program == "crasher"
        && mode == "selftest"
    {
        std::os::seraph::log!("argv ok ({args:?})");
    }
    else
    {
        std::os::seraph::log!("FATAL: argv mismatch {args:?} (want [crasher, selftest])");
    }
}

/// Assert env survived the (re)spawn: the recipe declares
/// `env = CRASHER_MARKER=107`.
fn check_env()
{
    match std::env::var("CRASHER_MARKER")
    {
        Ok(v) if v == "107" => std::os::seraph::log!("env ok (CRASHER_MARKER={v})"),
        Ok(v) => std::os::seraph::log!("FATAL: env CRASHER_MARKER={v:?} (want \"107\")"),
        Err(e) => std::os::seraph::log!("FATAL: env CRASHER_MARKER unset: {e}"),
    }
}

/// Assert cwd survived the (re)spawn: the recipe declares `cwd = /tests/fixtures`,
/// where crasher's own binary lives. A **relative** lookup of `crasher`
/// resolves through the child's `current_dir_cap`; if cwd were dropped on
/// restart that cap is zero and the lookup fails. The path is relative (no
/// leading `/`, no `.` component) so it routes through cwd, not the
/// namespace root. `std::env::current_dir()` is deliberately NOT used — the
/// spawner installs the cwd cap without a path string, so it reports
/// `Unsupported` until a process calls `set_current_dir`.
fn check_cwd()
{
    match std::fs::metadata("crasher")
    {
        Ok(_) => std::os::seraph::log!("cwd ok (relative lookup of \"crasher\" resolved)"),
        Err(e) => std::os::seraph::log!("FATAL: cwd relative lookup failed: {e}"),
    }
}

/// Assert the bootstrap seeds survived the (re)spawn: the recipe declares
/// `seed = svcmgr pwrmgr.deny`, so both slots must be present and non-zero.
fn check_seeds(svcmgr_cap: u64, second_cap: u64, cap_count: usize)
{
    if cap_count == 2 && svcmgr_cap != 0 && second_cap != 0
    {
        std::os::seraph::log!("seed ok (cap_count=2, both non-zero)");
    }
    else
    {
        std::os::seraph::log!(
            "FATAL: seed mismatch cap_count={cap_count} svcmgr={svcmgr_cap} \
             pwrmgr_deny={second_cap} (want 2 non-zero)"
        );
    }
}

/// Request the generic bootstrap rounds, returning `(svcmgr_cap, second_cap,
/// cap_count)`, `cap_count` being the caps delivered in the first four
/// slots. Missing caps are zero.
fn bootstrap_caps(creator_ep: u64, ipc_buffer: *mut u8) -> (u64, u64, usize)
{
    if creator_ep == 0
    {
        return (0, 0, 0);
    }
    #[expect(
        clippy::cast_ptr_alignment,
        reason = "the IPC buffer is page-aligned (4 KiB), satisfying u64 alignment"
    )]
    let ipc_buf = ipc_buffer.cast::<u64>();
    // SAFETY: IPC buffer is registered by `_start` and page-aligned by the
    // boot protocol.
    // Only the present caps ride, named by each round's presence word; an
    // absent slot decodes as `0`. Two spare slots catch caps past the
    // recipe's two seeds, which the count then shows.
    let Ok(slots) = (unsafe { ipc::bootstrap::request_slots::<4>(creator_ep, ipc_buf) })
    else
    {
        return (0, 0, 0);
    };
    let present = slots.iter().filter(|&&cap| cap != 0).count();
    (slots[0], slots[1], present)
}

/// Liveness probe: call `QUERY_ENDPOINT` on the svcmgr cap for a name that
/// does not exist. A successful round-trip (any reply, including
/// `UNKNOWN_NAME`) proves the cap is live. A dead or stale seed makes
/// `ipc_call` return `Err`, which is a surface that failed to round-trip and
/// is logged with `FATAL:` (services/fixtures/crasher/README.md).
fn probe_svcmgr(svcmgr_cap: u64, ipc_buffer: *mut u8)
{
    #[expect(
        clippy::cast_ptr_alignment,
        reason = "the IPC buffer is page-aligned (4 KiB), satisfying u64 alignment"
    )]
    let ipc_buf = ipc_buffer.cast::<u64>();
    let probe_name = b"__probe__";
    let name_len = probe_name.len();
    let label = ipc::svcmgr_labels::QUERY_ENDPOINT | ((name_len as u64) << 16);
    let msg = ipc::IpcMessage::builder(label).bytes(0, probe_name).build();
    // SAFETY: `ipc_buf` is the kernel-registered, page-aligned IPC buffer
    // page installed by `_start`.
    match unsafe { ipc::ipc_call(svcmgr_cap, &msg, ipc_buf) }
    {
        Ok(reply) => std::os::seraph::log!("svcmgr probe reply={}", reply.label),
        Err(_) => std::os::seraph::log!("FATAL: svcmgr probe ipc_call failed"),
    }
}

/// The `worker-fault` role: take the provided name's service endpoint from
/// bootstrap slot 0, draw this instance's nonce, and serve
/// `restart_probe_labels` until a `PROBE_FAULT_WORKER` request, after which a
/// worker thread faults while the main thread parks.
fn worker_fault_role(creator_ep: u64, ipc_buf: *mut u64) -> !
{
    let service_ep = if creator_ep == 0
    {
        0
    }
    else
    {
        // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
        unsafe { ipc::bootstrap::request_slots::<1>(creator_ep, ipc_buf) }.map_or(0, |[cap]| cap)
    };
    let nonce = syscall::random_u64().unwrap_or(0);
    if service_ep == 0 || nonce == 0
    {
        std::os::seraph::log!("FATAL: worker-fault: no service endpoint or nonce");
        syscall::thread_exit();
    }
    let worker = start_fault_worker_retrying();
    std::os::seraph::log!("worker-fault: serving");
    let mut guard = ipc::recv_guard::RecvGuard::new(|_, _| {});
    loop
    {
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let msg = match unsafe { ipc::ipc_recv(service_ep, ipc_buf) }
        {
            Ok(msg) => msg,
            Err(e) =>
            {
                guard.on_failure(e);
                continue;
            }
        };
        guard.on_success();
        for &c in msg.caps()
        {
            let _ = syscall::cap_delete(c);
        }
        let reply = match msg.label
        {
            restart_probe_labels::PROBE_INSTANCE =>
            {
                IpcMessage::builder(restart_probe_labels::SUCCESS)
                    .word(0, nonce)
                    .build()
            }
            restart_probe_labels::PROBE_FAULT_WORKER =>
            {
                IpcMessage::new(restart_probe_labels::SUCCESS)
            }
            _ => IpcMessage::new(restart_probe_labels::UNKNOWN_OPCODE),
        };
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
        if msg.label == restart_probe_labels::PROBE_FAULT_WORKER
        {
            fault_worker(&worker);
        }
    }
}

/// How long the role sleeps between attempts to start the fault worker.
const WORKER_RETRY_MS: u64 = 50;

/// Start the fault worker ([`start_fault_worker`]), trying again every
/// [`WORKER_RETRY_MS`] until it starts. A thread's IPC buffer is a memmgr
/// grant made at once, which memmgr refuses outside the reserve while memory
/// is critical, and an instance svcmgr restarts can start in that window:
/// it waits for the memory, as its held demand faults would, and serves once
/// the worker runs, so a request queued on the endpoint meanwhile is answered
/// then. The first refusal is logged.
fn start_fault_worker_retrying() -> thread::Thread
{
    let mut logged = false;
    loop
    {
        if let Some(worker) = start_fault_worker()
        {
            return worker;
        }
        if !logged
        {
            std::os::seraph::log!(warn: "worker-fault: worker thread not started; retrying");
            logged = true;
        }
        let _ = syscall::thread_sleep(WORKER_RETRY_MS);
    }
}

/// Set by the main thread on `PROBE_FAULT_WORKER`: the fault worker's go.
static FAULT_GO: AtomicBool = AtomicBool::new(false);

/// Start the thread that takes a terminal fault
/// [`restart_probe_labels::FAULT_DELAY_MS`] after [`FAULT_GO`] is set. The
/// role starts it before it serves, so the fault takes no memory when it is
/// asked for: one asked for while memory is critical, when a new thread
/// could not be made, still happens. `None` when the thread was not started.
fn start_fault_worker() -> Option<thread::Thread>
{
    thread::Builder::new()
        .name("fault-worker".into())
        .spawn(|| {
            while !FAULT_GO.load(Ordering::Acquire)
            {
                thread::park();
            }
            let _ = syscall::thread_sleep(restart_probe_labels::FAULT_DELAY_MS);
            std::os::seraph::log!("worker-fault: worker thread faulting");
            // SAFETY: deliberately invalid: the null write faults, and no
            // handler maps the null page, so the fault is terminal.
            unsafe {
                core::ptr::write_volatile(core::ptr::null_mut::<u8>(), 0x42);
            }
        })
        .ok()
        .map(|handle| handle.thread().clone())
}

/// Let the fault worker `worker` go, and park the main thread without
/// receiving again: only the worker's fault ends the process, through
/// procmgr's teardown, which posts no death for the main thread.
fn fault_worker(worker: &thread::Thread) -> !
{
    FAULT_GO.store(true, Ordering::Release);
    worker.unpark();
    loop
    {
        let _ = syscall::thread_sleep(u64::from(u32::MAX));
    }
}
