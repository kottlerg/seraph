// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/acpid/src/main.rs

//! acpid, the ACPI service: it runs the firmware's AML.
//!
//! acpid is a svcmgr-launched provider seeded with `devmgr.acpi`, a SEND on
//! devmgr's registry that carries `ACPI_AUTHORITY`. Through it acpid acquires
//! everything it touches: the tables (`QUERY_ACPI_TABLE`), the FADT's fixed
//! register blocks (`QUERY_ACPI_RESOURCES`), each operation region the AML
//! reaches (`ACPI_REGION_GRANT`), and each configuration-space access
//! (`ACPI_PCI_CONFIG`). On every start it loads the DSDT and the SSDTs,
//! runs the start-up sequence of `services/acpid/README.md` on an
//! evaluation thread, and pushes each PCI host bridge's `_OSC` grant,
//! windows and interrupt routes to devmgr. On x86-64 it then arms the
//! fixed power button and the GPEs on the SCI devmgr serves. The same thread
//! then runs every evaluation the service needs, while two receiver threads
//! serve pwrmgr's requests (`ipc::acpid_labels`) on acpid's service
//! endpoint and an event thread takes the SCI (`server`).

mod arch;
mod caps;
mod devmgr;
mod platform;
mod server;
mod startup;

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// acpid's `logd.flush` seed, `0` when absent: set once at start, before
/// any thread that writes a power register runs.
static LOG_FLUSH: AtomicU64 = AtomicU64::new(0);

/// The longest acpid waits for logd to write its line before a write that
/// ends the machine: a log call's own bound.
const FLUSH_BOUND_MS: u32 = log::LOG_CALL_TIMEOUT_MS;

/// Wait, at most [`FLUSH_BOUND_MS`], for logd to write every line acpid
/// logged before the call (logd's flush barrier, `LOG_FLUSH`): a log call
/// returns once logd holds the line, and the register write that follows
/// ends the machine and the lines logd holds unwritten with it. A refused,
/// failed or timed-out wait returns all the same, and the caller writes
/// (`services/logd/docs/ipc-interface.md` § Flush barrier).
pub fn flush_log()
{
    let cap = LOG_FLUSH.load(Ordering::Relaxed);
    if cap == 0
    {
        return;
    }
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let start = Instant::now();
    ipc::log_flush::wait(
        FLUSH_BOUND_MS,
        || u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX),
        // SAFETY: ipc_buf is this thread's registered IPC buffer page.
        |request, timeout| unsafe { ipc::ipc_call_timeout(cap, request, ipc_buf, timeout) }.ok(),
        |ms| std::thread::sleep(Duration::from_millis(ms)),
    );
}

/// The evaluation thread's stack: the evaluator's and the parser's own
/// bound ([`aml::EVAL_STACK_BYTES`], [`aml::PARSE_STACK_BYTES`]), whichever
/// is larger, and 256 KiB for acpid's frames below them. A spawned thread's
/// stack is at least the size it asks for, while the main thread's grows past
/// its few committed pages only in a demand-paged process.
const EVAL_THREAD_STACK: usize = max(aml::EVAL_STACK_BYTES, aml::PARSE_STACK_BYTES) + 256 * 1024;

const fn max(a: usize, b: usize) -> usize
{
    if a > b { a } else { b }
}

fn main() -> !
{
    std::os::seraph::log::register_name(b"acpid");
    let info = std::os::seraph::startup_info();

    #[expect(
        clippy::cast_ptr_alignment,
        reason = "IPC buffer is page-aligned (4 KiB) by the boot protocol, satisfying u64 alignment"
    )]
    let ipc_buf = info.ipc_buffer.cast::<u64>();

    let Some(caps) = caps::request_bootstrap(info, ipc_buf).filter(|c| c.service != 0)
    else
    {
        std::os::seraph::log!(error: "bootstrap failed: no service endpoint");
        // Staying alive keeps svcmgr from restarting acpid into the same
        // failed round. acpid holds no endpoint to answer on, so a power
        // request waits out its caller's bound.
        loop
        {
            std::thread::park();
        }
    };
    LOG_FLUSH.store(caps.log_flush, Ordering::Relaxed);
    if caps.registry == 0
    {
        std::os::seraph::log!(error: "bootstrap failed: no devmgr.acpi seed; refusing power requests");
        // As above, alive rather than restarted into the same round, and
        // answering every request instead of leaving it queued.
        server::refuse(caps.service);
    }
    let aspace = info.self_aspace;
    // Each thread acpid runs reports its end here, in a panic too.
    let (ended, end) = std::sync::mpsc::channel();
    let spawned = std::thread::Builder::new()
        .name("acpid-eval".into())
        .stack_size(EVAL_THREAD_STACK)
        .spawn(move || {
            let _watched = server::Watched::new("evaluation", ended.clone());
            startup::run(
                &devmgr::Devmgr::new(caps.registry),
                aspace,
                caps.service,
                &ended,
            )
        });
    match spawned
    {
        Ok(_) => match end.recv()
        {
            Ok(thread) => std::os::seraph::log!(error: "the {thread} thread ended; exiting"),
            Err(_) => std::os::seraph::log!(error: "every thread ended; exiting"),
        },
        Err(e) => std::os::seraph::log!(error: "evaluation thread not spawned: {e}; exiting"),
    }
    // acpid's threads serve its endpoint and its events for acpid's
    // lifetime; without one of them a request or an event would wait
    // unanswered, so acpid exits and svcmgr restarts it.
    syscall::process_exit(1)
}
