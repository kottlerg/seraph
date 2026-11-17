// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/acpid/src/main.rs

//! acpid, the ACPI service: it runs the firmware's AML.
//!
//! acpid is a svcmgr-launched service seeded with `devmgr.acpi`, a SEND on
//! devmgr's registry that carries `ACPI_AUTHORITY`. Through it acpid acquires
//! everything it touches: the tables (`QUERY_ACPI_TABLE`), the FADT's fixed
//! register blocks (`QUERY_ACPI_RESOURCES`), each operation region the AML
//! reaches (`ACPI_REGION_GRANT`), and each configuration-space access
//! (`ACPI_PCI_CONFIG`). On every start it loads the DSDT and the SSDTs,
//! runs the start-up sequence of `services/acpid/README.md` on an
//! evaluation thread, pushes each PCI host bridge's `_OSC` grant, windows
//! and interrupt routes to devmgr, and then idles.

mod arch;
mod caps;
mod devmgr;
mod platform;
mod startup;

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

    match caps::request_bootstrap(info, ipc_buf)
    {
        Some(registry) =>
        {
            let aspace = info.self_aspace;
            let spawned = std::thread::Builder::new()
                .name("acpid-eval".into())
                .stack_size(EVAL_THREAD_STACK)
                .spawn(move || startup::run(&devmgr::Devmgr::new(registry), aspace));
            match spawned.map(std::thread::JoinHandle::join)
            {
                Ok(Ok(())) =>
                {}
                Ok(Err(_)) => std::os::seraph::log!(error: "the evaluation thread panicked"),
                Err(e) => std::os::seraph::log!(error: "evaluation thread not spawned: {e}"),
            }
        }
        None => std::os::seraph::log!(error: "bootstrap failed: no devmgr.acpi seed"),
    }
    // acpid serves no requests yet. It stays alive, so that svcmgr does not
    // restart it into the same start-up, and keeps the grants it holds.
    loop
    {
        std::thread::park();
    }
}
