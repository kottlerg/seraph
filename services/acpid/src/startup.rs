// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/acpid/src/startup.rs

//! acpid's start-up sequence, run on the evaluation thread: acquire the
//! sleep and reset registers, load the DSDT and the SSDTs, enable ACPI mode
//! where the platform has a legacy mode, run the module-level code and the
//! initialization walk, then evaluate each PCI host bridge's `_PRT`, `_OSC`
//! and `_CRS` and push the results to devmgr. The event blocks and the SCI
//! are acquired at the start, and a start that devmgr does not report as a
//! restart clears the events there, before anything else can fail and
//! restart acpid. Every failure is logged and the
//! sequence goes on with what it has; the thread then arms the events and
//! serves (`crate::server`).

use acpid::bridge::{self, Bridge, Osc};
use acpid::hotplug::HotplugSlots;
use acpid::{Failure, Why, walk};
use aml::namespace::NodeId;
use aml::{Data, Evaluator, Namespace};
use ipc::{devmgr_errors, devmgr_labels};
use std::os::seraph::{mem_map_funded, reserve_pages, unreserve_pages};
use std::sync::mpsc::Sender;

use crate::arch;
use crate::devmgr::{CallError, Devmgr, TableView};
use crate::platform::Platform;
use crate::server;

/// The most SSDTs acpid asks devmgr for (`docs/limits.md`); the XSDT of a
/// QEMU machine lists one.
const MAX_SSDTS: u64 = 64;

/// Run the start-up sequence, reaching devmgr through `devmgr` and mapping
/// into the address space `aspace`, then serve the requests received on
/// `service`, acpid's service endpoint, for acpid's lifetime; `ended` is
/// where each thread acpid watches reports its end.
pub fn run(devmgr: &Devmgr, aspace: u64, service: u64, ended: &Sender<&'static str>) -> !
{
    let thread = std::os::seraph::thread::current_thread_cap();
    let power = arch::current::Power::acquire(devmgr, aspace, thread);
    let events = arch::current::Events::acquire(devmgr, thread).map(|events| server::EventSource {
        events,
        power_button: fixed_power_button(devmgr, aspace),
    });
    let mut platform = Platform::new(devmgr, aspace, thread);
    let mut ns = load(devmgr, aspace);
    let mut hotplug_slots = HotplugSlots::default();
    // Whether or not the DSDT loaded: the fixed power button the events arm
    // raises the SCI only in ACPI mode, and the switch needs no AML.
    arch::current::enable_acpi(devmgr, thread, &power);
    if let Some((ns, tables)) = &mut ns
    {
        hotplug_slots = start(ns, *tables, devmgr, &mut platform);
    }
    server::serve(
        service,
        ns.as_mut().map(|(ns, _)| ns),
        &mut platform,
        &power,
        events,
        hotplug_slots,
        ended,
    );
}

/// Whether the FADT declares the fixed power button
/// ([`acpid::events::fixed_power_button`]); false, logged, when the FADT
/// cannot be read.
fn fixed_power_button(devmgr: &Devmgr, aspace: u64) -> bool
{
    let fixed = devmgr
        .table(*b"FACP", 0)
        .ok()
        .and_then(|view| with_table(aspace, &view, acpid::events::fixed_power_button))
        .flatten();
    fixed.unwrap_or_else(|| {
        std::os::seraph::log!(warn: "the FADT could not be read; no fixed power button");
        false
    })
}

/// Evaluate the loaded namespace `ns` of `tables` tables: the module-level
/// code, the initialization walk, and each PCI host bridge's results, pushed
/// to devmgr. Returns the hotplug slots acpid serves, behind the ports of
/// the host bridges found ([`HotplugSlots`]).
fn start(
    ns: &mut Namespace,
    tables: usize,
    devmgr: &Devmgr,
    platform: &mut Platform<'_>,
) -> HotplugSlots
{
    let mut ev = Evaluator::new(ns, platform);
    let module = ev.run_module_code();
    if module.faults > 0
    {
        std::os::seraph::log!(
            warn: "module-level code: {} of {} terms faulted, first {:?}",
            module.faults,
            module.terms,
            module.first_fault
        );
    }
    let walk = walk::initialize(&mut ev);
    log_failures(&ev, &walk.failures);
    let (bridges, failures) = bridge::host_bridges(&mut ev, &walk.present);
    log_failures(&ev, &failures);
    // devmgr checks a `_PRT` against the functions on the buses of the
    // bridge's windows, so the windows go first.
    for b in &bridges
    {
        push_windows(&mut ev, devmgr, *b);
    }
    if let Some(model) = arch::current::APIC_MODEL
    {
        for b in &bridges
        {
            push_routes(&mut ev, devmgr, *b, devmgr_labels::PRT_PIC_MODE);
        }
        select_model(&mut ev, model);
    }
    for b in &bridges
    {
        push_osc(&mut ev, devmgr, *b);
        push_routes(&mut ev, devmgr, *b, devmgr_labels::PRT_ROUTES);
    }
    std::os::seraph::log!(
        "ready: {tables} tables, {} devices present, {} _INI run, {} host bridges",
        walk.present.len(),
        walk.initialized,
        bridges.len()
    );
    HotplugSlots::new(bridges)
}

/// Load the DSDT, then each SSDT devmgr serves, and parse their methods; the
/// namespace and the tables loaded. `None`, logged, when the DSDT cannot be.
fn load(devmgr: &Devmgr, aspace: u64) -> Option<(Namespace, usize)>
{
    let Ok(mut ns) = Namespace::new()
    else
    {
        std::os::seraph::log!(error: "no memory for the namespace");
        return None;
    };
    let dsdt = devmgr.table(*b"DSDT", 0);
    if !dsdt.is_ok_and(|view| load_one(&mut ns, aspace, &view, "DSDT"))
    {
        std::os::seraph::log!(error: "the DSDT could not be loaded; no AML runs");
        return None;
    }
    let mut tables = 1usize;
    for index in 0..MAX_SSDTS
    {
        match devmgr.table(*b"SSDT", index)
        {
            Ok(view) =>
            {
                if load_one(&mut ns, aspace, &view, "SSDT")
                {
                    tables = tables.saturating_add(1);
                }
            }
            Err(CallError::Status(devmgr_errors::NO_DEVICE)) => break,
            Err(e) =>
            {
                std::os::seraph::log!(warn: "SSDT {index} not served: {e:?}");
                break;
            }
        }
    }
    let (methods, faults, first) = ns.parse_methods();
    if faults > 0
    {
        std::os::seraph::log!(
            warn: "{faults} of {methods} methods did not parse, first {:?}",
            first.map(|(node, fault)| (path(&ns, node), fault))
        );
    }
    Some((ns, tables))
}

/// Load the table `view` serves into `ns`; whether it loaded.
fn load_one(ns: &mut Namespace, aspace: u64, view: &TableView, what: &str) -> bool
{
    match with_table(aspace, view, |bytes| ns.load_table(bytes))
    {
        Some(Ok(report)) =>
        {
            if report.faults > 0
            {
                std::os::seraph::log!(
                    warn: "{what} at {:#x}: {} faults, first {:?}",
                    view.table_phys,
                    report.faults,
                    report.first_fault
                );
            }
            true
        }
        Some(Err(fault)) =>
        {
            std::os::seraph::log!(warn: "{what} at {:#x} not loaded: {fault:?}", view.table_phys);
            false
        }
        None =>
        {
            std::os::seraph::log!(warn: "{what} at {:#x} could not be mapped", view.table_phys);
            false
        }
    }
}

/// Map the region behind `view` read-only, hand `f` the bytes from the
/// table's first byte to the mapping's end, then unmap it and delete the
/// capability. `None` when the table is not inside the region or the
/// mapping fails.
fn with_table<R>(aspace: u64, view: &TableView, f: impl FnOnce(&[u8]) -> R) -> Option<R>
{
    let out = acpid::table::window(view.region_base, view.region_size, view.table_phys).and_then(
        |window| {
            let range = reserve_pages(window.pages).ok()?;
            let va = range.va_start();
            // SAFETY: `range` is a fresh reservation of `window.pages` pages,
            // owned here: VA no Rust object or IPC page occupies.
            let mapped = unsafe {
                mem_map_funded(
                    view.memory_cap,
                    aspace,
                    va,
                    0,
                    window.pages,
                    syscall_abi::MAP_READ,
                )
            };
            let out = match (mapped, usize::try_from(window.len))
            {
                (Ok(()), Ok(len)) =>
                {
                    // SAFETY: `[va + offset, + len)` lies inside the
                    // read-only mapping just made, which stays until the
                    // unmap below; `f` cannot keep the slice past its call.
                    let bytes = unsafe {
                        core::slice::from_raw_parts(
                            va.saturating_add(window.offset) as *const u8,
                            len,
                        )
                    };
                    Some(f(bytes))
                }
                _ => None,
            };
            // A failed map can leave some pages mapped, so the span is
            // unmapped on either path, and stays reserved if that fails.
            // SAFETY: the span is this call's reservation and no reference
            // into it is live.
            if unsafe { syscall::mem_unmap(aspace, va, window.pages) }.is_ok()
            {
                unreserve_pages(range);
            }
            out
        },
    );
    let _ = syscall::cap_delete(view.memory_cap);
    out
}

/// Select the interrupt model `model` with `\_PIC`, when the tables
/// define it.
fn select_model(ev: &mut Evaluator<'_>, model: u64)
{
    if let Some(pic) = ev.namespace().find("\\_PIC")
        && let Err(fault) = ev.evaluate(pic, vec![Data::Integer(model)])
    {
        std::os::seraph::log!(warn: "\\_PIC({model}) faulted: {fault:?}");
    }
}

/// Evaluate `bridge`'s `_OSC` and push the result.
fn push_osc(ev: &mut Evaluator<'_>, devmgr: &Devmgr, b: Bridge)
{
    let at = path(ev.namespace(), b.node);
    let (evaluated, status, control) = match bridge::osc(ev, b.node)
    {
        Osc::Returned { status, control } =>
        {
            std::os::seraph::log!("{at}: _OSC status {status:#x}, control {control:#x}");
            (1, status, control)
        }
        Osc::Absent => (0, 0, 0),
        Osc::Failed(why) =>
        {
            std::os::seraph::log!(warn: "{at}._OSC failed: {why:?}");
            (0, 0, 0)
        }
    };
    let words = [
        evaluated,
        u64::from(status),
        u64::from(control),
        u64::from(bridge::OSC_CONTROL),
    ];
    report(
        devmgr.push(devmgr_labels::OSC_RESULT, b.segment, b.bus, &words),
        &at,
        "_OSC",
    );
}

/// Evaluate `bridge`'s `_CRS` and push its windows.
fn push_windows(ev: &mut Evaluator<'_>, devmgr: &Devmgr, b: Bridge)
{
    let at = path(ev.namespace(), b.node);
    let windows = match bridge::windows(ev, b.node)
    {
        Ok(Some(windows)) => windows,
        Ok(None) => return std::os::seraph::log!(warn: "{at} has no _CRS"),
        Err(why) => return std::os::seraph::log!(warn: "{at}._CRS failed: {why:?}"),
    };
    let mut words = vec![windows.len() as u64];
    for w in &windows
    {
        words.extend([w.kind, w.base, w.len]);
    }
    report(
        devmgr.push(devmgr_labels::BRIDGE_WINDOWS, b.segment, b.bus, &words),
        &at,
        "_CRS windows",
    );
}

/// Evaluate `bridge`'s `_PRT` in the model selected now and push it as
/// `mode`.
fn push_routes(ev: &mut Evaluator<'_>, devmgr: &Devmgr, b: Bridge, mode: u64)
{
    let at = path(ev.namespace(), b.node);
    let routes = match bridge::routes(ev, b.node)
    {
        Ok(Some(routes)) => routes,
        Ok(None) => return std::os::seraph::log!(warn: "{at} has no _PRT"),
        Err(why) => return std::os::seraph::log!(warn: "{at}._PRT failed: {why:?}"),
    };
    log_failures(ev, &routes.failures);
    let mut words = vec![mode];
    words.extend(routes.lanes);
    let what = if mode == devmgr_labels::PRT_PIC_MODE
    {
        "PIC-model _PRT"
    }
    else
    {
        "_PRT"
    };
    report(
        devmgr.push(devmgr_labels::PRT_TABLE, b.segment, b.bus, &words),
        &at,
        what,
    );
}

/// Log devmgr's answer to the push of `what` of the bridge `at`.
fn report(result: Result<(), CallError>, at: &str, what: &str)
{
    match result
    {
        Ok(()) => std::os::seraph::log!("{at}: devmgr holds the {what}"),
        Err(e) if e.refused() =>
        {
            std::os::seraph::log!(warn: "{at}: devmgr refused the {what}, which disagrees with its boot records");
        }
        Err(e) => std::os::seraph::log!(warn: "{at}: push of the {what} failed: {e:?}"),
    }
}

/// Log each failure in `failures`.
fn log_failures(ev: &Evaluator<'_>, failures: &[Failure])
{
    for f in failures
    {
        let name = String::from_utf8_lossy(&f.name);
        let at = path(ev.namespace(), f.node);
        match f.why
        {
            Why::Fault(fault) => std::os::seraph::log!(warn: "{at}.{name} faulted: {fault:?}"),
            Why::Shape =>
            {
                std::os::seraph::log!(warn: "{at}.{name} returned a value of the wrong shape");
            }
            Why::Bound =>
            {
                std::os::seraph::log!(warn: "{at}.{name} returned more than devmgr takes");
            }
        }
    }
}

/// The ASL path of `node` (`\_SB_.PCI0`).
pub fn path(ns: &Namespace, node: NodeId) -> String
{
    let segs = ns.path(node).unwrap_or_default();
    let segs: Vec<String> = segs
        .iter()
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect();
    format!("\\{}", segs.join("."))
}
