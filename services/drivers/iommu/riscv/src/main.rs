// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/drivers/iommu/riscv/src/main.rs

//! The RISC-V IOMMU driver (`iommu-riscv`).
//!
//! devmgr spawns it first at boot, before any DMA-capable driver, and
//! delivers it in its resource list the register page of each RISC-V IOMMU
//! PCI function it found through the ACPI RIMT, with the devices the IOMMU
//! translates (`iommu_core::delivery`), and the anchor page devmgr keeps for
//! each. The driver maps each IOMMU's register page and anchor, sets each up
//! with empty command and fault queues and an empty device directory rooted
//! at its anchor and turns translation on ([`backend::Riscv`]), so every
//! device an IOMMU translates reaches nothing until devmgr attaches it; then
//! it reports ready and serves `ipc::iommu_labels` for devmgr
//! ([`iommu_core::service`]), with a second thread polling the fault
//! queues. An IOMMU that cannot be set up returns every IOMMU to Bare and
//! the driver exits without reporting ready, so devmgr runs DMA unconfined.
//! A driver devmgr restarts after a death adopts the IOMMUs instead,
//! translating through the dead instance's directories until devmgr's replay
//! commits, and one that cannot adopt them exits leaving them as they stand,
//! for devmgr to fail the IOMMU. See `docs/device-management.md` § IOMMU
//! Discovery and Programming and § IOMMU Driver Restart.

mod backend;

use std::sync::{Arc, Mutex, PoisonError};

use iommu_core::Start;
use iommu_core::delivery::{Delivery, Registers};
use iommu_core::service::{self, KernelCaps, Lock, Service};
use iommu_store::{Flush, Store};
use std::os::seraph::{reserve_pages, startup_info};

use backend::{Riscv, Unit};

// ── Declaration ────────────────────────────────────────────────────────────

// What devmgr binds this driver to and how it starts it
// (docs/driver-binding.md § Driver Declarations): the IOMMU family record
// of the platform's remapping table, which devmgr binds before any device
// driver.
driver_binding::driver_declaration!(driver_binding::decl::Declaration {
    name: "iommu-riscv",
    class: None,
    matches: &[driver_binding::decl::Match::IommuFamily("rimt")],
    instance_limit: Some(1),
    interrupt: driver_binding::decl::Interrupt::NONE,
    dma: true,
    dma_width: None,
    phys_access: true,
    reset: driver_binding::decl::Reset::None,
    tier: driver_binding::decl::Tier::Boot,
});

/// The driver's one [`Service`], shared by the service loop and the fault
/// poll thread.
struct Shared(Mutex<Service<Riscv, KernelCaps>>);

impl Lock<Service<Riscv, KernelCaps>> for Shared
{
    fn with<R>(&self, f: impl FnOnce(&mut Service<Riscv, KernelCaps>) -> R) -> R
    {
        // A poisoned lock means the other thread panicked mid-request; the
        // service is used as it stands, since the hardware keeps translating
        // whatever its tables hold.
        let mut guard = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        f(&mut guard)
    }
}

/// Map `registers` into the driver's own address space; the base of the
/// mapping, or `None`, logged, when it cannot be mapped or does not span the
/// register page.
fn map_registers(aspace: u64, registers: Registers) -> Option<u64>
{
    // The delivery bounds `pages` to `MAX_UNIT_REGISTER_PAGES`, so the
    // product does not saturate.
    if registers.pages.saturating_mul(syscall_abi::PAGE_SIZE) < iommu_riscv::regs::REGISTER_BYTES
    {
        std::os::seraph::log!(error: "register window: smaller than the register page");
        return None;
    }
    let Ok(range) = reserve_pages(registers.pages)
    else
    {
        std::os::seraph::log!(error: "register window: no VA");
        return None;
    };
    let va = range.va_start();
    // SAFETY: `range` is a fresh reservation of the cap's pages from the
    // per-process arena, kept for the driver's life whether or not it is
    // mapped, so the VA stays the registers' for the driver's life; the
    // backend reaches them only through raw volatile accesses (`mmio_map`
    // § Safety).
    if unsafe { std::os::seraph::mmio_map_funded(aspace, registers.cap, va, registers.pages) }
        .is_err()
    {
        std::os::seraph::log!(error: "register window: mmio_map failed");
        return None;
    }
    Some(va)
}

fn recv_diag(stage: ipc::recv_guard::RecvFailureStage, err: i64)
{
    std::os::seraph::log!(warn: "service receive failing ({:?}, err={})", stage, err);
}

fn faults_dropped(count: u64)
{
    std::os::seraph::log!(warn: "fault queue full: {} faults dropped", count);
}

fn log_started(start: Start, iommus: u64)
{
    match start
    {
        Start::Reset => std::os::seraph::log!("{} IOMMUs translating", iommus),
        Start::Adopt => std::os::seraph::log!("{} IOMMUs adopted", iommus),
    }
}

fn main() -> !
{
    std::os::seraph::log::register_name(b"iommu-riscv");
    let info = startup_info();
    #[expect(
        clippy::cast_ptr_alignment,
        reason = "the IPC buffer page is 4 KiB-aligned"
    )]
    let ipc_buf = info.ipc_buffer.cast::<u64>();

    // devmgr installs every block transfer's mapping through this driver, so
    // a core written while it is held would wait on it: declare it on the
    // core path before it serves (`procmgr_labels::DECLARE_NO_CORE`). A
    // refusal leaves its core to the crash service's dump bound.
    // SAFETY: ipc_buf is this thread's registered IPC buffer.
    let _ = unsafe {
        ipc::ipc_call(
            info.procmgr_endpoint,
            &ipc::IpcMessage::new(ipc::procmgr_labels::DECLARE_NO_CORE),
            ipc_buf,
        )
    };

    // SAFETY: ipc_buf is this thread's registered IPC buffer.
    let list = match unsafe { driver_binding::resources::receive(info.creator_endpoint, ipc_buf) }
    {
        Ok(list) => list,
        Err(e) =>
        {
            std::os::seraph::log!(error: "bootstrap failed ({:?})", e);
            syscall::thread_exit();
        }
    };
    let boot = match Delivery::from_list(&list)
    {
        Ok(boot) => boot,
        Err(e) =>
        {
            std::os::seraph::log!(error: "resource list refused ({:?})", e);
            syscall::thread_exit();
        }
    };
    // The IOMMU reads its structures coherently with the caches (the
    // `backend` module doc): no table write needs writing back.
    let mut store = Store::new(info.memmgr_endpoint, info.self_aspace, Flush::Coherent);
    let mut units = Vec::new();
    for (&r, unit) in boot.registers.iter().zip(&boot.units.0)
    {
        let Some(va) = map_registers(info.self_aspace, r)
        else
        {
            syscall::thread_exit();
        };
        let Some(anchor) = store.adopt(unit.anchor, 1)
        else
        {
            std::os::seraph::log!(error: "anchor not mapped");
            syscall::thread_exit();
        };
        units.push(Unit::new(va, anchor));
    }
    let count = units.len() as u64;
    let start = boot.units.start();
    // SAFETY: ipc_buf is this thread's registered IPC buffer.
    let Some(caps) = (unsafe { KernelCaps::new(info.memmgr_endpoint, ipc_buf) })
    else
    {
        std::os::seraph::log!(error: "no physical-address credential");
        syscall::thread_exit();
    };
    let Some(mut svc) = Service::new(Riscv::new(units, store, start), caps, boot.units)
    else
    {
        std::os::seraph::log!(error: "no memory for the service");
        syscall::thread_exit();
    };
    if let Err((unit, e)) = svc.init()
    {
        match start
        {
            Start::Reset => std::os::seraph::log!(error:
                "IOMMU {} not set up ({:?}); every IOMMU left Bare", unit, e
            ),
            Start::Adopt => std::os::seraph::log!(error:
                "IOMMU {} not adopted ({:?}); IOMMUs left as they stand", unit, e
            ),
        }
        syscall::thread_exit();
    }
    log_started(start, count);

    let shared = Arc::new(Shared(Mutex::new(svc)));
    let poller = Arc::clone(&shared);
    if std::thread::Builder::new()
        .name("faults".into())
        .spawn(move || service::poll_faults(&*poller, faults_dropped))
        .is_err()
    {
        std::os::seraph::log!(warn:
            "fault poll thread not started; faults are polled only when devmgr takes them"
        );
    }

    // SAFETY: ipc_buf is this thread's registered IPC buffer.
    if let Err(e) = unsafe { ipc::report_driver_ready(boot.devmgr_query, ipc_buf) }
    {
        std::os::seraph::log!(error:
            "DRIVER_READY failed ({:?}); driver exiting",
            e
        );
        shared.with(Service::disable);
        syscall::thread_exit();
    }
    // SAFETY: ipc_buf is this thread's registered IPC buffer.
    unsafe { service::serve(boot.service_ep, ipc_buf, &*shared, recv_diag) }
}
