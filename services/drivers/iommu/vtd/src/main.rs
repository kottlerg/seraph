// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/drivers/iommu/vtd/src/main.rs

//! The VT-d IOMMU driver (`iommu-vtd`).
//!
//! devmgr spawns it first at boot, before any DMA-capable driver, and
//! delivers it in its resource list one register range per VT-d remapping
//! unit it found in the ACPI DMAR, with the functions the unit translates
//! (`iommu_core::delivery`). The driver maps each unit's registers,
//! programs every unit with an empty root table and turns translation on
//! ([`backend::Vtd`]), so every function a unit translates reaches nothing
//! until devmgr attaches it; then it reports ready and serves
//! `ipc::iommu_labels` for devmgr ([`iommu_core::service`]), with a second
//! thread polling the units' fault records. A unit that cannot be set up
//! turns every unit off again and the driver exits without reporting ready,
//! so devmgr runs DMA unconfined. See `docs/device-management.md`
//! § IOMMU Discovery and Programming.

mod arch;
mod backend;

use std::sync::{Arc, Mutex, PoisonError};

use iommu_core::delivery::{Delivery, Registers};
use iommu_core::service::{self, KernelCaps, Lock, Service};
use iommu_store::{Flush, Store};
use iommu_vtd::regs;
use std::os::seraph::{reserve_pages, startup_info};
use syscall_abi::PAGE_SIZE;

use backend::{Unit, Vtd};

// ── Declaration ────────────────────────────────────────────────────────────

// What devmgr binds this driver to and how it starts it
// (docs/driver-binding.md § Driver Declarations): the IOMMU family record
// of the platform's remapping table, which devmgr binds before any device
// driver.
driver_binding::driver_declaration!(driver_binding::decl::Declaration {
    name: "iommu-vtd",
    class: None,
    matches: &[driver_binding::decl::Match::IommuFamily("dmar")],
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
struct Shared(Mutex<Service<Vtd, KernelCaps>>);

impl Lock<Service<Vtd, KernelCaps>> for Shared
{
    fn with<R>(&self, f: impl FnOnce(&mut Service<Vtd, KernelCaps>) -> R) -> R
    {
        // A poisoned lock means the other thread panicked mid-request; the
        // service is used as it stands, since the hardware keeps translating
        // whatever its tables hold.
        let mut guard = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        f(&mut guard)
    }
}

/// Map `registers` into the driver's own address space; the base of the
/// mapping, or `None`, logged, when it cannot be mapped.
fn map_registers(aspace: u64, registers: Registers) -> Option<u64>
{
    let Ok(range) = reserve_pages(registers.pages)
    else
    {
        std::os::seraph::log!(error: "register window: no VA");
        return None;
    };
    let va = range.va_start();
    // SAFETY: `range` is a fresh reservation of the cap's pages from the
    // per-process arena, never returned, so the VA stays the registers' for
    // the driver's life; the backend reaches them only through raw volatile
    // accesses (`mmio_map` § Safety).
    if unsafe { std::os::seraph::mmio_map_funded(aspace, registers.cap, va, registers.pages) }
        .is_err()
    {
        std::os::seraph::log!(error: "register window: mmio_map failed");
        return None;
    }
    Some(va)
}

/// How table writes reach the units whose registers are mapped at `regs`:
/// with no write-back when every unit's page walks snoop the processor
/// caches, read from each unit's `ECAP` (the store's fence and the fence
/// before each register write order them), and written back with
/// [`arch::current::flush`] otherwise.
fn table_flush(regs: &[u64]) -> Flush
{
    let coherent = regs.iter().all(|&va| {
        // SAFETY: `va` maps a unit's register set, whose `ECAP` (8 bytes at
        // 0x10) lies in its first page, so the sum does not saturate; reached
        // only through a raw volatile access.
        let ecap =
            unsafe { core::ptr::read_volatile(va.saturating_add(regs::ECAP as u64) as *const u64) };
        regs::coherent(ecap)
    });
    if coherent
    {
        Flush::Coherent
    }
    else
    {
        Flush::Writeback(arch::current::flush)
    }
}

fn recv_diag(stage: ipc::recv_guard::RecvFailureStage, err: i64)
{
    std::os::seraph::log!(warn: "service receive failing ({:?}, err={})", stage, err);
}

fn faults_dropped(count: u64)
{
    std::os::seraph::log!(warn: "fault queue full: {} faults dropped", count);
}

fn main() -> !
{
    std::os::seraph::log::register_name(b"iommu-vtd");
    let info = startup_info();
    #[expect(
        clippy::cast_ptr_alignment,
        reason = "the IPC buffer page is 4 KiB-aligned"
    )]
    let ipc_buf = info.ipc_buffer.cast::<u64>();

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
    let mut mapped = Vec::new();
    for &r in &boot.registers
    {
        let Some(va) = map_registers(info.self_aspace, r)
        else
        {
            syscall::thread_exit();
        };
        mapped.push(va);
    }
    let units = boot
        .registers
        .iter()
        .zip(&mapped)
        // The delivery bounds `pages` to `MAX_UNIT_REGISTER_PAGES`, so the
        // product does not saturate.
        .map(|(r, &va)| Unit::new(va, r.pages.saturating_mul(PAGE_SIZE)))
        .collect();
    let store = Store::new(info.memmgr_endpoint, info.self_aspace, table_flush(&mapped));
    // SAFETY: ipc_buf is this thread's registered IPC buffer.
    let Some(caps) = (unsafe { KernelCaps::new(info.memmgr_endpoint, ipc_buf) })
    else
    {
        std::os::seraph::log!(error: "no physical-address credential");
        syscall::thread_exit();
    };
    let Some(mut svc) = Service::new(Vtd::new(units, store), caps, boot.units)
    else
    {
        std::os::seraph::log!(error: "no memory for the service");
        syscall::thread_exit();
    };
    if let Err((unit, e)) = svc.init()
    {
        std::os::seraph::log!(error: "unit {} not set up ({:?}); translation left off", unit, e);
        syscall::thread_exit();
    }
    std::os::seraph::log!("{} units translating", mapped.len() as u64);

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
        std::os::seraph::log!(error: "DRIVER_READY failed ({:?}); translation left off", e);
        shared.with(Service::disable);
        syscall::thread_exit();
    }
    // SAFETY: ipc_buf is this thread's registered IPC buffer.
    unsafe { service::serve(boot.service_ep, ipc_buf, &*shared, recv_diag) }
}
