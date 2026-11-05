// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/drivers/iommu/riscv/src/main.rs

//! The RISC-V IOMMU driver (`iommu-riscv`).
//!
//! devmgr spawns it first at boot, before any DMA-capable driver, with one
//! register cap per RISC-V IOMMU PCI function it found through the ACPI RIMT
//! (`iommu_core::bootstrap`). The driver maps each IOMMU's register page,
//! sets each up with empty command and fault queues and an empty device
//! directory and turns translation on ([`backend::Riscv`]), so every device
//! an IOMMU translates reaches nothing until devmgr attaches it; then it
//! reports ready and serves `ipc::iommu_labels` for devmgr
//! ([`iommu_core::service`]), with a second thread polling the fault queues.
//! An IOMMU that cannot be set up returns every IOMMU to Bare and the driver
//! exits without reporting ready, so devmgr runs DMA unconfined. See
//! `docs/device-management.md` § IOMMU Discovery and Programming.

mod backend;

use std::sync::{Arc, Mutex, PoisonError};

use iommu_core::bootstrap::Registers;
use iommu_core::service::{self, KernelCaps, Lock, Service};
use iommu_store::{Flush, Store};
use std::os::seraph::{reserve_pages, startup_info};

use backend::{Riscv, Unit};

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
    if registers.pages * syscall_abi::PAGE_SIZE < iommu_riscv::regs::REGISTER_BYTES
    {
        std::os::seraph::log!("register window: smaller than the register page");
        return None;
    }
    let Ok(range) = reserve_pages(registers.pages)
    else
    {
        std::os::seraph::log!("register window: no VA");
        return None;
    };
    let va = range.va_start();
    if !std::os::seraph::fund_aspace_pt_budget(aspace, registers.pages)
    {
        std::os::seraph::log!("register window: page-table funding failed");
        return None;
    }
    // SAFETY: `range` is a fresh reservation of the cap's pages from the
    // per-process arena, kept for the driver's life once mapped, so the VA
    // stays the registers' for the driver's life; the backend reaches them
    // only through raw volatile accesses (`mmio_map` § Safety).
    if unsafe { syscall::mmio_map(aspace, registers.cap, va, 0) }.is_err()
    {
        std::os::seraph::log!("register window: mmio_map failed");
        return None;
    }
    Some(va)
}

fn recv_diag(stage: ipc::recv_guard::RecvFailureStage, err: i64)
{
    std::os::seraph::log!("service receive failing ({:?}, err={})", stage, err);
}

fn faults_dropped(count: u64)
{
    std::os::seraph::log!("fault queue full: {} faults dropped", count);
}

fn main() -> !
{
    std::os::seraph::log::register_name(b"iommu-riscv");
    let info = startup_info();
    // cast_ptr_alignment: the IPC buffer page is 4 KiB-aligned.
    #[allow(clippy::cast_ptr_alignment)]
    let ipc_buf = info.ipc_buffer.cast::<u64>();

    // SAFETY: ipc_buf is this thread's registered IPC buffer.
    let boot = match unsafe { iommu_core::bootstrap::receive(info.creator_endpoint, ipc_buf) }
    {
        Ok(boot) => boot,
        Err(e) =>
        {
            std::os::seraph::log!("bootstrap failed ({:?})", e);
            syscall::thread_exit();
        }
    };
    let mut units = Vec::new();
    for &r in &boot.registers
    {
        let Some(va) = map_registers(info.self_aspace, r)
        else
        {
            syscall::thread_exit();
        };
        units.push(Unit::new(va));
    }
    let count = units.len() as u64;
    // The IOMMU reads its structures coherently with the caches
    // (`backend` § coherence): the store's fences suffice.
    let store = Store::new(info.memmgr_endpoint, info.self_aspace, Flush::Coherent);
    let Some(mut svc) = Service::new(Riscv::new(units, store), KernelCaps, boot.units)
    else
    {
        std::os::seraph::log!("no memory for the service");
        syscall::thread_exit();
    };
    if let Err((unit, e)) = svc.init()
    {
        std::os::seraph::log!("IOMMU {} not set up ({:?}); every IOMMU left Bare", unit, e);
        syscall::thread_exit();
    }
    std::os::seraph::log!("{} IOMMUs translating", count);

    let shared = Arc::new(Shared(Mutex::new(svc)));
    let poller = Arc::clone(&shared);
    if std::thread::Builder::new()
        .name("faults".into())
        .spawn(move || service::poll_faults(&*poller, faults_dropped))
        .is_err()
    {
        std::os::seraph::log!(
            "fault poll thread not started; faults are polled only when devmgr takes them"
        );
    }

    // SAFETY: ipc_buf is this thread's registered IPC buffer.
    if let Err(e) = unsafe { ipc::report_driver_ready(boot.devmgr_query, ipc_buf) }
    {
        std::os::seraph::log!(
            "DRIVER_READY failed ({:?}); every IOMMU returned to Bare",
            e
        );
        shared.with(Service::disable);
        syscall::thread_exit();
    }
    // SAFETY: ipc_buf is this thread's registered IPC buffer.
    unsafe { service::serve(boot.service_ep, ipc_buf, &*shared, recv_diag) }
}
