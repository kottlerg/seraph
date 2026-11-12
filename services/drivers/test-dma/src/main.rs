// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/drivers/test-dma/src/main.rs

//! Test-only driver for QEMU's `edu` device (PCI `1234:11e8`), whose DMA
//! engine copies between a 4 KiB buffer inside the device, at device offset
//! `0x40000`, and a device address the driver programs.
//!
//! devmgr binds it to the device by the declaration below when svcmgr hands
//! it the drivers directory, like any driver, and delivers it the resource
//! list of `driver_binding::resources`: BAR 0 whole (the identification,
//! interrupt, and DMA registers), the device's one MSI vector (its wired line
//! where devmgr cannot give MSI), then the service endpoint, the devmgr query
//! cap, and the device's DMA capability. It checks the device's
//! identification register, binds its interrupt to a notification of its
//! own, reports ready, and answers `ipc::test_dma_labels::INTERRUPT_PROBE`
//! (the device raises its interrupt and the driver waits for it) and
//! `ipc::test_dma_labels::DMA_PROBE`: it maps one page of its memory for the
//! device, copies a pattern from the page into the device's buffer and back
//! to the page's second half, unmaps the page, and copies the buffer to the
//! same device address once more, reporting whether the mapped copies arrived
//! and whether the copy after the unmap reached the page. Behind an IOMMU it
//! does not, and the IOMMU records a fault for it, which the driver waits to
//! see counted by devmgr (`devmgr_dma_labels::DMA_FAULTS`) and reports with
//! the probe.

use std::time::{Duration, Instant};

use driver_binding::decl::{Declaration, Interrupt, InterruptNeed, Match, Reset, Tier};
use driver_binding::resources::{Endpoints, InterruptKind, Resource};
use ipc::{IpcMessage, memmgr_errors, memmgr_labels, test_dma_labels};
use std::os::seraph::{reserve_pages, startup_info};
use syscall_abi::PAGE_SIZE;

driver_binding::driver_declaration!(Declaration {
    name: "test-dma",
    class: Some("test-dma"),
    matches: &[Match::PciId {
        vendor: 0x1234,
        device: 0x11e8,
    }],
    instance_limit: Some(1),
    // The edu device's one MSI vector; the probe reports what it was given.
    interrupt: Interrupt {
        need: InterruptNeed::Optional,
        msi_vectors: 1,
    },
    dma: true,
    // The edu device's default DMA mask is 28 bits.
    dma_width: Some(28),
    phys_access: false,
    reset: Reset::None,
    tier: Tier::Auxiliary,
});

/// The identification register and the value an `edu` device reads there
/// (major version 1, minor 0).
const IDENT: u64 = 0x00;
const IDENT_EDU: u32 = 0x0100_00ed;
/// The interrupt status, raise, and acknowledge registers (32-bit): a value
/// written to raise is set in the status and signals the device's
/// interrupt (its MSI when MSI is enabled, its wired line otherwise); a
/// value written to acknowledge clears those status bits.
const IRQ_STATUS: u64 = 0x24;
const IRQ_RAISE: u64 = 0x60;
const IRQ_ACKNOWLEDGE: u64 = 0x64;
/// The status bit the interrupt probe raises.
const PROBE_STATUS: u32 = 1;
/// DMA source, destination, byte count, and command registers (64-bit).
const DMA_SRC: u64 = 0x80;
const DMA_DST: u64 = 0x88;
const DMA_CNT: u64 = 0x90;
const DMA_CMD: u64 = 0x98;
/// Command bits: start the transfer (clear once it completed), and copy from
/// the device's buffer to memory rather than from memory to the buffer.
const CMD_RUN: u64 = 1 << 0;
const CMD_TO_MEMORY: u64 = 1 << 1;
/// The device address of the device's DMA buffer.
const DEVICE_BUFFER: u64 = 0x4_0000;
/// The DMA reach of the device: its default DMA mask is 28 bits, and it
/// truncates a wider address.
const DMA_REACH: u64 = 1 << 28;
/// Bytes of the probe page.
const PAGE_BYTES: usize = 4096;
/// Bytes each probe transfer copies.
const PROBE_LEN: usize = 256;
/// Where in the page the copies back to memory land.
const BACK_OFFSET: usize = 0x800;
/// How long one transfer may take: the device starts a transfer on a 100 ms
/// timer, so a transfer that has not completed in 2 s never will.
const TRANSFER_TIMEOUT: Duration = Duration::from_secs(2);
/// How long to wait between two `DMA_FAULTS` requests.
const FAULT_POLL: Duration = Duration::from_millis(50);

/// The device's interrupt as the driver holds it: its `Interrupt` cap, the
/// kind devmgr gave, and the notification the cap is bound to.
#[derive(Clone, Copy)]
struct Irq
{
    cap: u64,
    kind: InterruptKind,
    notification: u64,
}

struct Driver
{
    regs: u64,
    dma_ep: u64,
    memmgr_ep: u64,
    aspace: u64,
    irq: Option<Irq>,
}

impl Driver
{
    fn read32(&self, off: u64) -> u32
    {
        // SAFETY: `regs` maps the device's first BAR page for the driver's
        // life, `off` lies in it, and the register is 32-bit aligned; reached
        // only through raw volatile accesses.
        unsafe { core::ptr::read_volatile((self.regs + off) as *const u32) }
    }

    fn write32(&self, off: u64, value: u32)
    {
        // SAFETY: as in `read32`.
        unsafe { core::ptr::write_volatile((self.regs + off) as *mut u32, value) };
    }

    fn read64(&self, off: u64) -> u64
    {
        // SAFETY: as in `read32`, for a 64-bit register.
        unsafe { core::ptr::read_volatile((self.regs + off) as *const u64) }
    }

    fn write64(&self, off: u64, value: u64)
    {
        // SAFETY: as in `read64`.
        unsafe { core::ptr::write_volatile((self.regs + off) as *mut u64, value) };
    }

    /// Copy `PROBE_LEN` bytes from `src` to `dst` with `cmd`'s direction and
    /// wait for the device to complete it; `false` when it does not within
    /// [`TRANSFER_TIMEOUT`].
    fn transfer(&self, src: u64, dst: u64, to_memory: bool) -> bool
    {
        self.write64(DMA_SRC, src);
        self.write64(DMA_DST, dst);
        self.write64(DMA_CNT, PROBE_LEN as u64);
        let dir = if to_memory { CMD_TO_MEMORY } else { 0 };
        self.write64(DMA_CMD, CMD_RUN | dir);
        let start = Instant::now();
        while self.read64(DMA_CMD) & CMD_RUN != 0
        {
            if start.elapsed() > TRANSFER_TIMEOUT
            {
                return false;
            }
            let _ = syscall::thread_yield();
        }
        true
    }

    /// One page of memory from memmgr, mapped writable: its cap and address.
    fn page(&self, ipc_buf: *mut u64) -> Option<(u64, u64)>
    {
        let arg = 1 | (u64::from(memmgr_labels::REQUIRE_CONTIGUOUS) << 32);
        let request = IpcMessage::builder(memmgr_labels::REQUEST_MEMORY_CAPS)
            .word(0, arg)
            .build();
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let reply = unsafe { ipc::ipc_call(self.memmgr_ep, &request, ipc_buf) }.ok()?;
        if reply.label != memmgr_errors::SUCCESS || reply.caps().len() != 1
        {
            for &c in reply.caps()
            {
                let _ = syscall::cap_delete(c);
            }
            return None;
        }
        let cap = reply.caps()[0];
        let range = reserve_pages(1).ok()?;
        let va = range.va_start();
        // SAFETY: `range` is a fresh one-page reservation, kept for the
        // driver's life: VA no Rust object or IPC page occupies.
        unsafe { syscall::mem_map(cap, self.aspace, va, 0, 1, syscall::MAP_WRITABLE) }.ok()?;
        Some((cap, va))
    }

    /// Run the interrupt probe: clear any delivery already pending, have the
    /// device raise its interrupt, wait for it for at most
    /// `test_dma_labels::INTERRUPT_WAIT_MS`, then acknowledge it at the
    /// device and with `SYS_IRQ_ACK`, which clears the acknowledgement the
    /// binding owes. Returns whether it was delivered and the kind of
    /// interrupt held; `(false, None)` with none.
    fn interrupt_probe(&self) -> (bool, Option<InterruptKind>)
    {
        let Some(irq) = self.irq
        else
        {
            return (false, None);
        };
        let _ = syscall::notification_try_wait(irq.notification);
        self.write32(IRQ_RAISE, PROBE_STATUS);
        let bits = syscall::notification_wait_timeout(
            irq.notification,
            test_dma_labels::INTERRUPT_WAIT_MS,
        )
        .unwrap_or(0);
        self.write32(IRQ_ACKNOWLEDGE, self.read32(IRQ_STATUS));
        let _ = syscall::irq_ack(irq.cap);
        (bits != 0, Some(irq.kind))
    }

    /// Run the probe; the reply's outcome, whether the copy after the unmap
    /// reached the page, and the device address the page was mapped at.
    fn probe(&self, ipc_buf: *mut u64) -> Option<(u64, u64, u64)>
    {
        let (cap, va) = self.page(ipc_buf)?;
        let byte = |i: usize| (va + i as u64) as *mut u8;
        for i in 0..PAGE_BYTES
        {
            let v = if i < PROBE_LEN { pattern(i) } else { 0 };
            // SAFETY: `va` maps one writable page and `i` is inside it.
            unsafe { core::ptr::write_volatile(byte(i), v) };
        }
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let iova = unsafe {
            virtio_core::dma::map(
                self.dma_ep,
                cap,
                virtio_core::dma::DEVICE_READS_WRITES,
                ipc_buf,
            )
        }
        .ok()?;
        let back = |i: usize| {
            // SAFETY: `va` maps one writable page and `BACK_OFFSET + i` is
            // inside it; the device writes it, so it is read volatile.
            unsafe { core::ptr::read_volatile(byte(BACK_OFFSET + i)) }
        };
        if iova + PAGE_SIZE > DMA_REACH
        {
            // SAFETY: as above.
            let _ = unsafe { virtio_core::dma::unmap(self.dma_ep, iova, ipc_buf) };
            return Some((test_dma_labels::PROBE_SKIPPED, 0, iova));
        }
        let dst = iova + BACK_OFFSET as u64;
        let copied = self.transfer(iova, DEVICE_BUFFER, false)
            && self.transfer(DEVICE_BUFFER, dst, true)
            && (0..PROBE_LEN).all(|i| back(i) == pattern(i));
        // SAFETY: as above.
        unsafe { virtio_core::dma::unmap(self.dma_ep, iova, ipc_buf) }.ok()?;
        for i in 0..PROBE_LEN
        {
            // SAFETY: as above.
            unsafe { core::ptr::write_volatile(byte(BACK_OFFSET + i), 0) };
        }
        let completed = self.transfer(DEVICE_BUFFER, dst, true);
        let landed = (0..PROBE_LEN).any(|i| back(i) != 0);
        let outcome = if copied && completed
        {
            test_dma_labels::PROBE_PASSED
        }
        else
        {
            test_dma_labels::PROBE_FAILED
        };
        Some((outcome, u64::from(landed), iova))
    }
}

/// The IOMMU faults devmgr has taken for the device once the copy after the
/// unmap at `iova` is counted: `DMA_FAULTS` asked until its latest fault is
/// in the probe page, for at most `test_dma_labels::FAULT_WAIT_MS`. An
/// unconfined device's reply comes at once. `None` when devmgr refuses.
fn faults_after(dma_ep: u64, iova: u64, ipc_buf: *mut u64) -> Option<ipc::DmaFaults>
{
    let start = Instant::now();
    loop
    {
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let f = unsafe { ipc::dma_faults(dma_ep, ipc_buf) }.ok()?;
        let counted = f.count != 0 && f.last_iova == iova & !(PAGE_SIZE - 1);
        if !f.confined
            || counted
            || start.elapsed() >= Duration::from_millis(test_dma_labels::FAULT_WAIT_MS)
        {
            return Some(f);
        }
        std::thread::sleep(FAULT_POLL);
    }
}

/// The probe pattern's byte at `i`: none zero.
fn pattern(i: usize) -> u8
{
    i.to_le_bytes()[0].wrapping_mul(7) | 0x80
}

fn main() -> !
{
    std::os::seraph::log::register_name(b"test-dma");
    let info = startup_info();
    // cast_ptr_alignment: the IPC buffer page is 4 KiB-aligned.
    #[allow(clippy::cast_ptr_alignment)]
    let ipc_buf = info.ipc_buffer.cast::<u64>();

    let Some((bar_cap, bar_pages, irq, eps)) = receive(info.creator_endpoint, ipc_buf)
    else
    {
        std::os::seraph::log!("test-dma: bootstrap caps missing");
        syscall::thread_exit();
    };
    let Ok(range) = reserve_pages(bar_pages)
    else
    {
        syscall::thread_exit();
    };
    let regs = range.va_start();
    let funded = std::os::seraph::fund_aspace_pt_budget(info.self_aspace, bar_pages);
    // SAFETY: `range` is a fresh reservation of `bar_pages` pages, kept for
    // the driver's life, and the BAR cap spans at most `bar_pages` pages, so
    // the whole-cap mapping stays inside it; the registers are reached only
    // through raw volatile accesses (`mmio_map` § Safety).
    if !funded || unsafe { syscall::mmio_map(info.self_aspace, bar_cap, regs, 0) }.is_err()
    {
        std::os::seraph::log!("test-dma: BAR 0 not mapped");
        syscall::thread_exit();
    }
    let driver = Driver {
        regs,
        dma_ep: eps.dma,
        memmgr_ep: info.memmgr_endpoint,
        aspace: info.self_aspace,
        irq: irq.and_then(bind_interrupt),
    };
    if driver.read32(IDENT) != IDENT_EDU
    {
        std::os::seraph::log!("test-dma: the device is not an edu device");
        syscall::thread_exit();
    }
    std::os::seraph::log!("test-dma: interrupt {:?}", driver.irq.map(|irq| irq.kind));
    // SAFETY: ipc_buf is the registered IPC buffer page.
    if unsafe { ipc::report_driver_ready(eps.devmgr_query, ipc_buf) }.is_err()
    {
        syscall::thread_exit();
    }
    serve(&driver, eps.service, ipc_buf);
}

/// Bind the interrupt `(cap, kind, mode)` to a notification created for it
/// and arm it: `irq_register` leaves the binding masked until its first
/// acknowledgement. `None`, logged, when the notification cannot be
/// created or the binding is refused.
fn bind_interrupt((cap, kind, mode): (u64, InterruptKind, u64)) -> Option<Irq>
{
    let notification =
        std::os::seraph::object_slab_retype(std::os::seraph::NOTIFICATION_RETYPE_BYTES, |slab| {
            syscall::cap_create_notification(slab).ok()
        });
    let Some(notification) = notification
    else
    {
        std::os::seraph::log!("test-dma: no notification for the interrupt");
        return None;
    };
    if syscall::irq_register(cap, notification, mode).is_err()
    {
        std::os::seraph::log!("test-dma: interrupt not bound");
        let _ = syscall::cap_delete(notification);
        return None;
    }
    let _ = syscall::irq_ack(cap);
    Some(Irq {
        cap,
        kind,
        notification,
    })
}

/// The first interrupt resource of a resource list: its cap, kind, and mode.
type ListedIrq = (u64, InterruptKind, u64);

/// Request the resource list from `creator`, the driver's creator endpoint:
/// the cap of BAR 0 with the pages it spans, the first interrupt resource
/// (`None` when there is none), and the end round's endpoints. `None` when
/// the list does not decode, carries no BAR 0, or carries no DMA capability.
fn receive(creator: u64, ipc_buf: *mut u64) -> Option<(u64, u64, Option<ListedIrq>, Endpoints)>
{
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let list = unsafe { driver_binding::resources::receive(creator, ipc_buf) }.ok()?;
    let eps = list.endpoints()?;
    let bar = list.resources().iter().find_map(|r| match *r
    {
        Resource::Mmio {
            cap,
            bar: Some(0),
            bytes,
            ..
        } => Some((cap, bytes.div_ceil(PAGE_SIZE))),
        _ => None,
    });
    let (cap, pages) = bar?;
    let irq = list.resources().iter().find_map(|r| match *r
    {
        Resource::Interrupt {
            cap, kind, mode, ..
        } => Some((cap, kind, mode)),
        _ => None,
    });
    (eps.dma != 0 && eps.service != 0).then_some((cap, pages, irq, eps))
}

/// Answer `INTERRUPT_PROBE` and `DMA_PROBE` for the rest of the driver's
/// life.
fn serve(driver: &Driver, service_ep: u64, ipc_buf: *mut u64) -> !
{
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
            test_dma_labels::INTERRUPT_PROBE =>
            {
                let (delivered, kind) = driver.interrupt_probe();
                std::os::seraph::log!(
                    "test-dma: interrupt probe {:?}, delivered={}",
                    kind,
                    delivered
                );
                IpcMessage::builder(ipc::devmgr_errors::SUCCESS)
                    .word(0, u64::from(delivered))
                    .word(1, kind.map_or(0, |k| k as u64))
                    .build()
            }
            test_dma_labels::DMA_PROBE => match driver.probe(ipc_buf).and_then(|(o, l, iova)| {
                faults_after(driver.dma_ep, iova, ipc_buf).map(|f| (o, l, iova, f))
            })
            {
                Some((outcome, landed, iova, faults)) =>
                {
                    std::os::seraph::log!(
                        "test-dma: probe outcome {} at device address {:#x}, copy after unmap landed={}, confined={}, faults={}",
                        outcome,
                        iova,
                        landed,
                        faults.confined,
                        faults.count
                    );
                    let confined = if faults.confined
                    {
                        ipc::devmgr_dma_labels::DMA_CONFINED
                    }
                    else
                    {
                        0
                    };
                    IpcMessage::builder(ipc::devmgr_errors::SUCCESS)
                        .word(0, outcome)
                        .word(1, landed)
                        .word(2, iova)
                        .word(3, confined)
                        .word(4, faults.count)
                        .word(5, faults.last_iova)
                        .build()
                }
                None => IpcMessage::new(ipc::devmgr_errors::INVALID_REQUEST),
            },
            _ => IpcMessage::new(ipc::devmgr_errors::UNKNOWN_OPCODE),
        };
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
    }
}
