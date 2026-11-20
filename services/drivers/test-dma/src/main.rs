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
//! (the device raises its interrupt and the driver waits for it),
//! `ipc::test_dma_labels::INTERRUPT_CHURN` (while a thread has the device
//! raise in a loop, the driver deletes its bound cap, then its notification's
//! last cap and the binding's cap, and after each binds a spare copy to a new
//! notification and probes through it), `ipc::test_dma_labels::FIXTURE_EXIT`
//! (it leaves the interrupt raised and exits, so devmgr frees its target),
//! and `ipc::test_dma_labels::DMA_PROBE`: it maps one page of its memory for the
//! device, copies a pattern from the page into the device's buffer and back
//! to the page's second half, unmaps the page, and copies the buffer to the
//! same device address once more, reporting whether the mapped copies arrived
//! and whether the copy after the unmap reached the page. Behind an IOMMU it
//! does not, and the IOMMU records a fault for it, which the driver waits to
//! see counted by devmgr (`devmgr_dma_labels::DMA_FAULTS`) and reports with
//! the probe. `ipc::test_dma_labels::MSI_FORGE` has the device's DMA engine
//! write the driver's own message to its message address, which must be
//! delivered, and then to a forged message address its targets do not allow,
//! which must not: on riscv64 the IOMMU blocks the write and records a fault,
//! which devmgr counts for the device; on `x86_64` interrupt remapping finds no
//! entry for the forged handle, and the probe can observe only that the write
//! is not delivered, since QEMU records no requester for the fault.
//! `ipc::test_dma_labels::DMA_STREAM_START` maps one page for the device,
//! which stays mapped, and starts a thread that copies through it in a loop
//! (each round a fresh pattern to the page's first half, through the device's
//! buffer, back to the second half, and a check); `DMA_STREAM_COUNT` reports
//! the rounds so far and `DMA_STREAM_STOP` ends the thread and unmaps the
//! page. While the stream runs the driver refuses the other probes, so only
//! the thread drives the device's DMA engine.

use std::cell::{Cell, RefCell};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread::JoinHandle;
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
    // The edu device's default DMA mask is 28 bits; a test launch widens
    // it, but the fixture's mappings keep within the default.
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
/// The DMA reach the fixture declares, and devmgr's device addresses for it
/// stay below: 28 bits, the `edu` device's default DMA mask. A test launch
/// widens the device's mask to 32 bits, so the forged-message probe reaches
/// the interrupt addresses, which it writes without a mapping.
const DMA_REACH: u64 = 1 << 28;
/// Bytes of the probe page.
const PAGE_BYTES: usize = 4096;
/// Bytes each probe transfer copies.
const PROBE_LEN: usize = 256;
/// Where in the page the copies back to memory land.
const BACK_OFFSET: usize = 0x800;
/// Bytes of a message-signaled interrupt's data, which a device writes to
/// its message address.
const MESSAGE_BYTES: u64 = 4;
/// Bit 4 of an `x86_64` message address: the remappable format (Intel VT-d
/// specification, "Interrupt Requests in Remappable Format").
#[cfg(target_arch = "x86_64")]
const ADDRESS_REMAPPABLE: u64 = 1 << 4;
/// The remappable message address naming handle `0xFFFF`, with the
/// subhandle valid: `0xFEE` in bits 31:20, handle bits 14:0 in bits 19:5, the
/// format bit, the subhandle-valid bit, and handle bit 15 in bit 2. The
/// kernel gives no target that handle, so no remapping table holds it.
#[cfg(target_arch = "x86_64")]
const FORGED_REMAPPABLE: u64 =
    0xFEE0_0000 | (0x7FFF << 5) | ADDRESS_REMAPPABLE | (1 << 3) | (1 << 2);
/// How long one transfer may take: the device starts a transfer on a 100 ms
/// timer, so a transfer that has not completed in 2 s never will.
const TRANSFER_TIMEOUT: Duration = Duration::from_secs(2);
/// How long to wait between two `DMA_FAULTS` requests.
const FAULT_POLL: Duration = Duration::from_millis(50);
/// Raises the churn's loop makes before a case's deletes start and after
/// they end, so the deletes run while the device raises.
const CHURN_RAISES: u64 = 64;
/// How long the churn waits for each run of [`CHURN_RAISES`] raises.
const CHURN_WAIT: Duration = Duration::from_secs(2);

/// The device's interrupt as the driver holds it: its `Interrupt` cap, the
/// kind and `SYS_IRQ_REGISTER` mode devmgr gave, and the notification the cap
/// is bound to.
#[derive(Clone, Copy)]
struct Irq
{
    cap: u64,
    kind: InterruptKind,
    mode: u64,
    notification: u64,
}

struct Driver
{
    regs: u64,
    dma_ep: u64,
    memmgr_ep: u64,
    aspace: u64,
    /// The binding the probes use; the churn replaces it.
    irq: Cell<Option<Irq>>,
    /// The running DMA stream, if any.
    stream: RefCell<Option<Stream>>,
}

/// The counters a DMA stream's thread shares with the driver.
struct StreamShared
{
    /// Rounds whose copy arrived.
    arrived: AtomicU64,
    /// Rounds whose copy did not arrive or whose transfer did not complete.
    failed: AtomicU64,
    /// Set to end the thread after its round.
    stop: AtomicBool,
}

/// A running DMA stream (`test_dma_labels::DMA_STREAM_START`).
struct Stream
{
    shared: Arc<StreamShared>,
    thread: JoinHandle<()>,
    /// The device address the stream's page is mapped at.
    iova: u64,
}

/// The address of the register at `off` in the BAR page mapped at `regs`.
/// Every register offset lies inside the page, so the sum never saturates.
fn register(regs: u64, off: u64) -> u64
{
    regs.saturating_add(off)
}

impl Driver
{
    fn read32(&self, off: u64) -> u32
    {
        // SAFETY: `regs` maps the device's first BAR page for the driver's
        // life, `off` lies in it, and the register is 32-bit aligned; reached
        // only through raw volatile accesses.
        unsafe { core::ptr::read_volatile(register(self.regs, off) as *const u32) }
    }

    fn write32(&self, off: u64, value: u32)
    {
        // SAFETY: as in `read32`.
        unsafe { core::ptr::write_volatile(register(self.regs, off) as *mut u32, value) };
    }

    /// Copy `PROBE_LEN` bytes from `src` to `dst` ([`Driver::transfer_bytes`]).
    #[expect(
        clippy::fn_params_excessive_bools,
        reason = "`to_memory` is the direction bit of the edu DMA command register"
    )]
    fn transfer(&self, src: u64, dst: u64, to_memory: bool) -> bool
    {
        self.transfer_bytes(src, dst, PROBE_LEN as u64, to_memory)
    }

    /// Copy `len` bytes from `src` to `dst`, from the device's buffer to
    /// memory when `to_memory`, and wait for the device to complete it;
    /// `false` when it does not within [`TRANSFER_TIMEOUT`].
    #[expect(
        clippy::fn_params_excessive_bools,
        reason = "`to_memory` is the direction bit of the edu DMA command register"
    )]
    fn transfer_bytes(&self, src: u64, dst: u64, len: u64, to_memory: bool) -> bool
    {
        dma_transfer(self.regs, src, dst, len, to_memory)
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
        let (memmgr_errors::SUCCESS, &[cap]) = (reply.label, reply.caps())
        else
        {
            for &c in reply.caps()
            {
                let _ = syscall::cap_delete(c);
            }
            return None;
        };
        let range = reserve_pages(1).ok()?;
        let va = range.va_start();
        // SAFETY: `range` is a fresh one-page reservation, kept for the
        // driver's life, mapped or not: VA no Rust object or IPC page
        // occupies.
        unsafe {
            std::os::seraph::mem_map_funded(cap, self.aspace, va, 0, 1, syscall::MAP_WRITABLE)
        }
        .ok()?;
        Some((cap, va))
    }

    /// Run the interrupt probe through the fixture's binding
    /// ([`Driver::delivers`]). Returns whether it was delivered and the kind
    /// of interrupt held; `(false, None)` with none.
    fn interrupt_probe(&self) -> (bool, Option<InterruptKind>)
    {
        let Some(irq) = self.irq.get()
        else
        {
            return (false, None);
        };
        (self.delivers(irq), Some(irq.kind))
    }

    /// Clear any delivery already pending on `irq`'s notification, have the
    /// device raise its interrupt, wait for it for at most
    /// `test_dma_labels::INTERRUPT_WAIT_MS`, then acknowledge it at the
    /// device and with `SYS_IRQ_ACK`, which clears the acknowledgement the
    /// binding owes. Returns whether it was delivered.
    fn delivers(&self, irq: Irq) -> bool
    {
        let _ = syscall::notification_try_wait(irq.notification);
        self.write32(IRQ_RAISE, PROBE_STATUS);
        let bits = syscall::notification_wait_timeout(
            irq.notification,
            test_dma_labels::INTERRUPT_WAIT_MS,
        )
        .unwrap_or(0);
        self.write32(IRQ_ACKNOWLEDGE, self.read32(IRQ_STATUS));
        let _ = syscall::irq_ack(irq.cap);
        bits != 0
    }

    /// Run the interrupt churn (`test_dma_labels::INTERRUPT_CHURN`): the
    /// cases whose next binding received the device's interrupt, the kind of
    /// interrupt held, and the raises the loop made; `(0, None, 0)` with no
    /// interrupt. A case that cannot bind its next binding ends the churn.
    fn interrupt_churn(&self) -> (u64, Option<InterruptKind>, u64)
    {
        let Some(first) = self.irq.get()
        else
        {
            return (0, None, 0);
        };
        let raises = Arc::new(AtomicU64::new(0));
        let mut passed = 0;
        // The bound cap goes while the device raises; the binding it held
        // is removed with it.
        if let Some(second) = self.churn_case(first, &raises, |irq| {
            let _ = syscall::cap_delete(irq.cap);
        })
        {
            // No binding names the first notification any more.
            let _ = syscall::cap_delete(first.notification);
            if self.delivers(second)
            {
                passed |= test_dma_labels::CHURN_BOUND_CAP;
            }
            // The notification's last cap goes, so the binding holds it
            // alone, then the binding's cap, which frees it.
            if let Some(third) = self.churn_case(second, &raises, |irq| {
                let _ = syscall::cap_delete(irq.notification);
                let _ = syscall::cap_delete(irq.cap);
            }) && self.delivers(third)
            {
                passed |= test_dma_labels::CHURN_NOTIFICATION;
            }
        }
        (passed, Some(first.kind), raises.load(Ordering::Relaxed))
    }

    /// One churn case on the bound `irq`: derive a spare copy of its cap,
    /// run `delete` on it while the device raises ([`Driver::while_raising`]),
    /// then bind the spare to a new notification ([`bind_interrupt`]) and
    /// make that the fixture's binding. `None`, the fixture then holding no
    /// interrupt, when the copy or the new binding fails.
    fn churn_case(&self, irq: Irq, raises: &Arc<AtomicU64>, delete: impl FnOnce(Irq))
    -> Option<Irq>
    {
        let spare = syscall::cap_derive(irq.cap, syscall::RIGHTS_ALL).ok()?;
        self.while_raising(raises, || delete(irq));
        let next = bind_interrupt((spare, irq.kind, irq.mode));
        if next.is_none()
        {
            let _ = syscall::cap_delete(spare);
        }
        self.irq.set(next);
        next
    }

    /// Run `f` while a thread of the fixture has the device raise its
    /// interrupt in a loop, acknowledging each raise at the device. `f`
    /// starts once the loop has made [`CHURN_RAISES`] raises, and the loop
    /// stops once it has made as many more after `f` returned, each wait
    /// bounded by [`CHURN_WAIT`]. The loop's raises are added to `raises`;
    /// with no thread, `f` runs with none.
    fn while_raising(&self, raises: &Arc<AtomicU64>, f: impl FnOnce())
    {
        let stop = Arc::new(AtomicBool::new(false));
        let regs = self.regs;
        let (loop_stop, loop_raises) = (Arc::clone(&stop), Arc::clone(raises));
        let raise_loop = std::thread::Builder::new().spawn(move || {
            while !loop_stop.load(Ordering::Acquire)
            {
                #[expect(
                    clippy::multiple_unsafe_ops_per_block,
                    reason = "every write is to a register of the device's BAR 0, which `regs` \
                              maps for the driver's life"
                )]
                // SAFETY: as in `Driver::write32`: `regs` maps BAR 0 for the
                // driver's life, and both registers are 32-bit aligned in it.
                unsafe {
                    core::ptr::write_volatile(register(regs, IRQ_RAISE) as *mut u32, PROBE_STATUS);
                    core::ptr::write_volatile(
                        register(regs, IRQ_ACKNOWLEDGE) as *mut u32,
                        PROBE_STATUS,
                    );
                }
                loop_raises.fetch_add(1, Ordering::Relaxed);
            }
        });
        let wait_for = |count: u64| {
            let start = Instant::now();
            while raise_loop.is_ok()
                && raises.load(Ordering::Relaxed) < count
                && start.elapsed() < CHURN_WAIT
            {
                let _ = syscall::thread_yield();
            }
        };
        // A raise count near `u64::MAX` would take centuries to reach, so the
        // saturation never ends a wait early.
        wait_for(raises.load(Ordering::Relaxed).saturating_add(CHURN_RAISES));
        f();
        wait_for(raises.load(Ordering::Relaxed).saturating_add(CHURN_RAISES));
        stop.store(true, Ordering::Release);
        if let Ok(raise_loop) = raise_loop
        {
            let _ = raise_loop.join();
        }
    }

    /// Run the probe; the reply's outcome, whether the copy after the unmap
    /// reached the page, and the device address the page was mapped at.
    fn probe(&self, ipc_buf: *mut u64) -> Option<(u64, u64, u64)>
    {
        let (cap, va) = self.page(ipc_buf)?;
        // Every `i` passed lies inside the page, so the sum never saturates.
        let byte = |i: usize| va.saturating_add(i as u64) as *mut u8;
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
            unsafe { core::ptr::read_volatile(byte(BACK_OFFSET.saturating_add(i))) }
        };
        if !within_reach(iova)
        {
            // SAFETY: as above.
            let _ = unsafe { virtio_core::dma::unmap(self.dma_ep, iova, ipc_buf) };
            return Some((test_dma_labels::PROBE_SKIPPED, 0, iova));
        }
        // Below `DMA_REACH`, as the page's end is.
        let dst = iova.saturating_add(BACK_OFFSET as u64);
        let copied = self.transfer(iova, DEVICE_BUFFER, false)
            && self.transfer(DEVICE_BUFFER, dst, true)
            && (0..PROBE_LEN).all(|i| back(i) == pattern(i));
        // SAFETY: as above.
        unsafe { virtio_core::dma::unmap(self.dma_ep, iova, ipc_buf) }.ok()?;
        for i in 0..PROBE_LEN
        {
            // SAFETY: as above.
            unsafe { core::ptr::write_volatile(byte(BACK_OFFSET.saturating_add(i)), 0) };
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

/// Copy `len` bytes from `src` to `dst` through the DMA registers of the
/// BAR page mapped at `regs`, from the device's buffer to memory when
/// `to_memory`, and wait for the device to complete it; `false` when it
/// does not within [`TRANSFER_TIMEOUT`].
#[expect(
    clippy::fn_params_excessive_bools,
    reason = "`to_memory` is the direction bit of the edu DMA command register"
)]
fn dma_transfer(regs: u64, src: u64, dst: u64, len: u64, to_memory: bool) -> bool
{
    let write = |off: u64, value: u64| {
        // SAFETY: `regs` maps the device's first BAR page for the driver's
        // life, `off` lies in it, and the register is 64-bit aligned; reached
        // only through raw volatile accesses.
        unsafe { core::ptr::write_volatile(register(regs, off) as *mut u64, value) };
    };
    let read = |off: u64| {
        // SAFETY: as in `write`.
        unsafe { core::ptr::read_volatile(register(regs, off) as *const u64) }
    };
    write(DMA_SRC, src);
    write(DMA_DST, dst);
    write(DMA_CNT, len);
    let dir = if to_memory { CMD_TO_MEMORY } else { 0 };
    write(DMA_CMD, CMD_RUN | dir);
    let start = Instant::now();
    while read(DMA_CMD) & CMD_RUN != 0
    {
        if start.elapsed() > TRANSFER_TIMEOUT
        {
            return false;
        }
        let _ = syscall::thread_yield();
    }
    true
}

/// The pattern byte at `i` of stream round `round`: none zero.
fn stream_pattern(round: u64, i: usize) -> u8
{
    pattern(i).wrapping_add(round.to_le_bytes()[0]) | 0x80
}

/// One stream round on the page mapped at `va` and at the device address
/// `iova`: write round `round`'s pattern to the first half, clear the
/// second, copy through the device's buffer to the second half, and check
/// it. `false` when a transfer does not complete or the copy differs.
fn stream_round(regs: u64, va: u64, iova: u64, round: u64) -> bool
{
    // Every `i` passed lies inside the page, so the sum never saturates.
    let byte = |i: usize| va.saturating_add(i as u64) as *mut u8;
    for i in 0..PROBE_LEN
    {
        // SAFETY: `va` maps one writable page and `i` is inside it.
        unsafe { core::ptr::write_volatile(byte(i), stream_pattern(round, i)) };
        // SAFETY: as above, for the second half.
        unsafe { core::ptr::write_volatile(byte(BACK_OFFSET.saturating_add(i)), 0) };
    }
    // Below `DMA_REACH`, as the page's end is.
    let dst = iova.saturating_add(BACK_OFFSET as u64);
    dma_transfer(regs, iova, DEVICE_BUFFER, PROBE_LEN as u64, false)
        && dma_transfer(regs, DEVICE_BUFFER, dst, PROBE_LEN as u64, true)
        && (0..PROBE_LEN).all(|i| {
            // SAFETY: as above; the device writes it, so it is read volatile.
            let got = unsafe { core::ptr::read_volatile(byte(BACK_OFFSET.saturating_add(i))) };
            got == stream_pattern(round, i)
        })
}

/// The `DMA_CONFINED` word of a reply for the device whose faults are `faults`.
fn confined_word(faults: &ipc::DmaFaults) -> u64
{
    if faults.confined
    {
        ipc::devmgr_dma_labels::DMA_CONFINED
    }
    else
    {
        0
    }
}

impl Driver
{
    /// Whether a DMA stream runs.
    fn streaming(&self) -> bool
    {
        self.stream.borrow().is_some()
    }

    /// Whether the driver refuses `label` because a stream runs: the probes
    /// that drive the device's DMA engine.
    fn refuses(&self, label: u64) -> bool
    {
        self.streaming()
            && matches!(
                label,
                test_dma_labels::DMA_PROBE
                    | test_dma_labels::INTERRUPT_PROBE
                    | test_dma_labels::INTERRUPT_CHURN
                    | test_dma_labels::MSI_FORGE
            )
    }

    /// Start the DMA stream (`test_dma_labels::DMA_STREAM_START`): the
    /// reply's words `[started, device address, confined, faults]`. `None`
    /// when a stream runs or the setup fails.
    fn stream_start(&self, ipc_buf: *mut u64) -> Option<[u64; 4]>
    {
        if self.streaming()
        {
            return None;
        }
        let (cap, va) = self.page(ipc_buf)?;
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
        // SAFETY: as above.
        let Ok(faults) = (unsafe { ipc::dma_faults(self.dma_ep, ipc_buf) })
        else
        {
            // SAFETY: as above.
            let _ = unsafe { virtio_core::dma::unmap(self.dma_ep, iova, ipc_buf) };
            return None;
        };
        let words = |started: u64| [started, iova, confined_word(&faults), faults.count];
        if !within_reach(iova)
        {
            // SAFETY: as above.
            unsafe { virtio_core::dma::unmap(self.dma_ep, iova, ipc_buf) }.ok()?;
            return Some(words(0));
        }
        let shared = Arc::new(StreamShared {
            arrived: AtomicU64::new(0),
            failed: AtomicU64::new(0),
            stop: AtomicBool::new(false),
        });
        let (regs, thread_shared) = (self.regs, Arc::clone(&shared));
        let spawned = std::thread::Builder::new().spawn(move || {
            let mut round: u64 = 0;
            while !thread_shared.stop.load(Ordering::Acquire)
            {
                let counter = if stream_round(regs, va, iova, round)
                {
                    &thread_shared.arrived
                }
                else
                {
                    &thread_shared.failed
                };
                counter.fetch_add(1, Ordering::Relaxed);
                round = round.wrapping_add(1);
                let _ = syscall::thread_yield();
            }
        });
        let Ok(thread) = spawned
        else
        {
            // SAFETY: as above.
            let _ = unsafe { virtio_core::dma::unmap(self.dma_ep, iova, ipc_buf) };
            return None;
        };
        *self.stream.borrow_mut() = Some(Stream {
            shared,
            thread,
            iova,
        });
        Some(words(1))
    }

    /// The stream's rounds so far (`test_dma_labels::DMA_STREAM_COUNT`):
    /// `[arrived, failed]`; `None` when no stream runs.
    fn stream_count(&self) -> Option<[u64; 2]>
    {
        let stream = self.stream.borrow();
        let s = stream.as_ref()?;
        Some([
            s.shared.arrived.load(Ordering::Relaxed),
            s.shared.failed.load(Ordering::Relaxed),
        ])
    }

    /// Stop the stream (`test_dma_labels::DMA_STREAM_STOP`): the reply's
    /// words `[arrived, failed, device address, faults]`. `None` when no
    /// stream runs or the unmap or the fault request fails.
    fn stream_stop(&self, ipc_buf: *mut u64) -> Option<[u64; 4]>
    {
        let stream = self.stream.borrow_mut().take()?;
        stream.shared.stop.store(true, Ordering::Release);
        let _ = stream.thread.join();
        // SAFETY: ipc_buf is the registered IPC buffer page.
        unsafe { virtio_core::dma::unmap(self.dma_ep, stream.iova, ipc_buf) }.ok()?;
        // SAFETY: as above.
        let faults = unsafe { ipc::dma_faults(self.dma_ep, ipc_buf) }.ok()?;
        Some([
            stream.shared.arrived.load(Ordering::Relaxed),
            stream.shared.failed.load(Ordering::Relaxed),
            stream.iova,
            faults.count,
        ])
    }
}

/// The reply to a `DMA_STREAM_*` `label`.
fn stream_reply(driver: &Driver, label: u64, ipc_buf: *mut u64) -> IpcMessage
{
    match label
    {
        test_dma_labels::DMA_STREAM_START =>
        {
            words_reply(driver.stream_start(ipc_buf).as_ref().map(|w| &w[..]))
        }
        test_dma_labels::DMA_STREAM_COUNT =>
        {
            words_reply(driver.stream_count().as_ref().map(|w| &w[..]))
        }
        _ => words_reply(driver.stream_stop(ipc_buf).as_ref().map(|w| &w[..])),
    }
}

/// A `SUCCESS` reply carrying `words`, or `INVALID_REQUEST` for `None`.
fn words_reply(words: Option<&[u64]>) -> IpcMessage
{
    let Some(words) = words
    else
    {
        return IpcMessage::new(ipc::devmgr_errors::INVALID_REQUEST);
    };
    let mut builder = IpcMessage::builder(ipc::devmgr_errors::SUCCESS);
    for (i, &w) in words.iter().enumerate()
    {
        builder = builder.word(i, w);
    }
    builder.build()
}

/// What the forged-message probe found (`test_dma_labels::MSI_FORGE`).
#[derive(Clone, Copy, Default)]
struct Forge
{
    /// Whether an IOMMU confines the device.
    confined: bool,
    /// Whether the device's write of the fixture's own message reached its
    /// notification.
    own_delivered: bool,
    /// Whether the forged write reached it.
    forged_delivered: bool,
    /// The fixture's own message address.
    address: u64,
    /// The forged message address; 0 when the forged write was not made.
    forged: u64,
    /// The IOMMU faults devmgr has taken for the device, and the IOVA of the
    /// latest.
    faults: u64,
    last_fault: u64,
}

impl Driver
{
    /// Run the forged-message probe (`test_dma_labels::MSI_FORGE`): with
    /// the device confined and an MSI vector held, stage the fixture's own
    /// message data in the device's buffer, have the device write it to the
    /// fixture's own message address and then to [`forged_address`]'s, and
    /// report each write's delivery and, on riscv64, the device's faults
    /// once the forged write is counted. A probe whose preconditions do not
    /// hold reports the forged write not made. `None` on a setup failure.
    fn msi_forge(&self, ipc_buf: *mut u64) -> Option<Forge>
    {
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let confined = unsafe { ipc::dma_faults(self.dma_ep, ipc_buf) }
            .ok()?
            .confined;
        let skipped = Forge {
            confined,
            ..Forge::default()
        };
        let Some(irq) = self.irq.get().filter(|irq| irq.kind == InterruptKind::Msi)
        else
        {
            return Some(skipped);
        };
        if !confined
        {
            return Some(skipped);
        }
        let address = syscall::cap_info(irq.cap, syscall_abi::CAP_INFO_IRQ_MSG_ADDRESS).ok()?;
        let data = syscall::cap_info(irq.cap, syscall_abi::CAP_INFO_IRQ_MSG_DATA).ok()?;
        let Some(forged) = forged_address(address)
        else
        {
            return Some(Forge { address, ..skipped });
        };
        self.stage_message(u32::try_from(data).ok()?, ipc_buf)?;
        let own_delivered = self.write_message(irq, address)?;
        let forged_delivered = self.write_message(irq, forged)?;
        let faults = if cfg!(target_arch = "riscv64")
        {
            faults_after(self.dma_ep, forged, ipc_buf)?
        }
        else
        {
            // SAFETY: ipc_buf is the registered IPC buffer page.
            unsafe { ipc::dma_faults(self.dma_ep, ipc_buf) }.ok()?
        };
        Some(Forge {
            confined,
            own_delivered,
            forged_delivered,
            address,
            forged,
            faults: faults.count,
            last_fault: faults.last_iova,
        })
    }

    /// Put `data`, little-endian, at the start of the device's buffer, copied
    /// from a page of the driver's memory mapped for the device. `None` when
    /// the page, its mapping or the copy fails.
    fn stage_message(&self, data: u32, ipc_buf: *mut u64) -> Option<()>
    {
        let (cap, va) = self.page(ipc_buf)?;
        // SAFETY: `va` maps one writable page, 4-byte aligned.
        unsafe { core::ptr::write_volatile(va as *mut u32, data.to_le()) };
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
        let staged =
            within_reach(iova) && self.transfer_bytes(iova, DEVICE_BUFFER, MESSAGE_BYTES, false);
        // SAFETY: as above.
        unsafe { virtio_core::dma::unmap(self.dma_ep, iova, ipc_buf) }.ok()?;
        staged.then_some(())
    }

    /// Have the device write the message data staged in its buffer to
    /// `address`, wait for `irq`'s notification for at most
    /// `test_dma_labels::INTERRUPT_WAIT_MS`, and acknowledge the binding.
    /// Whether the write was delivered; `None` when the device does not
    /// complete it.
    fn write_message(&self, irq: Irq, address: u64) -> Option<bool>
    {
        let _ = syscall::notification_try_wait(irq.notification);
        if !self.transfer_bytes(DEVICE_BUFFER, address, MESSAGE_BYTES, true)
        {
            return None;
        }
        let bits = syscall::notification_wait_timeout(
            irq.notification,
            test_dma_labels::INTERRUPT_WAIT_MS,
        )
        .unwrap_or(0);
        let _ = syscall::irq_ack(irq.cap);
        Some(bits != 0)
    }
}

/// The message address the forged-message probe writes, given the
/// fixture's own `address`: the interrupt file page beside the one its
/// target sits on, which its domain does not map (bit 12 flipped: the
/// paired hart's supervisor file, 4 KiB apart, or a page past the files).
#[cfg(target_arch = "riscv64")]
#[expect(
    clippy::unnecessary_wraps,
    reason = "the signature is the x86_64 variant's, which has no forged address with remapping \
              off"
)]
fn forged_address(address: u64) -> Option<u64>
{
    Some(address ^ PAGE_SIZE)
}

/// The message address the forged-message probe writes, given the
/// fixture's own `address`: [`FORGED_REMAPPABLE`] when the fixture's own
/// message is remappable, and none otherwise, since with remapping off a
/// remappable-format write would be taken as a compatibility-format one.
#[cfg(target_arch = "x86_64")]
fn forged_address(address: u64) -> Option<u64>
{
    (address & ADDRESS_REMAPPABLE != 0).then_some(FORGED_REMAPPABLE)
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

/// Whether the page devmgr mapped at the device address `iova` ends within
/// the fixture's [`DMA_REACH`]; false for an address whose page end passes
/// `u64`.
fn within_reach(iova: u64) -> bool
{
    iova.checked_add(PAGE_SIZE)
        .is_some_and(|end| end <= DMA_REACH)
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
    #[expect(
        clippy::cast_ptr_alignment,
        reason = "the IPC buffer page is 4 KiB-aligned"
    )]
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
    // SAFETY: `range` is a fresh reservation of `bar_pages` pages, kept for
    // the driver's life, and the BAR cap spans at most `bar_pages` pages, so
    // the whole-cap mapping stays inside it; the registers are reached only
    // through raw volatile accesses (`mmio_map` § Safety).
    let mapped =
        unsafe { std::os::seraph::mmio_map_funded(info.self_aspace, bar_cap, regs, bar_pages) };
    if mapped.is_err()
    {
        std::os::seraph::log!("test-dma: BAR 0 not mapped");
        syscall::thread_exit();
    }
    let driver = Driver {
        regs,
        dma_ep: eps.dma,
        memmgr_ep: info.memmgr_endpoint,
        aspace: info.self_aspace,
        irq: Cell::new(irq.and_then(bind_interrupt)),
        stream: RefCell::new(None),
    };
    if driver.read32(IDENT) != IDENT_EDU
    {
        std::os::seraph::log!("test-dma: the device is not an edu device");
        syscall::thread_exit();
    }
    std::os::seraph::log!(
        "test-dma: interrupt {:?}",
        driver.irq.get().map(|irq| irq.kind)
    );
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
        mode,
        notification,
    })
}

/// The first interrupt resource of a resource list: its cap, kind, and mode.
type ListedIrq = (u64, InterruptKind, u64);

/// Request the resource list from `creator`, the driver's creator endpoint:
/// the cap of BAR 0 with the pages it spans, the first interrupt resource
/// (`None` when there is none), and the end round's endpoints. `None` when
/// the list does not decode, holds an IOMMU unit (an IOMMU record's list),
/// carries no BAR 0, or carries no DMA capability.
fn receive(creator: u64, ipc_buf: *mut u64) -> Option<(u64, u64, Option<ListedIrq>, Endpoints)>
{
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let list = unsafe { driver_binding::resources::receive(creator, ipc_buf) }.ok()?;
    let eps = list.endpoints()?;
    if list.holds_units()
    {
        return None;
    }
    let bar = list.resources().iter().find_map(|r| match *r
    {
        Resource::Mmio {
            cap,
            bar: Some(0),
            bytes,
            ..
        } => Some((cap, bytes.div_ceil(PAGE_SIZE))),
        Resource::Mmio { .. } | Resource::IoPort { .. } | Resource::Interrupt { .. } => None,
    });
    let (cap, pages) = bar?;
    let irq = list.resources().iter().find_map(|r| match *r
    {
        Resource::Interrupt {
            cap, kind, mode, ..
        } => Some((cap, kind, mode)),
        Resource::Mmio { .. } | Resource::IoPort { .. } => None,
    });
    (eps.dma != 0 && eps.service != 0).then_some((cap, pages, irq, eps))
}

/// The reply to `MSI_FORGE` from the probe's findings, logged;
/// `INVALID_REQUEST` when the probe's setup failed.
fn forge_reply(forge: Option<Forge>) -> IpcMessage
{
    let Some(f) = forge
    else
    {
        return IpcMessage::new(ipc::devmgr_errors::INVALID_REQUEST);
    };
    let made = f.forged != 0;
    std::os::seraph::log!(
        "test-dma: forged-message probe made={}, own message at {:#x} delivered={}, forged at {:#x} delivered={}, faults={}",
        made,
        f.address,
        f.own_delivered,
        f.forged,
        f.forged_delivered,
        f.faults
    );
    let confined = if f.confined
    {
        ipc::devmgr_dma_labels::DMA_CONFINED
    }
    else
    {
        0
    };
    IpcMessage::builder(ipc::devmgr_errors::SUCCESS)
        .word(0, confined)
        .word(1, u64::from(made))
        .word(2, u64::from(f.own_delivered))
        .word(3, u64::from(f.forged_delivered))
        .word(4, f.address)
        .word(5, f.forged)
        .word(6, f.faults)
        .word(7, f.last_fault)
        .build()
}

/// Answer `INTERRUPT_PROBE`, `INTERRUPT_CHURN`, `DMA_PROBE`, `MSI_FORGE` and the
/// `DMA_STREAM_*` labels until a `FIXTURE_EXIT`, then exit. While a stream runs the
/// four probes are refused.
#[expect(
    clippy::large_stack_frames,
    reason = "the received `msg` and the `reply` `IpcMessage`s (568 B each) and the builder copies \
              of the arms; on the 32 KiB main-thread stack of test-dma"
)]
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
            label if driver.refuses(label) => IpcMessage::new(ipc::devmgr_errors::INVALID_REQUEST),
            test_dma_labels::DMA_STREAM_START
            | test_dma_labels::DMA_STREAM_COUNT
            | test_dma_labels::DMA_STREAM_STOP => stream_reply(driver, msg.label, ipc_buf),
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
            test_dma_labels::INTERRUPT_CHURN =>
            {
                let (passed, kind, raises) = driver.interrupt_churn();
                std::os::seraph::log!(
                    "test-dma: interrupt churn {:?}, cases passed={:#x}, raises={}",
                    kind,
                    passed,
                    raises
                );
                IpcMessage::builder(ipc::devmgr_errors::SUCCESS)
                    .word(0, passed)
                    .word(1, kind.map_or(0, |k| k as u64))
                    .word(2, raises)
                    .build()
            }
            test_dma_labels::FIXTURE_EXIT => IpcMessage::new(ipc::devmgr_errors::SUCCESS),
            test_dma_labels::MSI_FORGE => forge_reply(driver.msi_forge(ipc_buf)),
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
        if msg.label == test_dma_labels::FIXTURE_EXIT
        {
            // Left raised: devmgr releases the device, and frees its
            // message-signaled target, with its interrupt asserted.
            driver.write32(IRQ_RAISE, PROBE_STATUS);
            let _ = syscall::thread_sleep(test_dma_labels::EXIT_DELAY_MS);
            std::os::seraph::log!("test-dma: exiting on FIXTURE_EXIT");
            syscall::thread_exit();
        }
    }
}
