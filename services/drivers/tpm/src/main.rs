// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/drivers/tpm/src/main.rs

//! Seraph TPM 2.0 driver: the TPM's random number generator as a member of
//! the `hwrng` class.
//!
//! devmgr binds it to the ACPI namespace record whose `_HID` is `MSFT0101`
//! and delivers the record's register window, the TPM's localities from
//! locality 0, as an `Mmio` range, with the driver's service endpoint and
//! its devmgr query cap (`driver_binding::resources::PlatformDelivery`). The
//! driver maps the window, reads which interface the TPM presents (FIFO or
//! CRB), and reads a first few bytes within devmgr's settle bound, sending
//! `TPM2_Startup` when no firmware did; a TPM that fails that probe ends the
//! driver before it reports ready, and the system runs on without it. Then it
//! reports ready and serves [`hwrng_protocol::READ`] with
//! `TPM2_GetRandom`. It polls: the declaration asks for no interrupt.
//!
//! The driver holds the TPM's registers and nothing more: no kernel
//! authority. The design is in `services/drivers/docs/tpm.md`.

use std::time::{Duration, Instant};

use driver_binding::resources::{self, PlatformDelivery, Resource};
use hwrng_protocol::{MAX_READ_BYTES, errors as hwrng_errors};
use ipc::IpcMessage;
use ipc::serve::{Reply, next_request};
use std::os::seraph::{reserve_pages, startup_info};
use syscall_abi::{MSG_DATA_WORDS_MAX, PAGE_SIZE};
use tpm::crb::Crb;
use tpm::fifo::Fifo;
use tpm::regs::{Fault, Registers, Wait};
use tpm::{Interface, Session, Transport};

// ── Declaration ────────────────────────────────────────────────────────────

// What devmgr binds this driver to and how it starts it
// (docs/driver-binding.md § Driver Declarations).
driver_binding::driver_declaration!(driver_binding::decl::Declaration {
    name: "tpm",
    class: Some("hwrng"),
    // The TCG's ACPI identifier of a TPM 2.0 device.
    matches: &[driver_binding::decl::Match::AcpiHid("MSFT0101")],
    instance_limit: Some(1),
    interrupt: driver_binding::decl::Interrupt::NONE,
    dma: false,
    dma_width: None,
    phys_access: false,
    reset: driver_binding::decl::Reset::None,
    tier: driver_binding::decl::Tier::Auxiliary,
});

// ── Constants ──────────────────────────────────────────────────────────────

/// The smallest window the driver takes: locality 0, which holds the
/// registers of both interfaces and, on a CRB TPM, usually its buffers.
const WINDOW_MIN: u64 = PAGE_SIZE;

/// The largest window the driver maps: the five localities of the PC Client
/// TPM range. A record naming more holds no further TPM register.
const WINDOW_MAX: u64 = 5 * PAGE_SIZE;

/// The bound on the start-up probe: inside devmgr's 10 s settle bound, with
/// room for a TPM that runs its self-tests after `TPM2_Startup`.
const PROBE_WAIT: Duration = Duration::from_secs(5);

/// The bound on one `READ`: below the 2 s entropyd gives a reply, so a slow
/// TPM answers with what it produced, or `NOT_READY`, before the caller
/// stops waiting.
const READ_WAIT: Duration = Duration::from_millis(1_500);

/// The pause between polls of a register a command waits on. A TPM answers a
/// `TPM2_GetRandom` in milliseconds.
const POLL_PAUSE: Duration = Duration::from_millis(1);

/// Bytes the probe reads, and discards.
const PROBE_BYTES: usize = 8;

// ── The register window ────────────────────────────────────────────────────

/// The TPM's mapped register window: `len` bytes from `va`. Every access is
/// volatile and bounds-checked against the window, so no offset the library
/// computes from the device's values reaches past it.
#[derive(Clone, Copy)]
struct Window
{
    va: u64,
    len: usize,
}

impl Window
{
    /// The address of the `width`-byte register at `offset`, `None` when it
    /// does not lie wholly inside the window or is not aligned to its width.
    fn at(self, offset: usize, width: usize) -> Option<u64>
    {
        let end = offset.checked_add(width)?;
        if end > self.len || !offset.is_multiple_of(width)
        {
            return None;
        }
        self.va.checked_add(u64::try_from(offset).ok()?)
    }
}

impl Registers for Window
{
    fn read8(&self, offset: usize) -> u8
    {
        let Some(addr) = self.at(offset, 1)
        else
        {
            return u8::MAX;
        };
        // SAFETY: `at` keeps the byte inside the window, which `map_window`
        // mapped for the process's lifetime and nothing else references.
        unsafe { core::ptr::read_volatile(addr as *const u8) }
    }

    fn read32(&self, offset: usize) -> u32
    {
        let Some(addr) = self.at(offset, 4)
        else
        {
            return u32::MAX;
        };
        // SAFETY: as `read8`; `at` also keeps the register 4-byte aligned.
        unsafe { core::ptr::read_volatile(addr as *const u32) }
    }

    fn write8(&self, offset: usize, value: u8)
    {
        let Some(addr) = self.at(offset, 1)
        else
        {
            return;
        };
        // SAFETY: as `read8`.
        unsafe { core::ptr::write_volatile(addr as *mut u8, value) };
        // The TPM must see the writes of a command in program order.
        mmio::mmio_to_mmio_barrier();
    }

    fn write32(&self, offset: usize, value: u32)
    {
        let Some(addr) = self.at(offset, 4)
        else
        {
            return;
        };
        // SAFETY: as `read32`.
        unsafe { core::ptr::write_volatile(addr as *mut u32, value) };
        mmio::mmio_to_mmio_barrier();
    }
}

/// The interface the TPM presents, over the window.
enum Device
{
    Fifo(Fifo<Window>),
    Crb(Crb<Window>),
}

impl Transport for Device
{
    fn execute(&mut self, cmd: &[u8], rsp: &mut [u8], wait: &mut dyn Wait) -> Result<usize, Fault>
    {
        match self
        {
            Self::Fifo(fifo) => fifo.execute(cmd, rsp, wait),
            Self::Crb(crb) => crb.execute(cmd, rsp, wait),
        }
    }
}

/// A command's bound: `limit` from when it was made, polled every
/// [`POLL_PAUSE`].
struct Deadline
{
    start: Instant,
    limit: Duration,
}

impl Deadline
{
    fn new(limit: Duration) -> Self
    {
        Self {
            start: Instant::now(),
            limit,
        }
    }
}

impl Wait for Deadline
{
    fn pause(&mut self) -> bool
    {
        if self.start.elapsed() >= self.limit
        {
            return false;
        }
        std::thread::sleep(POLL_PAUSE);
        true
    }
}

// ── Bootstrap ──────────────────────────────────────────────────────────────

/// Receive the resource list (`driver_binding::resources`): the TPM's
/// register window as an `Mmio` range, and the endpoints. Returns the range's
/// cap, its physical address, and its length, `None` unless the range is
/// page-aligned and spans from [`WINDOW_MIN`] to [`WINDOW_MAX`] bytes.
fn bootstrap(creator_endpoint: u64, ipc_buf: *mut u64)
-> Option<(u64, u64, u64, PlatformDelivery)>
{
    if creator_endpoint == 0
    {
        return None;
    }
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let list = unsafe { resources::receive(creator_endpoint, ipc_buf) }.ok()?;
    let device = PlatformDelivery::from_list(&list)?;
    let Resource::Mmio {
        cap, phys, bytes, ..
    } = device.registers
    else
    {
        return None;
    };
    let fits = phys.is_multiple_of(PAGE_SIZE) && (WINDOW_MIN..=WINDOW_MAX).contains(&bytes);
    fits.then_some((cap, phys, bytes, device))
}

/// Map the `bytes`-byte register window the `Mmio` cap `cap` covers. Exits
/// on any failure: the TPM cannot be reached without it.
fn map_window(self_aspace: u64, cap: u64, bytes: u64) -> Window
{
    let pages = bytes.div_ceil(PAGE_SIZE);
    // The mapping lives for the driver process's lifetime; the reservation is
    // intentionally never returned to the arena (the ReservedRange has no Drop
    // impl, so falling out of scope is a no-op).
    let Ok(range) = reserve_pages(pages)
    else
    {
        std::os::seraph::log!(error: "reserve_pages failed");
        syscall::thread_exit();
    };
    let va = range.va_start();
    // SAFETY: `range` is a fresh reservation of `pages` pages from the
    // per-process arena, owned for the process's lifetime, and `bootstrap`
    // admits only a page-aligned range of at most [`WINDOW_MAX`] bytes, whose
    // cap devmgr carves to the page end, so the whole-cap mapping stays inside
    // it: VA no Rust object or IPC page occupies. `Window` reaches the mapping
    // only through raw volatile accesses, never a reference (`mmio_map`
    // § Safety).
    if unsafe { std::os::seraph::mmio_map_funded(self_aspace, cap, va, pages) }.is_err()
    {
        std::os::seraph::log!(error: "mmio_map failed");
        syscall::thread_exit();
    }
    let Ok(len) = usize::try_from(bytes)
    else
    {
        syscall::thread_exit();
    };
    Window { va, len }
}

/// The interface the TPM behind `window`, at physical address `phys`,
/// presents. Exits when the driver speaks none of it.
fn open(window: Window, phys: u64) -> Device
{
    let id = window.read32(tpm::INTERFACE_ID);
    match tpm::interface(id)
    {
        Some(Interface::Fifo) =>
        {
            std::os::seraph::log!("FIFO interface (interface id {id:#x})");
            Device::Fifo(Fifo::new(window))
        }
        Some(Interface::Crb) =>
        {
            let Some(crb) = Crb::new(window, phys, window.len)
            else
            {
                std::os::seraph::log!(error: "CRB buffers lie outside the register window; not driven");
                syscall::thread_exit();
            };
            std::os::seraph::log!("CRB interface (interface id {id:#x})");
            Device::Crb(crb)
        }
        None =>
        {
            std::os::seraph::log!(error: "interface id {id:#x} names no interface this driver speaks");
            syscall::thread_exit();
        }
    }
}

// ── Service loop ───────────────────────────────────────────────────────────

/// Reply `label` with no data.
fn reply_status(label: u64, reply: &mut Reply)
{
    reply.set_status(label);
}

/// Reply `SUCCESS` carrying `bytes` ([`hwrng_protocol::encode_reply`]).
fn reply_bytes(bytes: &[u8], reply: &mut Reply)
{
    let mut words = [0u64; MSG_DATA_WORDS_MAX];
    let Some(used) = hwrng_protocol::encode_reply(bytes, &mut words)
    else
    {
        reply_status(hwrng_errors::NOT_READY, reply);
        return;
    };
    let msg = IpcMessage::builder(hwrng_errors::SUCCESS)
        .words(0, words.get(..used).unwrap_or_default())
        .build();
    reply.set(msg);
}

/// The read path's state across requests.
struct Reader
{
    session: Session<Device>,
    /// Whether a read has been answered with bytes, so the first one is
    /// logged.
    answered: bool,
    /// Whether the last read failed, so a run of failures logs once.
    failing: bool,
}

impl Reader
{
    /// Handle `READ` of `asked` bytes: `TPM2_GetRandom` until they are read
    /// or [`READ_WAIT`] passes, then reply with what arrived, or
    /// `NOT_READY` when nothing did.
    fn read(&mut self, asked: usize, reply: &mut Reply)
    {
        let mut bytes = [0u8; MAX_READ_BYTES];
        let Some(out) = bytes.get_mut(..asked)
        else
        {
            reply_status(hwrng_errors::NOT_READY, reply);
            return;
        };
        match self.session.get_random(out, &mut Deadline::new(READ_WAIT))
        {
            Ok(n) =>
            {
                if !self.answered && n > 0
                {
                    std::os::seraph::log!("first READ answered: {n} bytes from the TPM");
                    self.answered = true;
                }
                if self.failing
                {
                    std::os::seraph::log!("TPM reads again");
                    self.failing = false;
                }
                reply_bytes(out.get(..n).unwrap_or_default(), reply);
            }
            Err(fault) =>
            {
                if !self.failing
                {
                    std::os::seraph::log!(warn: "READ failed ({fault:?}); answering NOT_READY");
                    self.failing = true;
                }
                reply_status(hwrng_errors::NOT_READY, reply);
            }
        }
    }
}

/// `RecvGuard` diagnostic hook: one line at the start of a failure streak,
/// one more before the fatal exit.
fn recv_diag(stage: ipc::recv_guard::RecvFailureStage, err: i64)
{
    match stage
    {
        ipc::recv_guard::RecvFailureStage::First =>
        {
            std::os::seraph::log!(warn: "ipc_recv failing (err={err}); backing off");
        }
        ipc::recv_guard::RecvFailureStage::Fatal =>
        {
            std::os::seraph::log!(error: "ipc_recv wedged (err={err}); exiting");
        }
    }
}

fn service_loop(service_ep: u64, ipc_buf: *mut u64, reader: &mut Reader) -> !
{
    std::os::seraph::log!("ready, entering service loop");
    let mut guard = ipc::recv_guard::RecvGuard::new(recv_diag);
    let mut reply = Reply::new();
    loop
    {
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let msg = match unsafe { next_request(service_ep, &mut reply, ipc_buf) }
        {
            Ok(msg) => msg,
            Err(e) =>
            {
                guard.on_failure(e);
                continue;
            }
        };
        guard.on_success();

        // No label takes a cap: delete every cap the request carries, which
        // would otherwise take a slot of this driver's `CSpace` for good.
        for &cap in msg.caps()
        {
            let _ = syscall::cap_delete(cap);
        }
        if !tpm::authorized(msg.label, msg.badge)
        {
            reply_status(hwrng_errors::UNAUTHORIZED, &mut reply);
        }
        else if msg.label == hwrng_protocol::READ
        {
            reader.read(hwrng_protocol::requested_len(msg.words()), &mut reply);
        }
        else
        {
            reply_status(hwrng_errors::UNKNOWN_OPCODE, &mut reply);
        }
    }
}

// ── Entry point ────────────────────────────────────────────────────────────

fn main() -> !
{
    std::os::seraph::log::register_name(b"tpm");
    let info = startup_info();

    #[expect(
        clippy::cast_ptr_alignment,
        reason = "the IPC buffer page is 4 KiB-aligned, stricter than u64"
    )]
    let ipc_buf = info.ipc_buffer.cast::<u64>();

    let Some((cap, phys, bytes, device)) = bootstrap(info.creator_endpoint, ipc_buf)
    else
    {
        std::os::seraph::log!(error: "resource list missing or without a TPM register window");
        syscall::thread_exit();
    };
    let window = map_window(info.self_aspace, cap, bytes);
    let mut session = Session::new(open(window, phys));

    // The probe: a TPM that cannot produce bytes now ends the driver before
    // it reports ready, so devmgr serves no client a driver that would only
    // answer NOT_READY.
    let mut probe = [0u8; PROBE_BYTES];
    if let Err(fault) = session.get_random(&mut probe, &mut Deadline::new(PROBE_WAIT))
    {
        std::os::seraph::log!(error: "TPM probe failed ({fault:?}); not driven");
        syscall::thread_exit();
    }
    std::os::seraph::log!("TPM 2.0 answers TPM2_GetRandom");

    // SAFETY: ipc_buf is the registered IPC buffer page.
    if let Err(e) = unsafe { ipc::report_driver_ready(device.endpoints.devmgr_query, ipc_buf) }
    {
        std::os::seraph::log!(error: "DRIVER_READY failed ({e:?}); exiting");
        syscall::thread_exit();
    }
    let mut reader = Reader {
        session,
        answered: false,
        failing: false,
    };
    service_loop(device.endpoints.service, ipc_buf, &mut reader);
}
