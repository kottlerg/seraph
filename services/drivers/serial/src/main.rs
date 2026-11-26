// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/drivers/serial/src/main.rs

//! Seraph userspace serial (UART) device driver.
//!
//! Bound by devmgr to the UART's platform device record, it receives the
//! resource list (`driver_binding::resources`): the UART's register window
//! (an `IoPort` range on x86-64, an `Mmio` range on RISC-V), its wired line
//! when the record has one, a RECV cap on its service endpoint, and its
//! devmgr query cap. Once the UART is set up it reports ready
//! (`devmgr_labels::DRIVER_READY`) on the query cap: devmgr serves the
//! driver's endpoint only after that report, and the driver exits when
//! devmgr refuses it. Owns the UART end-to-end and is the sole
//! driver-mediated path for userspace serial bytes in both directions:
//! real-logd and every other writer reach it via
//! [`serial_labels::SERIAL_WRITE_BYTES`]; the terminal reads input via
//! [`serial_labels::SERIAL_READ_BYTES`], waking on the notification it
//! registers through [`serial_labels::SERIAL_REGISTER_RX_NOTIFY`].
//!
//! With the UART's line, the driver is interrupt-driven: the main thread is
//! the transmitter, the only thread that touches the UART, and
//! [`SERVICE_THREADS`] service threads serve the endpoint. A write is
//! copied into the transmit ring and answered; the transmit interrupt drains
//! the ring into the UART's FIFO. Received bytes are moved into the receive
//! ring on the receive interrupt, and a read takes them from there. So no
//! request waits on the UART except a write that asks to
//! ([`serial_labels::SERIAL_WRITE_SENT`]) or that finds the ring full, and
//! a read never waits behind a write. Without the line the driver is polled:
//! one thread serves the endpoint and writes and reads the UART itself
//! (`services/drivers/serial/README.md` § Transmit and receive).
//!
//! Unlike the sibling RTC drivers, this driver MUST NOT call
//! `std::os::seraph::log!`; the rule and its ground are in
//! `docs/console-model.md` § Logging constraint on the serial and framebuffer
//! drivers. Diagnostics are dropped; fatal bootstrap failures `thread_exit`
//! silently. The driver is debuggable: logd's serial writer is the only logd
//! thread that waits on it (`services/logd/docs/ipc-interface.md` § Output
//! sinks), and a stopped transmitter holds a write for [`TX_STALL_MS`] at
//! most.

mod arch;

use std::sync::atomic::{AtomicU64, Ordering, fence};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use arch::current::{Uart, serial_init};
use driver_binding::resources::{self, PlatformDelivery};
use ipc::{IpcMessage, serial_errors, serial_labels};
use serial::ring::{self, Consumer, Producer, RX_RING_BYTES, Ring, TX_RING_BYTES};
use serial::uart::{self, Cause};
use serial::wait::{StallWatch, TX_STALL_MS};
use std::os::seraph::startup_info;

// ── Declaration ────────────────────────────────────────────────────────────

// What devmgr binds this driver to and how it starts it
// (docs/driver-binding.md § Driver Declarations): the console UART the SPCR
// names, or an ACPI namespace device of `_HID` `PNP0501`.
driver_binding::driver_declaration!(driver_binding::decl::Declaration {
    name: "serial",
    class: Some("serial"),
    matches: &[
        driver_binding::decl::Match::Spcr(0x00),
        driver_binding::decl::Match::Spcr(0x12),
        driver_binding::decl::Match::AcpiHid("PNP0501")
    ],
    instance_limit: Some(1),
    interrupt: driver_binding::decl::Interrupt::OPTIONAL,
    dma: false,
    dma_width: None,
    phys_access: false,
    reset: driver_binding::decl::Reset::None,
    tier: driver_binding::decl::Tier::Auxiliary,
});

// ── Constants ──────────────────────────────────────────────────────────────

/// The most bytes one serial-protocol message carries either way:
/// `MSG_DATA_WORDS_MAX` words of 8 bytes. A read drains at most this many;
/// a caller drains more with further reads.
const MAX_MESSAGE_BYTES: usize = syscall_abi::MSG_DATA_WORDS_MAX * 8;

/// Service threads of the interrupt-driven driver. A write can wait on the
/// transmitter (a `SERIAL_WRITE_SENT` write, or one that finds the ring
/// full), so a thread is kept for each writer that does so in a running
/// system, logd's serial writer and the terminal's output, and one more, so
/// a read finds a thread free while both wait.
const SERVICE_THREADS: usize = 3;

/// The bit the kernel sets on the transmitter's notification when the UART's
/// line fires (`SYS_IRQ_REGISTER`).
const IRQ_BIT: u64 = 1;

/// The bit a service thread sets on the transmitter's notification to have
/// it look at the rings: bytes appended, a write waiting for the transmitter
/// to empty, or room freed in the receive ring.
const KICK_BIT: u64 = 1 << 1;

/// The longest the transmitter sleeps, in milliseconds, while bytes wait in
/// the transmit ring or a write waits for the transmitter to empty. It
/// reloads the FIFO if a transmit interrupt was lost, and looks again for
/// the transmitter-empty status, which raises no interrupt.
const TX_WATCHDOG_MS: u64 = 10;

/// How long the transmitter spins on LSR for the transmitter-empty status
/// once its FIFO is empty: the shift register's last character, one
/// character time (87 µs at 115200 baud, 1.04 ms at 9600), with margin.
/// Past it the transmitter looks again after [`TX_WATCHDOG_MS`].
const DRAIN_SPIN: Duration = Duration::from_millis(2);

/// IIR reads one service pass makes at most: a UART whose interrupt keeps
/// reasserting cannot hold the transmitter in one pass.
const IIR_READS: usize = 32;

/// The transmit ring: written by the service threads, drained by the
/// transmitter.
static TX_RING: Ring<TX_RING_BYTES> = Ring::new();

/// The receive ring: filled by the transmitter, read by the service threads.
static RX_RING: Ring<RX_RING_BYTES> = Ring::new();

// ── Bootstrap ──────────────────────────────────────────────────────────────

/// The UART's interrupt: its cap and the mode the record gives it.
#[derive(Clone, Copy)]
struct Irq
{
    cap: u64,
    mode: u64,
}

/// Receive the resource list (`driver_binding::resources`): the UART's
/// register window, an `IoPort` or `Mmio` range, its wired line if the
/// record has one, and the endpoints.
fn bootstrap(creator_endpoint: u64, ipc_buf: *mut u64) -> Option<PlatformDelivery>
{
    if creator_endpoint == 0
    {
        return None;
    }
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let list = unsafe { resources::receive(creator_endpoint, ipc_buf) }.ok()?;
    PlatformDelivery::from_list(&list)
}

/// Create a notification object.
fn create_notification() -> Option<u64>
{
    std::os::seraph::object_slab_retype(std::os::seraph::NOTIFICATION_RETYPE_BYTES, |slab| {
        syscall::cap_create_notification(slab).ok()
    })
}

// ── Requests ───────────────────────────────────────────────────────────────

/// A request, read from its message by [`parse`].
enum Request<'a>
{
    /// `SERIAL_WRITE_BYTES`: the bytes, and whether the reply waits until
    /// they have left the UART (`SERIAL_WRITE_SENT`).
    Write
    {
        bytes: &'a [u8], sent: bool
    },
    /// `SERIAL_READ_BYTES`.
    Read,
    /// `SERIAL_REGISTER_RX_NOTIFY` with the notification it carried, 0 when
    /// none.
    RegisterRxNotify(u64),
    /// A label the driver does not serve.
    Unknown,
    /// A served label the caller's badge lacks the verb bit for.
    Unauthorized,
}

/// Read `msg` as a request. Every cap it carries that the request does not
/// keep (all of them but the notification of an authorized RX-notify
/// registration, which [`Request::RegisterRxNotify`] hands on) is deleted
/// here, so no request leaves a slot of the driver's `CSpace` taken.
fn parse(msg: &IpcMessage) -> Request<'_>
{
    // Label encoding mirrors `stream_labels::STREAM_BYTES`: opcode in bits
    // 0-15, payload byte length in bits 16-31.
    let op = msg.label & 0xFFFF;
    // Verb-bit gate (docs/capability-model.md): writes need WRITE_AUTHORITY,
    // reads and RX-notify need READ_AUTHORITY. Unknown opcodes carry no gate
    // and fall through to UNKNOWN_OPCODE.
    let required_authority = match op
    {
        serial_labels::SERIAL_WRITE_BYTES => serial_labels::WRITE_AUTHORITY,
        serial_labels::SERIAL_READ_BYTES | serial_labels::SERIAL_REGISTER_RX_NOTIFY =>
        {
            serial_labels::READ_AUTHORITY
        }
        _ => 0,
    };
    let authorized = required_authority == 0 || msg.badge & required_authority != 0;
    // Only an authorized RX-notify request keeps a cap, its first one. No
    // client delivers a cap on an unauthorized request today: devmgr mints
    // its test-deny SENDs without GRANT, and every SEND it grants carries all
    // of this driver's verb bits. The `authorized` term keeps a future
    // partial-authority SEND from leaving its notification here.
    let kept = usize::from(authorized && op == serial_labels::SERIAL_REGISTER_RX_NOTIFY);
    for &cap in msg.caps().iter().skip(kept)
    {
        let _ = syscall::cap_delete(cap);
    }
    if !authorized
    {
        return Request::Unauthorized;
    }
    match op
    {
        serial_labels::SERIAL_WRITE_BYTES =>
        {
            // The mask bounds the length to 16 bits, so the conversion cannot
            // fail; 16 bits exceed the bytes one message's data words carry,
            // and the write stops at those bytes.
            let byte_len = usize::try_from((msg.label >> 16) & 0xFFFF).unwrap_or(0);
            let data = msg.data_bytes();
            Request::Write {
                bytes: data.get(..byte_len).unwrap_or(data),
                sent: msg.label & serial_labels::SERIAL_WRITE_SENT != 0,
            }
        }
        serial_labels::SERIAL_READ_BYTES => Request::Read,
        serial_labels::SERIAL_REGISTER_RX_NOTIFY =>
        {
            Request::RegisterRxNotify(msg.caps().first().copied().unwrap_or(0))
        }
        _ => Request::Unknown,
    }
}

/// The reply to a read that took `bytes`.
fn read_reply(bytes: &[u8]) -> IpcMessage
{
    // At most MAX_MESSAGE_BYTES, so the count fits the label's 16 bits.
    IpcMessage::builder(serial_errors::SUCCESS | ((bytes.len() as u64) << 16))
        .bytes(0, bytes)
        .build()
}

/// Whether `cap` is a notification the driver may signal: the check that
/// keeps a stray cap from standing as a client's RX notification.
fn signalable_notification(cap: u64) -> bool
{
    syscall::cap_info(cap, syscall_abi::CAP_INFO_TAG_RIGHTS).is_ok_and(|word| {
        (word >> 32) & 0xFF == u64::from(syscall_abi::CAP_TAG_NOTIFICATION)
            && word & syscall_abi::RIGHTS_NTF_NOTIFY != 0
    })
}

/// The transmit ring's progress count: the bytes it has handed to the UART
/// plus those known to have left it. A wait on the transmitter is bounded by
/// how long this stands still.
fn tx_progress() -> u64
{
    TX_RING.sent().wrapping_add(TX_RING.drained())
}

/// Milliseconds since `start`.
fn elapsed_ms(start: Instant) -> u64
{
    u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)
}

// ── Interrupt-driven: shared state ─────────────────────────────────────────

/// What the transmitter and the service threads share, for the driver's
/// life.
struct Shared
{
    /// The transmit ring's producer. A write holds it while it appends, and
    /// while it waits for room, so writes enter the ring whole and in the
    /// order they took it.
    tx: Mutex<Producer<'static, TX_RING_BYTES>>,
    /// The receive ring's consumer. A read holds it while it takes.
    rx: Mutex<Consumer<'static, RX_RING_BYTES>>,
    /// The transmitter's notification: the UART's line sets [`IRQ_BIT`], a
    /// service thread [`KICK_BIT`].
    transmitter: u64,
    /// Each service thread's notification while it waits on the
    /// transmitter, else 0; the transmitter signals each one set when it
    /// makes progress.
    waiting: [AtomicU64; SERVICE_THREADS],
    /// The highest transmit-ring mark a write waits to see leave the UART
    /// (`SERIAL_WRITE_SENT`): the transmitter looks for the
    /// transmitter-empty status only while this is ahead of the drained
    /// count.
    drain_wanted: AtomicU64,
    /// The client's RX notification, 0 until one is registered. Signalled
    /// under the lock, so a registration never deletes the cap between the
    /// read of the slot and the signal.
    rx_notify: Mutex<u64>,
}

// ── Interrupt-driven: the transmitter ──────────────────────────────────────

/// The main thread of the interrupt-driven driver: the only thread that
/// touches the UART. It loads the transmit FIFO from the transmit ring,
/// moves received bytes into the receive ring, and settles the drained count
/// when the UART's transmitter is empty.
struct Transmitter
{
    uart: Uart,
    shared: &'static Shared,
    tx: Consumer<'static, TX_RING_BYTES>,
    rx: Producer<'static, RX_RING_BYTES>,
    irq: Irq,
    /// Bytes one FIFO load writes ([`uart::transmit_load`]).
    load: usize,
    /// Whether the receive ring was full with bytes still in the UART: the
    /// receive interrupt is off until a read frees room.
    rx_paused: bool,
    /// The IER value last written; `None` before the first write.
    ier: Option<u8>,
}

impl Transmitter
{
    /// Serve the UART for the driver's life: service it, sleep until its
    /// line fires, a service thread kicks, or the watchdog runs out, and
    /// service it again. The line is acknowledged after the pass that
    /// follows its fire, and the next pass reads the UART again: the x86-64
    /// line is edge-triggered, so a source raised while the line was masked
    /// leaves it raised with no new edge.
    fn run(mut self) -> !
    {
        self.load = uart::transmit_load(self.uart.read(uart::IIR));
        self.set_interrupts();
        // irq_register leaves a first binding masked; the first ack arms it.
        let _ = syscall::irq_ack(self.irq.cap);
        // No diagnostic hook: a line logged here would be written back
        // through this driver (see the module doc).
        let mut guard = ipc::recv_guard::RecvGuard::new(|_, _| {});
        loop
        {
            self.service();
            let timeout = if self.tx_wanted() { TX_WATCHDOG_MS } else { 0 };
            match syscall::notification_wait_timeout(self.shared.transmitter, timeout)
            {
                Ok(bits) =>
                {
                    guard.on_success();
                    if bits & IRQ_BIT != 0
                    {
                        self.service();
                        let _ = syscall::irq_ack(self.irq.cap);
                    }
                }
                Err(e) => guard.on_failure(e),
            }
        }
    }

    /// One pass over the UART: clear each pending interrupt the IIR names,
    /// move received bytes into the receive ring, load the transmit FIFO or
    /// settle the drained count, set IER to match, and wake the service
    /// threads waiting on the transmitter if it moved.
    fn service(&mut self)
    {
        let before = tx_progress();
        if self.rx_paused && self.rx.room() > 0
        {
            self.rx_paused = false;
        }
        for _ in 0..IIR_READS
        {
            match uart::cause(self.uart.read(uart::IIR))
            {
                // An identification no 16550 defines has no source to clear.
                Cause::None | Cause::Other => break,
                Cause::LineStatus =>
                {
                    let _ = self.uart.read(uart::LSR);
                }
                Cause::ReceivedData | Cause::ReceiveTimeout => self.receive(),
                // The IIR read that named it cleared it.
                Cause::TransmitEmpty => self.transmit(),
                Cause::ModemStatus =>
                {
                    let _ = self.uart.read(uart::MSR);
                }
            }
        }
        // A kick, a lost interrupt, or a receive resumed with bytes already
        // waiting raises no IIR cause; look at LSR whatever the IIR said.
        self.receive();
        self.transmit();
        self.set_interrupts();
        if tx_progress() != before
        {
            self.wake_waiters();
        }
    }

    /// Move the bytes the UART holds into the receive ring, and signal the
    /// client's RX notification if any came. With the ring full and bytes
    /// still in the UART, turn the receive interrupt off until a read frees
    /// room: the UART's FIFO keeps the bytes meanwhile, and overruns, as it
    /// did before the ring, only once the client stops reading.
    fn receive(&mut self)
    {
        let mut received = false;
        while !self.rx_paused && self.uart.read(uart::LSR) & uart::LSR_DATA_READY != 0
        {
            if self.rx.room() == 0
            {
                self.rx_paused = true;
                self.set_interrupts();
                break;
            }
            let byte = self.uart.read(uart::DATA);
            let _ = self.rx.push(&[byte]);
            received = true;
        }
        if received
        {
            let client = self
                .shared
                .rx_notify
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if *client != 0
            {
                let _ = syscall::notification_send(*client, 1);
            }
        }
    }

    /// Load the transmit FIFO from the ring when LSR reports it empty. Once
    /// every byte up to a waiting write's mark is loaded
    /// ([`ring::hold_for_drain`]), load nothing more: wait the shift
    /// register's last character out ([`DRAIN_SPIN`]), settle the drained
    /// count once the transmitter is empty, and load again. A transmitter not
    /// empty within the spin is looked at again at the next wake.
    fn transmit(&mut self)
    {
        let mut lsr = self.uart.read(uart::LSR);
        if lsr & uart::LSR_THR_EMPTY == 0
        {
            return;
        }
        let wanted = self.shared.drain_wanted.load(Ordering::Acquire);
        if !ring::hold_for_drain(TX_RING.sent(), TX_RING.drained(), wanted)
        {
            self.load_fifo();
            return;
        }
        let start = Instant::now();
        while lsr & uart::LSR_TX_EMPTY == 0
        {
            if start.elapsed() >= DRAIN_SPIN
            {
                return;
            }
            core::hint::spin_loop();
            lsr = self.uart.read(uart::LSR);
        }
        // Nothing was loaded since the hold began, so every byte taken is
        // off the transmitter. The FIFO is empty too: load the bytes behind
        // the mark now, not at the next wake.
        self.tx.settle();
        self.load_fifo();
    }

    /// Write up to one FIFO load ([`uart::transmit_load`]) from the ring to
    /// THR, which the caller saw empty.
    fn load_fifo(&mut self)
    {
        let uart = self.uart;
        self.tx.take(self.load, |byte| uart.write(uart::DATA, byte));
    }

    /// Whether a write waits for bytes to leave the UART that have not been
    /// seen to.
    fn draining(&self) -> bool
    {
        self.shared.drain_wanted.load(Ordering::Acquire) > TX_RING.drained()
    }

    /// Whether the transmitter has work the UART's transmit side will end:
    /// bytes to load, or a write waiting for the transmitter to empty.
    fn tx_wanted(&self) -> bool
    {
        !self.tx.is_empty() || self.draining()
    }

    /// Write IER for the current state ([`uart::interrupt_enable`]) when it
    /// differs from the value last written. Enabling the transmit interrupt
    /// while THR is empty raises it at once, which starts the next load.
    fn set_interrupts(&mut self)
    {
        let ier = uart::interrupt_enable(self.rx_paused, self.tx_wanted());
        if self.ier != Some(ier)
        {
            self.uart.write(uart::IER, ier);
            self.ier = Some(ier);
        }
    }

    /// Signal every service thread waiting on the transmitter. The fence
    /// pairs with the one in [`Server::wait_for`]: a thread that published
    /// its notification after this pass read its slot sees the progress
    /// before it sleeps.
    fn wake_waiters(&self)
    {
        fence(Ordering::SeqCst);
        for slot in &self.shared.waiting
        {
            let notification = slot.load(Ordering::SeqCst);
            if notification != 0
            {
                let _ = syscall::notification_send(notification, 1);
            }
        }
    }
}

// ── Interrupt-driven: the service threads ──────────────────────────────────

/// One service thread of the interrupt-driven driver.
struct Server
{
    shared: &'static Shared,
    /// This thread's slot of [`Shared::waiting`].
    slot: &'static AtomicU64,
    /// This thread's notification, which the transmitter signals through
    /// [`Self::slot`].
    wake: u64,
}

impl Server
{
    /// Serve the endpoint for the driver's life.
    fn run(&self, service_ep: u64) -> !
    {
        let ipc_buf = std::os::seraph::current_ipc_buf();
        // No diagnostic hook: a line logged here would be written back
        // through this driver (see the module doc). The kernel's rate-limited
        // recv-failure line and the guard's exit remain the signal.
        let mut guard = ipc::recv_guard::RecvGuard::new(|_, _| {});
        loop
        {
            // SAFETY: ipc_buf is this thread's registered IPC buffer page.
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
            let reply = match parse(&msg)
            {
                Request::Write { bytes, sent } => IpcMessage::new(self.write(bytes, sent)),
                Request::Read => self.read(),
                Request::RegisterRxNotify(notification) => self.register_rx_notify(notification),
                Request::Unknown => IpcMessage::new(serial_errors::UNKNOWN_OPCODE),
                Request::Unauthorized => IpcMessage::new(serial_errors::UNAUTHORIZED),
            };
            // SAFETY: ipc_buf is this thread's registered IPC buffer page.
            let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
        }
    }

    /// Append `bytes` to the transmit ring, waiting for room, and kick the
    /// transmitter. With `sent`, wait further until the bytes have left
    /// the UART. `STALLED` when a wait sees the transmitter make no progress
    /// for [`TX_STALL_MS`]: the bytes were not appended (the ring stayed
    /// full), or, with `sent`, they are queued and not yet seen to leave.
    #[expect(
        clippy::fn_params_excessive_bools,
        reason = "`sent` is the request's SERIAL_WRITE_SENT bit, data the caller sent"
    )]
    #[expect(
        clippy::significant_drop_tightening,
        reason = "the producer guard is held over the wait for room, so writes enter the ring \
                  in the order they took it"
    )]
    fn write(&self, bytes: &[u8], sent: bool) -> u64
    {
        let mark = {
            let mut tx = self
                .shared
                .tx
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            loop
            {
                if let Some(mark) = tx.push(bytes)
                {
                    break mark;
                }
                self.kick();
                if !self.wait_for(|| tx.room() >= bytes.len())
                {
                    return serial_errors::STALLED;
                }
            }
        };
        if !bytes.is_empty()
        {
            self.kick();
        }
        if !sent
        {
            return serial_errors::SUCCESS;
        }
        self.shared.drain_wanted.fetch_max(mark, Ordering::AcqRel);
        self.kick();
        if self.wait_for(|| TX_RING.drained() >= mark)
        {
            serial_errors::SUCCESS
        }
        else
        {
            serial_errors::STALLED
        }
    }

    /// Take what the receive ring holds, up to one reply, and kick the
    /// transmitter: a receive paused on a full ring resumes, and the
    /// transmitter reads the UART, so a receive interrupt the line lost is
    /// recovered by the client's next read.
    fn read(&self) -> IpcMessage
    {
        let mut buf = [0u8; MAX_MESSAGE_BYTES];
        let n = {
            let mut slots = buf.iter_mut();
            self.shared
                .rx
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take(MAX_MESSAGE_BYTES, |byte| {
                    if let Some(slot) = slots.next()
                    {
                        *slot = byte;
                    }
                })
        };
        self.kick();
        read_reply(buf.get(..n).unwrap_or_default())
    }

    /// Keep `notification` as the client's RX notification, which the
    /// transmitter signals when bytes arrive, replacing (and deleting) the
    /// one kept before. Refused, and `notification` deleted, when it is not
    /// a notification the driver may signal; the one kept before stays.
    #[expect(
        clippy::significant_drop_tightening,
        reason = "the `rx_notify` guard is held over the delete of the replaced cap, so the \
                  transmitter never signals a slot that is deleted or reused"
    )]
    fn register_rx_notify(&self, notification: u64) -> IpcMessage
    {
        if notification == 0 || !signalable_notification(notification)
        {
            if notification != 0
            {
                let _ = syscall::cap_delete(notification);
            }
            return IpcMessage::new(serial_errors::REGISTER_FAILED);
        }
        let mut client = self
            .shared
            .rx_notify
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let old = core::mem::replace(&mut *client, notification);
        if old != 0
        {
            let _ = syscall::cap_delete(old);
        }
        IpcMessage::new(serial_errors::SUCCESS)
    }

    /// Have the transmitter look at the rings.
    fn kick(&self)
    {
        let _ = syscall::notification_send(self.shared.transmitter, KICK_BIT);
    }

    /// Wait until `done` holds: `true` then, `false` once the transmitter
    /// has made no progress for [`TX_STALL_MS`] ([`StallWatch`]). The
    /// thread publishes its notification in its slot before it looks at
    /// `done` the last time, so progress made after that look signals it
    /// (the fence pairs with [`Transmitter::wake_waiters`]'s).
    fn wait_for(&self, done: impl Fn() -> bool) -> bool
    {
        let start = Instant::now();
        let mut watch = StallWatch::new(TX_STALL_MS, tx_progress(), 0);
        loop
        {
            if done()
            {
                return true;
            }
            self.slot.store(self.wake, Ordering::SeqCst);
            fence(Ordering::SeqCst);
            let outcome = if done()
            {
                Some(true)
            }
            else if let Some(left) = watch.remaining(tx_progress(), elapsed_ms(start))
            {
                // `left` is non-zero, so the wait is bounded.
                let _ = syscall::notification_wait_timeout(self.wake, left);
                None
            }
            else
            {
                Some(false)
            };
            self.slot.store(0, Ordering::SeqCst);
            if let Some(outcome) = outcome
            {
                return outcome;
            }
        }
    }
}

/// Set up the interrupt-driven driver: split the rings, bind the UART's line
/// to the transmitter's notification, and start the service threads on
/// `service_ep`. `None` when any of it fails before a service thread
/// runs; the driver is then polled, and the line, bound but never
/// acknowledged, stays masked.
fn start_interrupt_driven(uart: Uart, irq: Irq, service_ep: u64) -> Option<Transmitter>
{
    let (tx_producer, tx_consumer) = TX_RING.split()?;
    let (rx_producer, rx_consumer) = RX_RING.split()?;
    let transmitter = create_notification()?;
    if syscall::irq_register(irq.cap, transmitter, irq.mode).is_err()
    {
        let _ = syscall::cap_delete(transmitter);
        return None;
    }
    let shared: &'static Shared = Box::leak(Box::new(Shared {
        tx: Mutex::new(tx_producer),
        rx: Mutex::new(rx_consumer),
        transmitter,
        waiting: [const { AtomicU64::new(0) }; SERVICE_THREADS],
        drain_wanted: AtomicU64::new(0),
        rx_notify: Mutex::new(0),
    }));
    let mut started = 0usize;
    for slot in &shared.waiting
    {
        let Some(wake) = create_notification()
        else
        {
            break;
        };
        let server = Server { shared, slot, wake };
        if std::thread::Builder::new()
            .spawn(move || {
                server.run(service_ep);
            })
            .is_err()
        {
            let _ = syscall::cap_delete(wake);
            break;
        }
        started = started.saturating_add(1);
    }
    (started > 0).then_some(Transmitter {
        uart,
        shared,
        tx: tx_consumer,
        rx: rx_producer,
        irq,
        load: 1,
        rx_paused: false,
        ier: None,
    })
}

// ── Polled ─────────────────────────────────────────────────────────────────

/// Spin until LSR shows `bit`; `false` once it has not for [`TX_STALL_MS`].
fn poll_lsr(uart: Uart, bit: u8) -> bool
{
    let start = Instant::now();
    while uart.read(uart::LSR) & bit == 0
    {
        if elapsed_ms(start) >= TX_STALL_MS
        {
            return false;
        }
        core::hint::spin_loop();
    }
    true
}

/// Write `bytes` to the UART one at a time, each once THR is empty; with
/// `sent`, then wait for the transmitter to empty. `STALLED` when the UART
/// takes no byte, or does not empty, for [`TX_STALL_MS`]; the bytes after
/// the stall are not written.
#[expect(
    clippy::fn_params_excessive_bools,
    reason = "`sent` is the request's SERIAL_WRITE_SENT bit, data the caller sent"
)]
fn poll_write(uart: Uart, bytes: &[u8], sent: bool) -> u64
{
    for &byte in bytes
    {
        if !poll_lsr(uart, uart::LSR_THR_EMPTY)
        {
            return serial_errors::STALLED;
        }
        uart.write(uart::DATA, byte);
    }
    if sent && !poll_lsr(uart, uart::LSR_TX_EMPTY)
    {
        return serial_errors::STALLED;
    }
    serial_errors::SUCCESS
}

/// The polled driver's one thread: serve the endpoint, writing and reading
/// the UART itself. A read drains what the UART's receive FIFO holds; with no
/// interrupt to signal a client, an RX-notify registration is refused, and a
/// client polls on a timeout.
fn polled_loop(uart: Uart, service_ep: u64, ipc_buf: *mut u64) -> !
{
    // No diagnostic hook: a line logged here would be written back through
    // this loop (see the module doc). The kernel's rate-limited recv-failure
    // line and the guard's exit remain the signal.
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
        let reply = match parse(&msg)
        {
            Request::Write { bytes, sent } => IpcMessage::new(poll_write(uart, bytes, sent)),
            Request::Read =>
            {
                let mut buf = [0u8; MAX_MESSAGE_BYTES];
                // Fill `buf` from the front until the UART holds no byte or
                // `buf` is full.
                let n = buf
                    .iter_mut()
                    .map_while(|slot| {
                        (uart.read(uart::LSR) & uart::LSR_DATA_READY != 0).then(|| {
                            *slot = uart.read(uart::DATA);
                        })
                    })
                    .count();
                read_reply(buf.get(..n).unwrap_or_default())
            }
            Request::RegisterRxNotify(notification) =>
            {
                if notification != 0
                {
                    let _ = syscall::cap_delete(notification);
                }
                IpcMessage::new(serial_errors::REGISTER_FAILED)
            }
            Request::Unknown => IpcMessage::new(serial_errors::UNKNOWN_OPCODE),
            Request::Unauthorized => IpcMessage::new(serial_errors::UNAUTHORIZED),
        };
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
    }
}

// ── Entry ──────────────────────────────────────────────────────────────────

fn main() -> !
{
    let info = startup_info();

    #[expect(
        clippy::cast_ptr_alignment,
        reason = "the IPC buffer page is 4 KiB-aligned"
    )]
    let ipc_buf = info.ipc_buffer.cast::<u64>();

    let Some(device) = bootstrap(info.creator_endpoint, ipc_buf)
    else
    {
        syscall::thread_exit();
    };
    let service_ep = device.endpoints.service;

    // SAFETY: `info.self_aspace` is this process's address space, and
    // `device.registers` is the register window devmgr delivered, whose cap
    // the call maps (riscv64) or binds to this thread (x86-64) only after
    // checking its kind and size.
    let Some(uart) =
        (unsafe { serial_init(info.self_thread, info.self_aspace, &device.registers) })
    else
    {
        syscall::thread_exit();
    };
    // The interrupt is optional at bind: without the line, or when the
    // interrupt-driven set-up fails, the driver is polled.
    let transmitter = device
        .wired
        .and_then(|(cap, mode)| start_interrupt_driven(uart, Irq { cap, mode }, service_ep));

    // SAFETY: ipc_buf is the registered IPC buffer page.
    if unsafe { ipc::report_driver_ready(device.endpoints.devmgr_query, ipc_buf) }.is_err()
    {
        syscall::thread_exit();
    }
    match transmitter
    {
        Some(transmitter) => transmitter.run(),
        None => polled_loop(uart, service_ep, ipc_buf),
    }
}
