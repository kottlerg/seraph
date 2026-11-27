// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/ipc/src/serve.rs

//! A server loop's reply, sent with the receive of its next request.
//!
//! A handler that ends its turn with a reply leaves the reply in the loop's
//! [`Reply`] ([`Reply::set`]), and the loop's [`next_request`] sends it with
//! the next receive in one `SYS_IPC_REPLY_RECV`, so the kernel places the
//! caller's wake knowing whether this thread blocks or runs on
//! (`docs/ipc-design.md` § The Call/Reply Model). A handler with work after
//! its reply, or one that must answer before something it does next, and a
//! loop with work before its next receive, send the slot's reply first
//! ([`Reply::flush`]), with a receive that does not wait, and the call that
//! receive binds is the one the next [`next_request`] returns; a thread
//! about to exit sends its last reply alone ([`Reply::send_last`]). With the slot
//! empty, [`next_request`] is [`crate::ipc_recv`]. A loop whose receive
//! waits a bounded time uses [`next_request_timeout`], and one that undoes a
//! request's effect when its reply does not reach the caller reads
//! [`Reply::undelivered`] after the send.

// When this crate is compiled as a std dep via rustc-dep-of-std, the
// crate root is `no_core` and the usual prelude is not auto-imported.
// The crate-root `use core::prelude::rust_2024::*;` only covers the
// root module; submodules need their own import. Harmless no-op
// otherwise.
#[cfg(feature = "rustc-dep-of-std")]
use core::prelude::rust_2024::*;

use syscall_abi::SyscallError;

use crate::IpcMessage;

/// The reply a server thread's handler leaves for the loop's next receive.
///
/// One per receiving thread, owned by its loop. It holds at most one reply,
/// to the caller the thread's last receive bound, or, after a
/// [`Reply::flush`] whose receive bound a call, that call, for the next
/// receive to return.
pub struct Reply
{
    /// The reply, valid while [`Slot::Pending`] and only up to its counts. It
    /// stays in place from its set to its send, so no turn copies the message.
    /// While [`Slot::Held`] or [`Slot::HeldLost`], the call a flush's receive
    /// bound, read here once the reply it replaced was sent.
    msg: IpcMessage,
    state: Slot,
    /// Delete the reply's caps from this thread's `CSpace` when the reply is
    /// not delivered ([`Self::set_or_delete_caps`]).
    delete_caps: bool,
}

/// What a [`Reply`] holds. One field carries both whether a reply waits and
/// how the last one sent went, so a send clears the one with a single store.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Slot
{
    /// No reply is set, and the last one sent, if any, was delivered.
    Empty,
    /// A reply is set and not yet sent.
    Pending,
    /// No reply is set, and the last one sent was not delivered.
    Lost,
    /// A flush's receive bound a call, held in the slot for the next receive
    /// to return; the reply that flush sent was delivered.
    Held,
    /// As [`Self::Held`], and the reply that flush sent was not delivered.
    HeldLost,
}

impl Slot
{
    /// The outcome a held call leaves once it is returned: the state of the
    /// slot with the call taken out, or `None` when the slot holds none.
    #[inline]
    const fn unheld(self) -> Option<Self>
    {
        match self
        {
            Self::Held => Some(Self::Empty),
            Self::HeldLost => Some(Self::Lost),
            Self::Empty | Self::Pending | Self::Lost => None,
        }
    }
}

/// What a receive of the loop returns: a call the kernel delivered, or the
/// call a flush's receive bound, held in the slot.
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
enum Next<G>
{
    Received(G),
    Held,
}

impl Reply
{
    /// An empty slot.
    #[must_use]
    pub const fn new() -> Self
    {
        Self {
            msg: IpcMessage::new(0),
            state: Slot::Empty,
            delete_caps: false,
        }
    }

    /// Whether the last reply sent from the slot, by [`next_request_timeout`],
    /// [`next_request`] or [`Self::flush`], did not reach the caller: the
    /// caller is gone, or its `CSpace` could not take the reply's caps, and the
    /// kernel woke it with a transfer failure instead. It holds until the next
    /// reply is sent; a call with no reply to send leaves it, and so does the
    /// return of a call a flush held. A server that
    /// undoes a request's effect when its caller never learns of it reads this
    /// after the call that sent that request's reply.
    #[must_use]
    pub const fn undelivered(&self) -> bool
    {
        matches!(self.state, Slot::Lost | Slot::HeldLost)
    }

    /// Whether the slot holds a call a flush's receive bound, which the next
    /// receive returns.
    const fn holds_call(&self) -> bool
    {
        matches!(self.state, Slot::Held | Slot::HeldLost)
    }

    /// Whether a reply is set and not yet sent.
    #[must_use]
    pub const fn is_set(&self) -> bool
    {
        matches!(self.state, Slot::Pending)
    }

    /// Leave `msg` as the reply to this thread's pending caller, for the
    /// loop's next [`next_request`] (or [`Self::flush`]) to send. A turn
    /// sets at most one reply.
    pub fn set(&mut self, msg: IpcMessage)
    {
        debug_assert!(!self.is_set(), "a turn sets at most one reply");
        debug_assert!(
            !self.holds_call(),
            "a held call is returned before a reply is set"
        );
        self.store(&msg);
        self.state = Slot::Pending;
        self.delete_caps = false;
    }

    /// [`Self::set`] of a reply that carries the label `status` alone, the
    /// form of most refusals and acknowledgements. The message is built here,
    /// so a handler with many such replies holds none of them in its frame.
    pub fn set_status(&mut self, status: u64)
    {
        debug_assert!(!self.is_set(), "a turn sets at most one reply");
        debug_assert!(
            !self.holds_call(),
            "a held call is returned before a reply is set"
        );
        self.msg.label = status;
        self.msg.data_len = 0;
        self.msg.cap_count = 0;
        self.state = Slot::Pending;
        self.delete_caps = false;
    }

    /// [`Self::set`], for a reply that moves caps this thread keeps no use
    /// for: when the reply is not delivered (the caller is gone, or its
    /// `CSpace` cannot take the caps), they stay in this thread's `CSpace`,
    /// and the send deletes them there.
    pub fn set_or_delete_caps(&mut self, msg: IpcMessage)
    {
        debug_assert!(!self.is_set(), "a turn sets at most one reply");
        debug_assert!(
            !self.holds_call(),
            "a held call is returned before a reply is set"
        );
        self.store(&msg);
        self.state = Slot::Pending;
        self.delete_caps = true;
    }

    /// Copy into the slot what a send of `msg` reads: its label, its counts,
    /// and its data words and cap slots within them. The words past the count
    /// are neither copied nor cleared, since no send reads them; a whole copy,
    /// or the zeroing of the words a built message does not write, costs more
    /// than the receive the reply rides saves.
    #[inline]
    fn store(&mut self, msg: &IpcMessage)
    {
        let words = usize::from(msg.data_len);
        let caps = usize::from(msg.cap_count);
        self.msg.label = msg.label;
        self.msg.data_len = msg.data_len;
        self.msg.cap_count = msg.cap_count;
        if let (Some(to), Some(from)) = (self.msg.data.get_mut(..words), msg.data.get(..words))
        {
            to.copy_from_slice(from);
        }
        if let (Some(to), Some(from)) = (
            self.msg.cap_slots.get_mut(..caps),
            msg.cap_slots.get(..caps),
        )
        {
            to.copy_from_slice(from);
        }
    }

    /// Send the reply now, when one is set, for a loop with work before its
    /// next receive, which the reply would otherwise wait behind: with a
    /// receive that does not wait (`SYS_IPC_REPLY_RECV` on `ep` at
    /// `syscall::WAIT_TRY_ONCE`). A server that outranks its caller and last
    /// received through `SYS_IPC_REPLY_RECV` may run on the caller's CPU, where
    /// a plain `SYS_IPC_REPLY` would leave the caller's wake queued behind the
    /// server until it parks, while the wake of a `SYS_IPC_REPLY_RECV` whose
    /// receive does not park goes to another CPU
    /// (`core/kernel/docs/scheduler.md` § Thread Assignment). A call that
    /// receive binds is held in the slot, and the next [`next_request`] or
    /// [`next_request_timeout`] returns it with no syscall, so it is served
    /// once the loop's work is done, as it would have been from the
    /// endpoint's queue. A receive that finds no call, or fails, holds none,
    /// and leaves the next receive to report a failure that lasts. The send's
    /// fallbacks are those of [`next_request_timeout`], and its outcome is
    /// [`Self::undelivered`]'s; the caps of an undelivered reply set with
    /// [`Self::set_or_delete_caps`] are deleted.
    ///
    /// # Safety
    /// `ipc_buf` must point to the calling thread's 4 KiB-aligned IPC buffer
    /// page as registered via `syscall::ipc_buffer_set`.
    pub unsafe fn flush(&mut self, ep: u64, ipc_buf: *mut u64)
    {
        self.flush_with(
            &mut Kernel {
                ipc_buf,
                wait: syscall::WAIT_TRY_ONCE,
            },
            ep,
        );
    }

    /// Send the reply now, alone (`SYS_IPC_REPLY`), when one is set, for a
    /// thread that receives no more requests: one about to exit. A plain reply
    /// waits behind nothing there, since the thread parks for good, and a
    /// receive would bind a call the exit then fails with `Interrupted` and
    /// its caps lost, where the endpoint's queue would have kept it. Any other
    /// send before work is [`Self::flush`]. The outcome is
    /// [`Self::undelivered`]'s; the caps of an undelivered reply set with
    /// [`Self::set_or_delete_caps`] are deleted.
    ///
    /// # Safety
    /// `ipc_buf` must point to the calling thread's 4 KiB-aligned IPC buffer
    /// page as registered via `syscall::ipc_buffer_set`.
    pub unsafe fn send_last(&mut self, ipc_buf: *mut u64)
    {
        self.send_last_with(&mut Kernel {
            ipc_buf,
            wait: Unbounded,
        });
    }

    fn send_last_with<T: Transport>(&mut self, kernel: &mut T)
    {
        if self.state != Slot::Pending
        {
            return;
        }
        self.state = Slot::Empty;
        if kernel.reply(&self.msg).is_err()
        {
            self.lose(kernel);
        }
    }

    fn flush_with<T: Transport>(&mut self, kernel: &mut T, ep: u64)
    {
        if self.state != Slot::Pending
        {
            return;
        }
        if let Ok(Next::Received(got)) = next_with(kernel, ep, self)
        {
            // The reply was sent from `msg`, so the call is read there.
            kernel.read(&got, &mut self.msg);
            self.state = if self.state == Slot::Lost
            {
                Slot::HeldLost
            }
            else
            {
                Slot::Held
            };
        }
    }

    /// The reply last set, now sent, was not delivered: record it for
    /// [`Self::undelivered`], and delete its caps when it was set to.
    fn lose<T: Transport>(&mut self, kernel: &mut T)
    {
        self.state = Slot::Lost;
        if self.delete_caps
        {
            for &cap in self.msg.caps()
            {
                kernel.delete_cap(cap);
            }
        }
    }
}

impl Default for Reply
{
    fn default() -> Self
    {
        Self::new()
    }
}

/// Receive the next request on `ep`, waiting without bound, after sending
/// `reply`'s reply when one is set, and empty the slot: the turn of
/// [`next_request_timeout`] with a `timeout_ms` of `0`, which returns the
/// request, or the call a [`Reply::flush`] held, with no syscall.
///
/// # Safety
/// As [`next_request_timeout`].
///
/// # Errors
/// As [`next_request_timeout`], which a wait without bound never ends with
/// `WouldBlock`.
#[inline]
pub unsafe fn next_request(ep: u64, reply: &mut Reply, ipc_buf: *mut u64)
-> Result<IpcMessage, i64>
{
    match next_with(
        &mut Kernel {
            ipc_buf,
            wait: Unbounded,
        },
        ep,
        reply,
    )?
    {
        // The message is read once, here, whichever syscall received it, so
        // no path moves it again.
        // SAFETY: ipc_buf is the registered IPC buffer page (this fn's
        // contract); the kernel wrote the delivered words and cap handles there
        // before return.
        Next::Received(delivery) => Ok(unsafe { IpcMessage::from_delivery(ipc_buf, &delivery) }),
        Next::Held => Ok(reply.msg),
    }
}

/// Receive the next request on `ep` under `SYS_IPC_RECV`'s `timeout_ms`
/// policy (`0` waits without bound, any other value but
/// `syscall::WAIT_TRY_ONCE` up to that many milliseconds), after sending
/// `reply`'s reply when one is set, and empty the slot. The request is read
/// into `req` in place ([`IpcMessage::read_delivery`]), so a loop that
/// receives into one buffer copies no whole message; on an error `req` is
/// left as it was. A call a [`Reply::flush`] held is copied into `req` with
/// no syscall instead.
///
/// With a reply set this is one [`crate::ipc_reply_recv`]. Its errors come
/// from three parts, before the reply, of the reply, and after it, and the
/// first two share codes, so on one of those the reply is sent again alone:
/// when the receive was refused before the reply, that sends it and the
/// refusal is returned for the loop's `RecvGuard`; when the reply itself
/// failed, it consumed the binding, the second send fails with nothing to
/// wake, and the receive is made alone. No reply is lost or sent twice, and a
/// reply's failure, which the caller's capabilities or `CSpace` cause, is
/// never returned as a receive failure: [`Reply::undelivered`] reports it.
/// The caps of an undelivered reply set with [`Reply::set_or_delete_caps`]
/// are deleted.
///
/// # Safety
/// `ipc_buf` must point to the calling thread's 4 KiB-aligned IPC buffer
/// page as registered via `syscall::ipc_buffer_set`.
///
/// # Errors
/// [`crate::ipc_recv_timeout`]'s: those of the receive's capability check and
/// cap-slot pre-allocation (`InvalidCapability`, `InsufficientRights`,
/// `QuotaExceeded`, `OutOfMemory`), after which the reply has been made
/// all the same, `NoReceiver` and `Interrupted` from the wait, and
/// `WouldBlock` when a bounded wait expires with no request.
#[inline]
pub unsafe fn next_request_timeout(
    ep: u64,
    reply: &mut Reply,
    ipc_buf: *mut u64,
    timeout_ms: u64,
    req: &mut IpcMessage,
) -> Result<(), i64>
{
    let mut kernel = Kernel {
        ipc_buf,
        wait: timeout_ms,
    };
    match next_with(&mut kernel, ep, reply)?
    {
        Next::Received(delivery) => kernel.read(&delivery, req),
        Next::Held => *req = reply.msg,
    }
    Ok(())
}

/// The syscalls of a turn of [`next_request_timeout`], behind a trait so that
/// its order and fallbacks are host-tested.
trait Transport
{
    /// What a receive returns: the kernel's delivery, from which the message
    /// is read.
    type Got;
    /// The `timeout_ms` every receive carries.
    fn timeout_ms(&self) -> u64;
    fn recv(&mut self, ep: u64, timeout_ms: u64) -> Result<Self::Got, i64>;
    fn reply(&mut self, msg: &IpcMessage) -> Result<(), i64>;
    fn reply_recv(&mut self, ep: u64, msg: &IpcMessage, timeout_ms: u64) -> Result<Self::Got, i64>;
    fn delete_cap(&mut self, cap: u64);
    /// Read the call `got` delivered into `msg`.
    fn read(&mut self, got: &Self::Got, msg: &mut IpcMessage);
}

/// The kernel, through the calling thread's registered IPC buffer page, with
/// the receives' bound `wait`.
struct Kernel<W>
{
    /// The calling thread's registered IPC buffer page
    /// ([`next_request_timeout`]'s contract).
    ipc_buf: *mut u64,
    wait: W,
}

/// A receive's bound under `SYS_IPC_RECV`'s `timeout_ms` policy: a `u64` of
/// milliseconds, or [`Unbounded`], which fixes it at `0` when the turn is
/// compiled, so a loop that always waits without bound passes none at run
/// time.
trait Wait: Copy
{
    fn ms(self) -> u64;
}

/// No bound: every receive waits until a request arrives.
#[derive(Clone, Copy)]
struct Unbounded;

impl Wait for Unbounded
{
    #[inline]
    fn ms(self) -> u64
    {
        0
    }
}

impl Wait for u64
{
    #[inline]
    fn ms(self) -> u64
    {
        self
    }
}

impl<W: Wait> Transport for Kernel<W>
{
    type Got = syscall::IpcDelivery;

    #[inline]
    fn timeout_ms(&self) -> u64
    {
        self.wait.ms()
    }

    #[inline]
    fn recv(&mut self, ep: u64, timeout_ms: u64) -> Result<syscall::IpcDelivery, i64>
    {
        syscall::raw_ipc_recv_timeout(ep, timeout_ms)
    }

    #[inline]
    fn reply(&mut self, msg: &IpcMessage) -> Result<(), i64>
    {
        // SAFETY: ipc_buf is the registered IPC buffer page
        // (next_request_timeout's contract).
        unsafe { crate::ipc_reply(msg, self.ipc_buf) }
    }

    #[inline]
    fn reply_recv(
        &mut self,
        ep: u64,
        msg: &IpcMessage,
        timeout_ms: u64,
    ) -> Result<syscall::IpcDelivery, i64>
    {
        // SAFETY: as in reply.
        unsafe { crate::reply_recv_delivery(ep, msg, self.ipc_buf, timeout_ms) }
    }

    fn delete_cap(&mut self, cap: u64)
    {
        let _ = syscall::cap_delete(cap);
    }

    #[inline]
    fn read(&mut self, got: &syscall::IpcDelivery, msg: &mut IpcMessage)
    {
        // SAFETY: ipc_buf is the registered IPC buffer page
        // (next_request_timeout's contract); the kernel wrote the delivered
        // words and cap handles there before the receive returned, and no
        // syscall has run on this thread since.
        unsafe { msg.read_delivery(self.ipc_buf, got) };
    }
}

#[inline]
fn next_with<T: Transport>(kernel: &mut T, ep: u64, reply: &mut Reply)
-> Result<Next<T::Got>, i64>
{
    let timeout_ms = kernel.timeout_ms();
    if reply.state != Slot::Pending
    {
        // A held call is tested for only here, off the path of a reply that
        // rides the receive.
        if let Some(outcome) = reply.state.unheld()
        {
            reply.state = outcome;
            return Ok(Next::Held);
        }
        return kernel.recv(ep, timeout_ms).map(Next::Received);
    }
    // The reply is sent from the slot and only the flag is cleared: no turn
    // copies the message.
    reply.state = Slot::Empty;
    let got = kernel.reply_recv(ep, &reply.msg, timeout_ms);
    match got
    {
        Err(e) if !failed_after_reply(e) =>
        {
            if kernel.reply(&reply.msg).is_ok()
            {
                // The binding survived a refusal before the reply.
                return Err(e);
            }
            // The reply failed and consumed the binding: nothing is owed.
            reply.lose(kernel);
            kernel.recv(ep, timeout_ms).map(Next::Received)
        }
        _ => got.map(Next::Received),
    }
}

/// Whether `e`, returned by `SYS_IPC_REPLY_RECV`, comes from its receive,
/// after the reply was made (`core/kernel/docs/syscalls.md`
/// § `SYS_IPC_REPLY_RECV`).
fn failed_after_reply(e: i64) -> bool
{
    e == SyscallError::NoReceiver as i64
        || e == SyscallError::Interrupted as i64
        || e == SyscallError::WouldBlock as i64
}

#[cfg(test)]
mod tests
{
    use super::*;

    /// A transport whose syscalls return what the test sets, and which
    /// records each call it takes, in order.
    struct Script
    {
        recv: Result<u64, i64>,
        reply: Result<(), i64>,
        reply_recv: Result<u64, i64>,
        /// The bound the transport gives, which every receive must carry.
        timeout: u64,
        calls: [Option<Call>; 8],
        count: usize,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Call
    {
        Recv,
        Reply(u64),
        ReplyRecv(u64),
        Delete(u64),
    }

    const EP: u64 = 0x40;
    const REPLY: u64 = 0x11;
    const NEXT: u64 = 0x22;
    /// The cap every test reply moves.
    const CAP: u64 = 0x7;

    fn err(e: SyscallError) -> i64
    {
        e as i64
    }

    impl Script
    {
        fn new() -> Self
        {
            Self {
                recv: Ok(NEXT),
                reply: Ok(()),
                reply_recv: Ok(NEXT),
                timeout: 0,
                calls: [None; 8],
                count: 0,
            }
        }

        fn log(&mut self, call: Call)
        {
            self.calls[self.count] = Some(call);
            self.count += 1;
        }

        fn calls(&self) -> &[Option<Call>]
        {
            &self.calls[..self.count]
        }
    }

    impl Transport for Script
    {
        /// The label of the request received.
        type Got = u64;

        fn timeout_ms(&self) -> u64
        {
            self.timeout
        }

        fn recv(&mut self, ep: u64, timeout_ms: u64) -> Result<u64, i64>
        {
            assert_eq!(ep, EP);
            assert_eq!(timeout_ms, self.timeout);
            self.log(Call::Recv);
            self.recv
        }

        fn reply(&mut self, msg: &IpcMessage) -> Result<(), i64>
        {
            self.log(Call::Reply(msg.label));
            self.reply
        }

        fn reply_recv(&mut self, ep: u64, msg: &IpcMessage, timeout_ms: u64) -> Result<u64, i64>
        {
            assert_eq!(ep, EP);
            assert_eq!(timeout_ms, self.timeout);
            self.log(Call::ReplyRecv(msg.label));
            self.reply_recv
        }

        fn delete_cap(&mut self, cap: u64)
        {
            self.log(Call::Delete(cap));
        }

        /// A delivered call is its label alone, with no words or caps.
        fn read(&mut self, got: &u64, msg: &mut IpcMessage)
        {
            *msg = IpcMessage::builder(*got).build();
        }
    }

    fn reply_msg() -> IpcMessage
    {
        IpcMessage::builder(REPLY).cap(CAP).build()
    }

    fn with_reply() -> Reply
    {
        let mut reply = Reply::new();
        reply.set(reply_msg());
        reply
    }

    fn with_owned_reply() -> Reply
    {
        let mut reply = Reply::new();
        reply.set_or_delete_caps(reply_msg());
        reply
    }

    // The defect caught: an empty slot that still makes a reply (to a caller
    // already answered, or to none), or a receive that is not the plain one.
    #[test]
    fn an_empty_slot_receives_alone()
    {
        let mut kernel = Script::new();
        let got = next_with(&mut kernel, EP, &mut Reply::new());
        assert_eq!(got, Ok(Next::Received(NEXT)));
        assert_eq!(kernel.calls(), &[Some(Call::Recv)]);
    }

    // The defect caught: a set reply sent apart from the receive, sent twice,
    // or left in the slot for the next turn's caller.
    #[test]
    fn a_set_reply_rides_the_receive_once()
    {
        let mut kernel = Script::new();
        let mut reply = with_reply();
        assert_eq!(
            next_with(&mut kernel, EP, &mut reply),
            Ok(Next::Received(NEXT))
        );
        assert_eq!(kernel.calls(), &[Some(Call::ReplyRecv(REPLY))]);
        assert_eq!(
            next_with(&mut kernel, EP, &mut reply),
            Ok(Next::Received(NEXT))
        );
        assert_eq!(
            kernel.calls(),
            &[Some(Call::ReplyRecv(REPLY)), Some(Call::Recv)]
        );
    }

    // The defect caught: a slot, reused without being cleared, that sends an
    // earlier reply's words or caps with a later reply that has fewer.
    #[test]
    fn a_reused_slot_sends_only_the_later_reply()
    {
        let mut kernel = Script::new();
        let mut reply = Reply::new();
        reply.set(
            IpcMessage::builder(REPLY)
                .word(0, 1)
                .word(1, 2)
                .cap(CAP)
                .build(),
        );
        assert_eq!(
            next_with(&mut kernel, EP, &mut reply),
            Ok(Next::Received(NEXT))
        );

        reply.set(IpcMessage::builder(NEXT).word(0, 9).build());
        assert_eq!(reply.msg.label, NEXT);
        assert_eq!(reply.msg.word_count(), 1);
        assert_eq!(reply.msg.word(0), 9);
        assert_eq!(reply.msg.caps(), &[] as &[u64]);
        assert_eq!(
            next_with(&mut kernel, EP, &mut reply),
            Ok(Next::Received(NEXT))
        );

        reply.set_status(REPLY);
        assert_eq!(reply.msg.label, REPLY);
        assert_eq!(reply.msg.word_count(), 0);
        assert_eq!(reply.msg.caps(), &[] as &[u64]);
    }

    /// The label of the call a turn returns: one the kernel delivered, or the
    /// one the slot held.
    fn label(got: Result<Next<u64>, i64>, reply: &Reply) -> Result<u64, i64>
    {
        got.map(|next| match next
        {
            Next::Received(label) => label,
            Next::Held => reply.msg.label,
        })
    }

    // The defect caught: a flush that sends a plain reply (whose caller's wake
    // can queue behind the server), sends an empty slot's, sends a reply
    // twice, or loses the call its receive bound, or returns that call twice.
    #[test]
    fn a_flush_sends_with_a_receive_that_does_not_wait_and_holds_its_call()
    {
        let mut kernel = Script::new();
        kernel.timeout = syscall::WAIT_TRY_ONCE;
        let mut reply = with_reply();
        reply.flush_with(&mut kernel, EP);
        assert!(!reply.is_set());
        reply.flush_with(&mut kernel, EP);
        assert_eq!(kernel.calls(), &[Some(Call::ReplyRecv(REPLY))]);
        let got = next_with(&mut kernel, EP, &mut reply);
        assert_eq!(label(got, &reply), Ok(NEXT));
        assert_eq!(
            kernel.calls(),
            &[Some(Call::ReplyRecv(REPLY))],
            "a held call takes no syscall"
        );
        let got = next_with(&mut kernel, EP, &mut reply);
        assert_eq!(got, Ok(Next::Received(NEXT)));
        assert_eq!(
            kernel.calls(),
            &[Some(Call::ReplyRecv(REPLY)), Some(Call::Recv)]
        );
        Reply::new().flush_with(&mut kernel, EP);
        assert_eq!(kernel.count, 2, "an empty slot's flush sends nothing");
    }

    // The defect caught: a last send that receives (binding a call the exit
    // fails), sends an empty slot's reply, or sends a reply twice, or an
    // undelivered last reply that keeps its caps.
    #[test]
    fn a_last_send_replies_alone_once()
    {
        let mut kernel = Script::new();
        let mut reply = with_reply();
        reply.send_last_with(&mut kernel);
        reply.send_last_with(&mut kernel);
        Reply::new().send_last_with(&mut kernel);
        assert_eq!(kernel.calls(), &[Some(Call::Reply(REPLY))]);
        assert!(!reply.undelivered());

        let mut kernel = Script::new();
        kernel.reply = Err(err(SyscallError::InvalidCapability));
        let mut reply = with_owned_reply();
        reply.send_last_with(&mut kernel);
        assert_eq!(
            kernel.calls(),
            &[Some(Call::Reply(REPLY)), Some(Call::Delete(CAP))]
        );
        assert!(reply.undelivered());
    }

    // The defect caught: a flush whose receive found no call, or was refused
    // before its reply, that holds a call anyway (a stale message served as a
    // request), or whose reply is not made.
    #[test]
    fn a_flush_that_binds_no_call_holds_none()
    {
        for (reply_recv, sent) in [
            (
                SyscallError::WouldBlock,
                &[Some(Call::ReplyRecv(REPLY))][..],
            ),
            (
                SyscallError::Interrupted,
                &[Some(Call::ReplyRecv(REPLY))][..],
            ),
            (
                SyscallError::QuotaExceeded,
                &[Some(Call::ReplyRecv(REPLY)), Some(Call::Reply(REPLY))][..],
            ),
        ]
        {
            let mut kernel = Script::new();
            kernel.timeout = syscall::WAIT_TRY_ONCE;
            kernel.reply_recv = Err(err(reply_recv));
            let mut reply = with_reply();
            reply.flush_with(&mut kernel, EP);
            assert_eq!(kernel.calls(), sent, "{reply_recv:?}");
            assert!(!reply.undelivered(), "{reply_recv:?}");
            let got = next_with(&mut kernel, EP, &mut reply);
            assert_eq!(got, Ok(Next::Received(NEXT)), "{reply_recv:?}");
            assert_eq!(
                kernel.calls().last(),
                Some(&Some(Call::Recv)),
                "{reply_recv:?}"
            );
        }
    }

    // The defect caught: an undelivered reply set to delete its caps that
    // leaves them in the server's CSpace, on a reply failure found by the
    // fallback or by a flush.
    #[test]
    fn an_undelivered_owned_reply_deletes_its_caps()
    {
        let mut kernel = Script::new();
        kernel.reply_recv = Err(err(SyscallError::InvalidCapability));
        kernel.reply = Err(err(SyscallError::InvalidCapability));
        let got = next_with(&mut kernel, EP, &mut with_owned_reply());
        assert_eq!(got, Ok(Next::Received(NEXT)));
        assert_eq!(
            kernel.calls(),
            &[
                Some(Call::ReplyRecv(REPLY)),
                Some(Call::Reply(REPLY)),
                Some(Call::Delete(CAP)),
                Some(Call::Recv)
            ]
        );

        let mut kernel = Script::new();
        kernel.timeout = syscall::WAIT_TRY_ONCE;
        kernel.reply_recv = Err(err(SyscallError::QuotaExceeded));
        kernel.reply = Err(err(SyscallError::QuotaExceeded));
        let mut reply = with_owned_reply();
        reply.flush_with(&mut kernel, EP);
        assert_eq!(
            kernel.calls(),
            &[
                Some(Call::ReplyRecv(REPLY)),
                Some(Call::Reply(REPLY)),
                Some(Call::Delete(CAP)),
                Some(Call::Recv)
            ]
        );
        assert!(reply.undelivered());
        assert_eq!(
            reply.msg.caps(),
            &[] as &[u64],
            "the held call replaced the reply"
        );
    }

    // The defect caught: a delivered reply whose caps are deleted anyway (the
    // caller's copies stay, the server's slots name nothing it owns), whether
    // it rode the receive or was sent again after a refusal.
    #[test]
    fn a_delivered_owned_reply_keeps_its_caps()
    {
        let mut kernel = Script::new();
        assert_eq!(
            next_with(&mut kernel, EP, &mut with_owned_reply()),
            Ok(Next::Received(NEXT))
        );
        assert_eq!(kernel.calls(), &[Some(Call::ReplyRecv(REPLY))]);

        let mut kernel = Script::new();
        kernel.reply_recv = Err(err(SyscallError::QuotaExceeded));
        let got = next_with(&mut kernel, EP, &mut with_owned_reply());
        assert_eq!(got, Err(err(SyscallError::QuotaExceeded)));
        assert_eq!(
            kernel.calls(),
            &[Some(Call::ReplyRecv(REPLY)), Some(Call::Reply(REPLY))]
        );
    }

    // The defect caught: a receive failure after the reply was made that sends
    // the reply again, or that the loop's guard never sees.
    #[test]
    fn a_receive_failure_after_the_reply_is_returned_without_a_resend()
    {
        for e in [
            SyscallError::Interrupted,
            SyscallError::NoReceiver,
            SyscallError::WouldBlock,
        ]
        {
            let mut kernel = Script::new();
            kernel.reply_recv = Err(err(e));
            assert_eq!(next_with(&mut kernel, EP, &mut with_reply()), Err(err(e)));
            assert_eq!(kernel.calls(), &[Some(Call::ReplyRecv(REPLY))], "{e:?}");
        }
    }

    // The defect caught: a receive refused before the reply (the binding kept)
    // whose reply is never sent, so the caller waits until the next receive
    // releases it, or whose refusal the loop's guard never sees.
    #[test]
    fn a_refusal_before_the_reply_sends_the_reply_alone_and_returns_the_refusal()
    {
        let mut kernel = Script::new();
        kernel.reply_recv = Err(err(SyscallError::QuotaExceeded));
        let got = next_with(&mut kernel, EP, &mut with_reply());
        assert_eq!(got, Err(err(SyscallError::QuotaExceeded)));
        assert_eq!(
            kernel.calls(),
            &[Some(Call::ReplyRecv(REPLY)), Some(Call::Reply(REPLY))]
        );
    }

    // The defect caught: a failed reply (the binding consumed) returned to the
    // loop as a receive failure, which counts a caller's bad capability toward
    // the service's wedge streak, or that ends the turn without a receive.
    #[test]
    fn a_failed_reply_is_not_a_receive_failure()
    {
        let mut kernel = Script::new();
        kernel.reply_recv = Err(err(SyscallError::QuotaExceeded));
        kernel.reply = Err(err(SyscallError::InvalidCapability));
        let got = next_with(&mut kernel, EP, &mut with_reply());
        assert_eq!(got, Ok(Next::Received(NEXT)));
        assert_eq!(
            kernel.calls(),
            &[
                Some(Call::ReplyRecv(REPLY)),
                Some(Call::Reply(REPLY)),
                Some(Call::Recv)
            ]
        );
    }

    // The defect caught: a bounded wait that one of the receiving syscalls
    // drops, so the loop blocks without bound on that path, or a wait the
    // empty slot's receive does not carry.
    #[test]
    fn a_bounded_wait_reaches_every_receive()
    {
        const WAIT: u64 = 2;
        let mut kernel = Script::new();
        kernel.timeout = WAIT;
        assert_eq!(
            next_with(&mut kernel, EP, &mut Reply::new()),
            Ok(Next::Received(NEXT))
        );
        assert_eq!(
            next_with(&mut kernel, EP, &mut with_reply()),
            Ok(Next::Received(NEXT))
        );
        kernel.reply_recv = Err(err(SyscallError::QuotaExceeded));
        kernel.reply = Err(err(SyscallError::InvalidCapability));
        assert_eq!(
            next_with(&mut kernel, EP, &mut with_reply()),
            Ok(Next::Received(NEXT))
        );
        assert_eq!(
            kernel.calls(),
            &[
                Some(Call::Recv),
                Some(Call::ReplyRecv(REPLY)),
                Some(Call::ReplyRecv(REPLY)),
                Some(Call::Reply(REPLY)),
                Some(Call::Recv)
            ]
        );
    }

    // The defect caught: a loop that never learns its reply failed, so the
    // effect of a request whose caller never heard of it stays, or that
    // learns of a failure that did not happen (a delivered reply, a refusal
    // before the reply after which the reply was sent alone, or an earlier
    // send's failure), so it undoes a request its caller saw succeed.
    #[test]
    fn an_undelivered_reply_is_reported_until_the_next_send()
    {
        let mut kernel = Script::new();
        kernel.reply_recv = Err(err(SyscallError::QuotaExceeded));
        kernel.reply = Err(err(SyscallError::InvalidCapability));
        let mut reply = with_reply();
        assert!(reply.is_set());
        assert_eq!(
            next_with(&mut kernel, EP, &mut reply),
            Ok(Next::Received(NEXT))
        );
        assert!(reply.undelivered());
        assert!(!reply.is_set());
        assert_eq!(
            next_with(&mut kernel, EP, &mut reply),
            Ok(Next::Received(NEXT))
        );
        assert!(
            reply.undelivered(),
            "a call with no reply leaves the outcome"
        );

        reply.set(reply_msg());
        assert!(reply.is_set());
        reply.flush_with(&mut kernel, EP);
        assert!(reply.undelivered());
        reply.flush_with(&mut kernel, EP);
        assert!(
            reply.undelivered(),
            "a flush with no reply leaves the outcome"
        );
        let got = next_with(&mut kernel, EP, &mut reply);
        assert_eq!(label(got, &reply), Ok(NEXT));
        assert!(
            reply.undelivered(),
            "the return of a held call leaves the outcome"
        );
        kernel.reply_recv = Ok(NEXT);
        reply.set(reply_msg());
        reply.flush_with(&mut kernel, EP);
        assert!(!reply.undelivered(), "a delivered send clears the outcome");
        assert_eq!(
            label(next_with(&mut kernel, EP, &mut reply), &reply),
            Ok(NEXT)
        );
        assert!(!reply.undelivered());

        let mut kernel = Script::new();
        kernel.reply_recv = Err(err(SyscallError::QuotaExceeded));
        let mut reply = with_reply();
        let got = next_with(&mut kernel, EP, &mut reply);
        assert_eq!(got, Err(err(SyscallError::QuotaExceeded)));
        assert!(!reply.undelivered());
        reply.set(reply_msg());
        kernel.reply_recv = Ok(NEXT);
        assert_eq!(
            next_with(&mut kernel, EP, &mut reply),
            Ok(Next::Received(NEXT))
        );
        assert!(!reply.undelivered());
    }
}
