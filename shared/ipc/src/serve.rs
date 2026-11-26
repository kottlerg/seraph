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
//! its reply, or one that must answer before something it does next, replies
//! at once with [`crate::ipc_reply`] and leaves the slot empty; a loop with
//! work before its next receive sends the slot's reply alone first
//! ([`Reply::flush`]). With the slot empty, [`next_request`] is
//! [`crate::ipc_recv`].

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
/// to the caller the thread's last receive bound.
pub struct Reply
{
    msg: Option<IpcMessage>,
    /// Delete the reply's caps from this thread's `CSpace` when the reply is
    /// not delivered ([`Self::set_or_delete_caps`]).
    delete_caps: bool,
}

impl Reply
{
    /// An empty slot.
    #[must_use]
    pub const fn new() -> Self
    {
        Self {
            msg: None,
            delete_caps: false,
        }
    }

    /// Leave `msg` as the reply to this thread's pending caller, for the
    /// loop's next [`next_request`] (or [`Self::flush`]) to send. A turn
    /// sets at most one reply.
    pub fn set(&mut self, msg: IpcMessage)
    {
        debug_assert!(self.msg.is_none(), "a turn sets at most one reply");
        self.msg = Some(msg);
        self.delete_caps = false;
    }

    /// [`Self::set`] of a reply that carries the label `status` alone, the
    /// form of most refusals and acknowledgements. The message is built here,
    /// so a handler with many such replies holds none of them in its frame.
    pub fn set_status(&mut self, status: u64)
    {
        self.set(IpcMessage::new(status));
    }

    /// [`Self::set`], for a reply that moves caps this thread keeps no use
    /// for: when the reply is not delivered (the caller is gone, or its
    /// `CSpace` cannot take the caps), they stay in this thread's `CSpace`,
    /// and the send deletes them there.
    pub fn set_or_delete_caps(&mut self, msg: IpcMessage)
    {
        debug_assert!(self.msg.is_none(), "a turn sets at most one reply");
        self.msg = Some(msg);
        self.delete_caps = true;
    }

    /// Send the reply now, alone (`SYS_IPC_REPLY`), when one is set, and
    /// empty the slot: for a loop with work before its next receive, which
    /// the reply would otherwise wait behind.
    ///
    /// # Safety
    /// `ipc_buf` must point to the calling thread's 4 KiB-aligned IPC buffer
    /// page as registered via `syscall::ipc_buffer_set`.
    ///
    /// # Errors
    /// [`crate::ipc_reply`]'s, which consume the pending reply as there, after
    /// the caps of a reply set with [`Self::set_or_delete_caps`] are deleted;
    /// `Ok` when no reply is set.
    pub unsafe fn flush(&mut self, ipc_buf: *mut u64) -> Result<(), i64>
    {
        self.flush_with(&mut Kernel { ipc_buf })
    }

    fn flush_with<T: Transport>(&mut self, kernel: &mut T) -> Result<(), i64>
    {
        let Some(msg) = self.msg.take()
        else
        {
            return Ok(());
        };
        let sent = kernel.reply(&msg);
        if sent.is_err()
        {
            self.undelivered(kernel, &msg);
        }
        sent
    }

    /// The reply `msg`, taken from the slot, was not delivered: delete its
    /// caps when it was set to.
    fn undelivered<T: Transport>(&self, kernel: &mut T, msg: &IpcMessage)
    {
        if self.delete_caps
        {
            for &cap in msg.caps()
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
/// `reply`'s reply when one is set, and empty the slot.
///
/// With a reply set this is one [`crate::ipc_reply_recv`]. Its errors come
/// from three parts, before the reply, of the reply, and after it, and the
/// first two share codes, so on one of those the reply is sent again alone:
/// when the receive was refused before the reply, that sends it and the
/// refusal is returned for the loop's `RecvGuard`; when the reply itself
/// failed, it consumed the binding, the second send fails with nothing to
/// wake, and the receive is made alone. No reply is lost or sent twice, and a
/// reply's failure, which the caller's capabilities or `CSpace` cause, is
/// never returned as a receive failure. The caps of an undelivered reply set
/// with [`Reply::set_or_delete_caps`] are deleted.
///
/// # Safety
/// `ipc_buf` must point to the calling thread's 4 KiB-aligned IPC buffer
/// page as registered via `syscall::ipc_buffer_set`.
///
/// # Errors
/// [`crate::ipc_recv`]'s: those of the receive's capability check and
/// cap-slot pre-allocation (`InvalidCapability`, `InsufficientRights`,
/// `QuotaExceeded`, `OutOfMemory`), after which the reply has been made
/// all the same, and `NoReceiver` and `Interrupted` from the wait.
pub unsafe fn next_request(ep: u64, reply: &mut Reply, ipc_buf: *mut u64)
-> Result<IpcMessage, i64>
{
    next_with(&mut Kernel { ipc_buf }, ep, reply)
}

/// The syscalls of a turn of [`next_request`], behind a trait so that its
/// order and fallbacks are host-tested.
trait Transport
{
    fn recv(&mut self, ep: u64) -> Result<IpcMessage, i64>;
    fn reply(&mut self, msg: &IpcMessage) -> Result<(), i64>;
    fn reply_recv(&mut self, ep: u64, msg: &IpcMessage) -> Result<IpcMessage, i64>;
    fn delete_cap(&mut self, cap: u64);
}

/// The kernel, through the calling thread's registered IPC buffer page.
struct Kernel
{
    /// The calling thread's registered IPC buffer page ([`next_request`]'s
    /// contract).
    ipc_buf: *mut u64,
}

impl Transport for Kernel
{
    fn recv(&mut self, ep: u64) -> Result<IpcMessage, i64>
    {
        // SAFETY: ipc_buf is the registered IPC buffer page (next_request's
        // contract).
        unsafe { crate::ipc_recv(ep, self.ipc_buf) }
    }

    fn reply(&mut self, msg: &IpcMessage) -> Result<(), i64>
    {
        // SAFETY: as in recv.
        unsafe { crate::ipc_reply(msg, self.ipc_buf) }
    }

    fn reply_recv(&mut self, ep: u64, msg: &IpcMessage) -> Result<IpcMessage, i64>
    {
        // SAFETY: as in recv.
        unsafe { crate::ipc_reply_recv(ep, msg, self.ipc_buf, 0) }
    }

    fn delete_cap(&mut self, cap: u64)
    {
        let _ = syscall::cap_delete(cap);
    }
}

fn next_with<T: Transport>(kernel: &mut T, ep: u64, reply: &mut Reply) -> Result<IpcMessage, i64>
{
    let Some(msg) = reply.msg.take()
    else
    {
        return kernel.recv(ep);
    };
    match kernel.reply_recv(ep, &msg)
    {
        Ok(next) => Ok(next),
        Err(e) if failed_after_reply(e) => Err(e),
        Err(e) =>
        {
            if kernel.reply(&msg).is_ok()
            {
                // The binding survived a refusal before the reply.
                return Err(e);
            }
            // The reply failed and consumed the binding: nothing is owed.
            reply.undelivered(kernel, &msg);
            kernel.recv(ep)
        }
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
        recv: Result<IpcMessage, i64>,
        reply: Result<(), i64>,
        reply_recv: Result<IpcMessage, i64>,
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
                recv: Ok(IpcMessage::new(NEXT)),
                reply: Ok(()),
                reply_recv: Ok(IpcMessage::new(NEXT)),
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
        fn recv(&mut self, ep: u64) -> Result<IpcMessage, i64>
        {
            assert_eq!(ep, EP);
            self.log(Call::Recv);
            self.recv
        }

        fn reply(&mut self, msg: &IpcMessage) -> Result<(), i64>
        {
            self.log(Call::Reply(msg.label));
            self.reply
        }

        fn reply_recv(&mut self, ep: u64, msg: &IpcMessage) -> Result<IpcMessage, i64>
        {
            assert_eq!(ep, EP);
            self.log(Call::ReplyRecv(msg.label));
            self.reply_recv
        }

        fn delete_cap(&mut self, cap: u64)
        {
            self.log(Call::Delete(cap));
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

    fn label(r: &Result<IpcMessage, i64>) -> Result<u64, i64>
    {
        r.as_ref().map(|m| m.label).map_err(|&e| e)
    }

    // The defect caught: an empty slot that still makes a reply (to a caller
    // already answered, or to none), or a receive that is not the plain one.
    #[test]
    fn an_empty_slot_receives_alone()
    {
        let mut kernel = Script::new();
        let got = next_with(&mut kernel, EP, &mut Reply::new());
        assert_eq!(label(&got), Ok(NEXT));
        assert_eq!(kernel.calls(), &[Some(Call::Recv)]);
    }

    // The defect caught: a set reply sent apart from the receive, sent twice,
    // or left in the slot for the next turn's caller.
    #[test]
    fn a_set_reply_rides_the_receive_once()
    {
        let mut kernel = Script::new();
        let mut reply = with_reply();
        assert_eq!(label(&next_with(&mut kernel, EP, &mut reply)), Ok(NEXT));
        assert_eq!(kernel.calls(), &[Some(Call::ReplyRecv(REPLY))]);
        assert_eq!(label(&next_with(&mut kernel, EP, &mut reply)), Ok(NEXT));
        assert_eq!(
            kernel.calls(),
            &[Some(Call::ReplyRecv(REPLY)), Some(Call::Recv)]
        );
    }

    // The defect caught: a flush that sends no reply, sends an empty slot's, or
    // leaves the reply for the next receive to send again.
    #[test]
    fn a_flush_sends_a_set_reply_once()
    {
        let mut kernel = Script::new();
        let mut reply = with_reply();
        assert_eq!(reply.flush_with(&mut kernel), Ok(()));
        assert_eq!(reply.flush_with(&mut kernel), Ok(()));
        assert_eq!(label(&next_with(&mut kernel, EP, &mut reply)), Ok(NEXT));
        assert_eq!(
            kernel.calls(),
            &[Some(Call::Reply(REPLY)), Some(Call::Recv)]
        );
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
        assert_eq!(label(&got), Ok(NEXT));
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
        kernel.reply = Err(err(SyscallError::QuotaExceeded));
        let mut reply = with_owned_reply();
        assert_eq!(
            reply.flush_with(&mut kernel),
            Err(err(SyscallError::QuotaExceeded))
        );
        assert_eq!(
            kernel.calls(),
            &[Some(Call::Reply(REPLY)), Some(Call::Delete(CAP))]
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
            label(&next_with(&mut kernel, EP, &mut with_owned_reply())),
            Ok(NEXT)
        );
        assert_eq!(kernel.calls(), &[Some(Call::ReplyRecv(REPLY))]);

        let mut kernel = Script::new();
        kernel.reply_recv = Err(err(SyscallError::QuotaExceeded));
        let got = next_with(&mut kernel, EP, &mut with_owned_reply());
        assert_eq!(label(&got), Err(err(SyscallError::QuotaExceeded)));
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
            assert_eq!(
                label(&next_with(&mut kernel, EP, &mut with_reply())),
                Err(err(e))
            );
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
        assert_eq!(label(&got), Err(err(SyscallError::QuotaExceeded)));
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
        assert_eq!(label(&got), Ok(NEXT));
        assert_eq!(
            kernel.calls(),
            &[
                Some(Call::ReplyRecv(REPLY)),
                Some(Call::Reply(REPLY)),
                Some(Call::Recv)
            ]
        );
    }
}
