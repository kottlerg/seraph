// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/ipc/message.rs

//! IPC message type — label + inline data words + capability handles.
//!
//! A [`Message`] carries:
//! - A 64-bit `label` — caller-defined tag identifying the operation.
//! - Up to [`MSG_DATA_WORDS_MAX`] data words (u64 values).
//! - Up to [`MSG_CAP_SLOTS_MAX`] full capability handles (u64 values).
//!
//! A message lives in a thread's TCB (`ThreadControlBlock::ipc_msg`) and is
//! built there, never on a stack: a sender stages its message in its own, a
//! replier writes its reply into its caller's, and a rendezvous copies the
//! message's valid part, the header, the `data_count` data words and the
//! `cap_count` handles, from the sender's into the receiver's
//! ([`Message::copy_from`]). No path zeroes or copies the whole message. The
//! arrays keep the words of earlier messages past the counts; the accessors
//! ([`Message::data`], [`Message::caps`]) are the only view of them and expose
//! only the counted words, so no word of another message is read, copied, or
//! delivered.
//!
//! Its data words and the sender's cap handles (the cap block from
//! `syscall::MSG_CAP_HANDLES_WORD`) are read from the sender's message
//! registers or its per-thread IPC buffer page (registered via
//! `SYS_IPC_BUFFER_SET`); the data words and the delivered handles are written
//! to the receiver's; no memory is shared between the threads. Bulk data
//! travels as a shared memory capability (`docs/ipc-design.md` § Message
//! Format and § Large Data Transfers).

use syscall::{MSG_CAP_SLOTS_MAX, MSG_DATA_WORDS_MAX};

/// An IPC message transferred between threads by an endpoint call
/// ([`EndpointState`](crate::ipc::endpoint::EndpointState)) or reply.
///
/// Neither `Clone` nor `Copy`: a message reaches another thread only through
/// [`Message::copy_from`], which copies its valid part.
///
/// The counts never exceed `MSG_DATA_WORDS_MAX` and `MSG_CAP_SLOTS_MAX`, and
/// the first `data_count` data words and `cap_count` handles are this
/// message's; every word past them is left from an earlier message. Each
/// method below keeps this, which is why the counts and the arrays are private.
///
/// # Adding message fields
/// `data` and `cap_slots` are sized by `MSG_DATA_WORDS_MAX` /
/// `MSG_CAP_SLOTS_MAX` in `abi/syscall/src/lib.rs`; raise those constants and
/// audit the marshalling in `core/kernel/src/syscall/ipc.rs`. A new field also
/// needs [`Message::begin`] and [`Message::copy_from`] updated.
pub struct Message
{
    /// Operation tag — caller-defined; not interpreted by the kernel.
    pub label: u64,
    /// Badge from the sender's endpoint capability slot. Zero if unbadged.
    /// Set by `sys_ipc_call` from the caller's endpoint cap, or by
    /// `fault_dispatch` from the faulting thread's `fault_badges` entry of the
    /// fault's class; delivered to the receiver via the third return register
    /// of `ipc_recv`.
    pub badge: u64,
    /// Number of valid entries in `data` (`0..=MSG_DATA_WORDS_MAX`).
    data_count: usize,
    /// Number of valid entries in `cap_slots` (`0..=MSG_CAP_SLOTS_MAX`).
    cap_count: usize,
    /// Inline data words. The width is the IPC buffer layout's
    /// `MSG_DATA_WORDS_MAX`; bulk data moves through Memory caps instead.
    data: [u64; MSG_DATA_WORDS_MAX],
    /// Capability handles in transfer: on the send side, the sender's full
    /// cap handles (index + generation) as copied from its IPC buffer's cap
    /// block (`syscall::MSG_CAP_HANDLES_WORD`); after a completed transfer,
    /// rewritten to the destination-side handles delivered to the recipient.
    cap_slots: [u64; MSG_CAP_SLOTS_MAX],
}

impl Default for Message
{
    /// An empty message, with every word zero: a new thread's `ipc_msg`.
    fn default() -> Self
    {
        Self {
            label: 0,
            badge: 0,
            data_count: 0,
            cap_count: 0,
            data: [0u64; MSG_DATA_WORDS_MAX],
            cap_slots: [0u64; MSG_CAP_SLOTS_MAX],
        }
    }
}

impl Message
{
    /// Start a new message in place: `label` and `badge`, with no data word
    /// and no capability. The words of the message it replaces stay in the
    /// arrays, past the counts, where no accessor reaches them.
    pub fn begin(&mut self, label: u64, badge: u64)
    {
        self.label = label;
        self.badge = badge;
        self.data_count = 0;
        self.cap_count = 0;
    }

    /// The message's data words: exactly its `data_count` leading words.
    pub fn data(&self) -> &[u64]
    {
        self.data.get(..self.data_count).unwrap_or(&[])
    }

    /// The message's capability handles: exactly its `cap_count` leading
    /// slots.
    pub fn caps(&self) -> &[u64]
    {
        self.cap_slots.get(..self.cap_count).unwrap_or(&[])
    }

    /// Write the message's data words with `fill`, which is handed exactly
    /// `count` words (clamped to `MSG_DATA_WORDS_MAX`) and must write each of
    /// them; on its success they become the message's data.
    ///
    /// # Errors
    /// `fill`'s error, after which the message has no data word.
    pub fn fill_data<E>(
        &mut self,
        count: usize,
        fill: impl FnOnce(&mut [u64]) -> Result<(), E>,
    ) -> Result<(), E>
    {
        self.data_count = 0;
        let count = count.min(MSG_DATA_WORDS_MAX);
        fill(self.data.get_mut(..count).unwrap_or(&mut []))?;
        self.data_count = count;
        Ok(())
    }

    /// Make `words` the message's data words; words past
    /// `MSG_DATA_WORDS_MAX` are dropped.
    pub fn set_data(&mut self, words: &[u64])
    {
        self.data_count = copy_leading(&mut self.data, words);
    }

    /// Make `handles` the message's capability handles; handles past
    /// `MSG_CAP_SLOTS_MAX` are dropped.
    pub fn set_caps(&mut self, handles: &[u64])
    {
        self.cap_count = copy_leading(&mut self.cap_slots, handles);
    }

    /// Make this message a copy of `src`: its label, badge, data words and
    /// capability handles, and no word past its counts.
    pub fn copy_from(&mut self, src: &Self)
    {
        self.label = src.label;
        self.badge = src.badge;
        self.set_data(src.data());
        self.set_caps(src.caps());
    }
}

/// Copy the leading words of `src` into `dst`, as many as `dst` holds, and
/// return how many were copied.
fn copy_leading(dst: &mut [u64], src: &[u64]) -> usize
{
    let count = src.len().min(dst.len());
    if let (Some(dst), Some(src)) = (dst.get_mut(..count), src.get(..count))
    {
        dst.copy_from_slice(src);
    }
    count
}

#[cfg(test)]
mod tests
{
    use super::*;

    /// A message whose every data word and handle is `fill`, all of them
    /// counted: the state a message leaves behind for the next one.
    fn full_of(fill: u64) -> Message
    {
        let mut msg = Message::default();
        msg.begin(fill, fill);
        msg.set_data(&[fill; MSG_DATA_WORDS_MAX]);
        msg.set_caps(&[fill; MSG_CAP_SLOTS_MAX]);
        msg
    }

    /// The words `1..=count`.
    fn words(count: usize) -> Vec<u64>
    {
        (1..=count as u64).collect()
    }

    #[test]
    fn data_shows_exactly_the_words_of_the_current_message()
    {
        for count in [0, 1, MSG_DATA_WORDS_MAX - 1, MSG_DATA_WORDS_MAX]
        {
            let mut msg = full_of(u64::MAX);
            msg.begin(7, 9);
            assert!(msg.data().is_empty(), "count {count}: begin left data");
            msg.set_data(&words(count));
            assert_eq!(msg.data(), words(count).as_slice(), "count {count}");
        }
    }

    #[test]
    fn data_past_the_maximum_is_dropped()
    {
        let mut msg = Message::default();
        msg.set_data(&words(MSG_DATA_WORDS_MAX + 1));
        assert_eq!(msg.data(), words(MSG_DATA_WORDS_MAX).as_slice());
    }

    #[test]
    fn caps_show_exactly_the_handles_of_the_current_message()
    {
        for count in 0..=MSG_CAP_SLOTS_MAX + 1
        {
            let mut msg = full_of(u64::MAX);
            msg.begin(0, 0);
            assert!(msg.caps().is_empty(), "count {count}: begin left caps");
            msg.set_caps(&words(count));
            let kept = count.min(MSG_CAP_SLOTS_MAX);
            assert_eq!(msg.caps(), words(kept).as_slice(), "count {count}");
        }
    }

    #[test]
    fn filled_data_is_the_message_only_when_the_fill_succeeds()
    {
        for count in [
            0,
            1,
            MSG_DATA_WORDS_MAX - 1,
            MSG_DATA_WORDS_MAX,
            MSG_DATA_WORDS_MAX + 1,
        ]
        {
            let mut msg = full_of(u64::MAX);
            let failed: Result<(), ()> = msg.fill_data(count, |w| {
                w.fill(5);
                Err(())
            });
            assert_eq!(failed, Err(()));
            assert!(
                msg.data().is_empty(),
                "count {count}: a failed fill left data"
            );

            let mut handed = 0;
            let filled: Result<(), ()> = msg.fill_data(count, |w| {
                handed = w.len();
                w.copy_from_slice(&words(w.len()));
                Ok(())
            });
            assert_eq!(filled, Ok(()));
            let kept = count.min(MSG_DATA_WORDS_MAX);
            assert_eq!(handed, kept, "count {count}");
            assert_eq!(msg.data(), words(kept).as_slice(), "count {count}");
        }
    }

    #[test]
    fn a_copy_carries_the_source_and_nothing_left_in_the_destination()
    {
        for count in [0, 1, MSG_DATA_WORDS_MAX - 1, MSG_DATA_WORDS_MAX]
        {
            let mut src = Message::default();
            src.begin(3, 4);
            src.set_data(&words(count));
            src.set_caps(&words(count.min(2)));
            let mut dst = full_of(u64::MAX);
            dst.copy_from(&src);
            assert_eq!((dst.label, dst.badge), (3, 4));
            assert_eq!(dst.data(), words(count).as_slice(), "count {count}");
            assert_eq!(dst.caps(), words(count.min(2)).as_slice(), "count {count}");
        }
    }
}
