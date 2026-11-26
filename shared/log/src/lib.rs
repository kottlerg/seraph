// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/log/src/lib.rs

//! System log primitives for Seraph userspace.
//!
//! Three parts:
//!
//! * **Wire-format helpers ([`write_bytes`], [`write_args`],
//!   [`write_record`], [`register_name`]):** thin no-allocation wrappers
//!   over the IPC labels defined in `ipc::stream_labels`. Callers supply
//!   their badged SEND cap, IPC buffer pointer, and line level explicitly.
//! * **Process-global cap cache ([`install_badged_cap`],
//!   [`ensure_badged_cap`]):** holds the pre-installed badged SEND
//!   cap. Std's `_start` installs the cap procmgr seeded in
//!   `ProcessInfo.log_send_cap`. No discovery roundtrip — the cap is
//!   live from the first user instruction. Beside it, the name the process
//!   registered on that cap ([`register_name`]), which a log call sends
//!   again when the receiver has lost it (`ipc::stream_labels::SENDER_NAMED`).
//! * **Process-global level filter ([`set_max_level`], [`enabled`],
//!   [`max_level`]):** the most verbose level [`emit`] sends, which std's
//!   `_start` sets from the process's `SERAPH_LOG` environment entry
//!   (`services/logd/docs/ipc-interface.md` § Levels); [`level_entry`]
//!   writes that entry for a spawner to hand a child.
//!
//! The user-facing macro lives in the std overlay (it needs thread-
//! local IPC-buffer access) and reaches [`emit`], or [`emit_record`] for a
//! line with fields; `shared/log/README.md` names the crate's consumers.

#![cfg_attr(feature = "rustc-dep-of-std", feature(no_core))]
#![cfg_attr(
    feature = "rustc-dep-of-std",
    expect(
        internal_features,
        reason = "`no_core` is an internal feature, needed to build as a dependency of std"
    )
)]
#![cfg_attr(all(not(feature = "rustc-dep-of-std"), not(test)), no_std)]
#![cfg_attr(feature = "rustc-dep-of-std", no_core)]

#[cfg(feature = "rustc-dep-of-std")]
extern crate rustc_std_workspace_core as core;

// Cargo records no source file of a `-Z build-std` unit, only the environment variables it
// reads: reading xtask's digest of the sources of every crate std depends on makes a change to
// any of them rebuild this unit (docs/build-system.md § Build Output: the Sysroot).
#[cfg(feature = "rustc-dep-of-std")]
const _: &str = core::env!("SERAPH_STD_DEPS_DIGEST");

#[cfg(feature = "rustc-dep-of-std")]
use core::prelude::rust_2024::*;

use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU64, AtomicUsize, Ordering, fence};
use core::time::Duration;

use ipc::{
    CallTimeout, IpcMessage,
    log_query::SLOT_NAME_MAX,
    log_record::RecordWriter,
    stream_labels::{
        LEVEL_ALERT, LEVEL_CRITICAL, LEVEL_DEBUG, LEVEL_EMERGENCY, LEVEL_ERROR, LEVEL_INFO,
        LEVEL_NOTICE, LEVEL_WARN, NAME_UNKNOWN, SENDER_NAMED, STREAM_BYTES, STREAM_RECORD,
        STREAM_REGISTER_NAME, level_bits, level_or_info,
    },
};
use syscall_abi::{MSG_DATA_WORDS_MAX, SyscallError};

/// Maximum bytes per `STREAM_BYTES` chunk. Lines longer than this are
/// chunked across multiple `ipc_call`s; the receiver concatenates the bytes
/// of answered calls in order.
pub const CHUNK_SIZE: usize = MSG_DATA_WORDS_MAX * 8;

/// Stack-buffer size used by [`write_args`]: one `STREAM_BYTES` payload. A
/// formatted message longer than this is sent in several chunks as the
/// buffer fills, so the size bounds the stack cost, not the message.
const STACK_BUF_LEN: usize = CHUNK_SIZE;

/// The bound, in milliseconds, on a log call (`ipc::ipc_call_timeout`) while
/// the log receiver answers: a call it does not answer in time fails with
/// `WouldBlock`. Its line is dropped, unless the receiver had already
/// received it, in which case it may still be written, even after a later
/// line of the same thread (`services/logd/docs/ipc-interface.md` § Receive
/// pool). A receiver that is wedged, or stopped while holding the endpoint,
/// thus stalls a sender for this long once rather than for good
/// (docs/limits.md § Shared IPC and protocol crates).
/// Long enough that a receiver merely slowed by load still takes every line.
pub const LOG_CALL_TIMEOUT_MS: u32 = 5000;

/// The bound, in milliseconds, on each later log call of the process once
/// one has timed out, until a call is answered again or the process is told
/// that a new receiver has started ([`RECEIVER_UNANSWERED`]): what a sender
/// pays per line while the log receiver stays wedged.
pub const LOG_CALL_UNANSWERED_TIMEOUT_MS: u32 = 10;

/// Whether the log receiver has left a log call of this process unanswered:
/// set when a call times out (`WouldBlock`) at its own bound, not at its
/// thread's call deadline ([`install_time_left`]), cleared when a call is answered
/// or when the process is told that a new receiver has started
/// ([`receiver_restarted`]), and left as it is by any other failure, which
/// says nothing of the receiver ([`unanswered_after`]). While set, log calls
/// are bounded by [`LOG_CALL_UNANSWERED_TIMEOUT_MS`] instead of
/// [`LOG_CALL_TIMEOUT_MS`] ([`call_bound`]). Process-wide because every thread of a process logs on
/// the same badged endpoint, so one thread's timeout says the receiver is
/// answering none of them.
// restore: rebound
static RECEIVER_UNANSWERED: AtomicBool = AtomicBool::new(false);

/// The source of the time left of the calling thread's call deadline, as
/// std's `_start` installs it ([`install_time_left`]): null until then, else
/// a `fn() -> Option<Duration>` stored as a pointer.
// restore: none
static TIME_LEFT: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Install `source`, which returns the time left of the calling thread's
/// call deadline, `None` for a thread with none, as every log call's limit:
/// a log call is then bounded by the earlier of its own bound and the
/// deadline, and is not made once the deadline has passed. std's `_start`
/// installs `std::os::seraph::call_time_left`; a process that installs none
/// makes its log calls under their own bound alone. Last writer wins.
pub fn install_time_left(source: fn() -> Option<Duration>)
{
    TIME_LEFT.store((source as *const ()).cast_mut(), Ordering::Release);
}

/// The time left of the calling thread's call deadline, through the source
/// [`install_time_left`] installed; `None` when none is installed.
fn time_left() -> Option<Duration>
{
    let raw = TIME_LEFT.load(Ordering::Acquire);
    if raw.is_null()
    {
        return None;
    }
    // SAFETY: `install_time_left` is the only writer of a non-null value, and
    // it stores a `fn() -> Option<Duration>`, never a dangling one; a data
    // pointer and a fn pointer are the same width on every target, so the
    // round-trip yields that live function.
    let source = unsafe { core::mem::transmute::<*mut (), fn() -> Option<Duration>>(raw) };
    source()
}

/// The bound a log call is made with, in milliseconds, and whose it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Bound
{
    /// The call's own bound, as [`RECEIVER_UNANSWERED`] selects it: a
    /// timeout says the receiver did not answer.
    Receiver(u32),
    /// The time left of the calling thread's call deadline, shorter than the
    /// call's own bound: a timeout says nothing of the receiver.
    Deadline(u32),
}

impl Bound
{
    /// The bound in milliseconds.
    const fn ms(self) -> u32
    {
        match self
        {
            Self::Receiver(ms) | Self::Deadline(ms) => ms,
        }
    }
}

/// The bound on a log call while [`RECEIVER_UNANSWERED`] reads `unanswered`,
/// with `left` of the calling thread's call deadline to run (`None` for
/// none): the earlier of the two, or `None`, no call, once the deadline has
/// passed.
#[expect(
    clippy::fn_params_excessive_bools,
    reason = "`unanswered` is the value of `RECEIVER_UNANSWERED`, which the function maps to a \
              bound"
)]
fn call_bound(unanswered: bool, left: Option<Duration>) -> Option<Bound>
{
    let own = if unanswered
    {
        LOG_CALL_UNANSWERED_TIMEOUT_MS
    }
    else
    {
        LOG_CALL_TIMEOUT_MS
    };
    match ipc::call_timeout(left)
    {
        CallTimeout::Expired => None,
        CallTimeout::Ms(ms) if ms < own => Some(Bound::Deadline(ms)),
        CallTimeout::Unbounded | CallTimeout::Ms(_) => Some(Bound::Receiver(own)),
    }
}

/// [`RECEIVER_UNANSWERED`] after a log call made with `bound` with
/// `outcome`, from `unanswered` before it: cleared by an answer, set by a
/// timeout at the call's own bound, kept by a timeout at the thread's
/// deadline and by any other error.
#[expect(
    clippy::fn_params_excessive_bools,
    reason = "`unanswered` is the value of `RECEIVER_UNANSWERED`, which the function maps to its \
              next value"
)]
fn unanswered_after<T>(unanswered: bool, bound: Bound, outcome: &Result<T, i64>) -> bool
{
    match outcome
    {
        Ok(_) => false,
        Err(code)
            if *code == SyscallError::WouldBlock as i64 && matches!(bound, Bound::Receiver(_)) =>
        {
            true
        }
        Err(_) => unanswered,
    }
}

/// Forget that the log receiver left a log call of this process unanswered
/// ([`RECEIVER_UNANSWERED`]), so the process's next log call is bounded by
/// [`LOG_CALL_TIMEOUT_MS`] again. For a process that knows a new receiver
/// has started on the log endpoint in place of one that stopped receiving
/// (svcmgr, once it has restarted logd): a timeout the old receiver caused
/// says nothing of the new one, whose start takes longer than
/// [`LOG_CALL_UNANSWERED_TIMEOUT_MS`], so a line written while it starts
/// would otherwise be dropped.
pub fn receiver_restarted()
{
    RECEIVER_UNANSWERED.store(false, Ordering::Relaxed);
}

/// One call made by `call` with the bound [`call_bound`] selects from
/// [`RECEIVER_UNANSWERED`] and `left` of the calling thread's call deadline,
/// then [`RECEIVER_UNANSWERED`] updated from the outcome. The reply when the
/// call was answered; `None`, with no call made, once the deadline has
/// passed.
fn bounded<T>(left: Option<Duration>, call: impl FnOnce(u32) -> Result<T, i64>) -> Option<T>
{
    let unanswered = RECEIVER_UNANSWERED.load(Ordering::Relaxed);
    let bound = call_bound(unanswered, left)?;
    let outcome = call(bound.ms());
    RECEIVER_UNANSWERED.store(
        unanswered_after(unanswered, bound, &outcome),
        Ordering::Relaxed,
    );
    outcome.ok()
}

/// One call of `msg` on `cap`, bounded as [`RECEIVER_UNANSWERED`] and the
/// calling thread's call deadline select ([`bounded`]). The reply's label
/// when the call was answered.
///
/// # Safety
/// `ipc_buf` must be this thread's registered IPC buffer page (the contract
/// of `ipc::ipc_call`).
unsafe fn bounded_call(cap: u64, msg: &IpcMessage, ipc_buf: *mut u64) -> Option<u64>
{
    // SAFETY: the caller's contract covers `ipc_buf`.
    bounded(time_left(), |bound| unsafe {
        ipc::ipc_call_timeout(cap, msg, ipc_buf, bound)
    })
    .map(|reply| reply.label)
}

/// One log message, `msg`, delivered on `cap` ([`deliver`]): each call
/// bounded ([`bounded_call`]), and the process's registered name
/// ([`REGISTERED_NAME`]) sent again when the receiver answers that it has
/// lost it. `true` when the message's last call was answered.
///
/// # Safety
/// `ipc_buf` must be this thread's registered IPC buffer page (the contract
/// of `ipc::ipc_call`).
unsafe fn log_call(cap: u64, msg: &IpcMessage, ipc_buf: *mut u64) -> bool
{
    let registration = || {
        let mut name = [0u8; NAME_KEPT_MAX];
        let len = REGISTERED_NAME.load(&mut name)?;
        Some(name_message(name.get(..len)?))
    };
    // SAFETY: the caller's contract covers `ipc_buf`.
    deliver(msg, registration, |m| unsafe {
        bounded_call(cap, m, ipc_buf)
    })
}

/// Deliver the log message `msg` through `call`, which makes one call and
/// returns its reply's label, `None` when the call failed. A message that
/// carries [`SENDER_NAMED`] and is answered [`NAME_UNKNOWN`] was not
/// consumed: the receiver holds no name for the sender (a restarted logd's
/// fresh table), so the name `registration` builds, when the process keeps
/// one, is sent, and the message is sent once more without the bit, which no
/// receiver refuses. A message is thus refused at most once and costs at most
/// three calls, the two after the first only when the receiver answered it.
/// `true` when the last call made was answered.
fn deliver(
    msg: &IpcMessage,
    registration: impl FnOnce() -> Option<IpcMessage>,
    mut call: impl FnMut(&IpcMessage) -> Option<u64>,
) -> bool
{
    let Some(reply) = call(msg)
    else
    {
        return false;
    };
    if msg.label & SENDER_NAMED == 0 || reply != NAME_UNKNOWN
    {
        return true;
    }
    if let Some(name) = registration()
    {
        // A registration that fails leaves the resend below to render as
        // unnamed; the next refused message tries again.
        let _ = call(&name);
    }
    let mut again = *msg;
    again.label &= !SENDER_NAMED;
    call(&again).is_some()
}

// ── Process-global registered name ──────────────────────────────────────────

/// Bytes of a registered name the process keeps: the most a log receiver
/// stores for a slot and reports (`ipc::log_query::SLOT_NAME_MAX`, which
/// logd's and init-logd's `MAX_NAME_LEN` equals), so the name sent again is
/// stored as the first registration was.
const NAME_KEPT_MAX: usize = SLOT_NAME_MAX;

/// Words of a [`NameCell`]'s bytes.
const NAME_WORDS: usize = NAME_KEPT_MAX / 8;

const _: () = assert!(NAME_KEPT_MAX % 8 == 0);

/// Attempts a [`NameCell::load`] makes before it gives up on a cell that a
/// store keeps changing. A store is a few dozen instructions and names are
/// registered at startup, so a reader that meets one finds it done on the
/// next attempt; the bound keeps a log call from spinning on a writer that
/// was preempted mid-store.
const NAME_LOAD_TRIES: u32 = 4;

/// A name of at most [`NAME_KEPT_MAX`] bytes that any thread of the process
/// reads without a lock: a sequence lock over its length and its bytes, packed
/// little-endian into words. `seq` is even while the cell is stable and odd
/// while a store writes it; a reader takes a copy only when `seq` was even
/// and unchanged across it.
struct NameCell
{
    /// The store count, twice over: odd while a store is writing.
    seq: AtomicU64,
    /// The name's length in bytes; 0 when no name is kept.
    len: AtomicUsize,
    /// The name's bytes, little-endian in each word; those past `len` are
    /// meaningless.
    words: [AtomicU64; NAME_WORDS],
}

impl NameCell
{
    const fn new() -> Self
    {
        Self {
            seq: AtomicU64::new(0),
            len: AtomicUsize::new(0),
            words: [const { AtomicU64::new(0) }; NAME_WORDS],
        }
    }

    /// Keep the first [`NAME_KEPT_MAX`] bytes of `name`. `false`, keeping
    /// nothing, while another store is writing the cell: two threads that
    /// register names at once race to the receiver too, so either name is as
    /// much the process's as the other, and the one being stored stands.
    fn store(&self, name: &[u8]) -> bool
    {
        let name = name.get(..NAME_KEPT_MAX).unwrap_or(name);
        let seq = self.seq.load(Ordering::Relaxed);
        if seq & 1 != 0
            || self
                .seq
                .compare_exchange(
                    seq,
                    seq.wrapping_add(1),
                    Ordering::Acquire,
                    Ordering::Relaxed,
                )
                .is_err()
        {
            return false;
        }
        // The odd `seq` is ordered before the writes below, so a reader that
        // sees one of them sees `seq` move.
        fence(Ordering::Release);
        let mut bytes = name.iter().copied();
        for word in &self.words
        {
            let mut chunk = [0u8; 8];
            for (dst, src) in chunk.iter_mut().zip(bytes.by_ref())
            {
                *dst = src;
            }
            word.store(u64::from_le_bytes(chunk), Ordering::Relaxed);
        }
        self.len.store(name.len(), Ordering::Relaxed);
        self.seq.store(seq.wrapping_add(2), Ordering::Release);
        true
    }

    /// Whether a name is kept; it may be one a store is replacing.
    fn is_set(&self) -> bool
    {
        self.len.load(Ordering::Relaxed) != 0
    }

    /// Copy the kept name into `out` and return its length; `None` when no
    /// name is kept, or when stores kept the cell changing through
    /// [`NAME_LOAD_TRIES`] attempts.
    fn load(&self, out: &mut [u8; NAME_KEPT_MAX]) -> Option<usize>
    {
        for _ in 0..NAME_LOAD_TRIES
        {
            let seq = self.seq.load(Ordering::Acquire);
            if seq & 1 != 0
            {
                core::hint::spin_loop();
                continue;
            }
            let len = self.len.load(Ordering::Relaxed);
            for (dst, word) in out.as_chunks_mut::<8>().0.iter_mut().zip(&self.words)
            {
                *dst = word.load(Ordering::Relaxed).to_le_bytes();
            }
            // The reads above are ordered before the check of `seq` below.
            fence(Ordering::Acquire);
            if self.seq.load(Ordering::Relaxed) == seq
            {
                return (len != 0).then_some(len.min(NAME_KEPT_MAX));
            }
        }
        None
    }
}

/// The name this process registered on its installed log cap
/// ([`install_badged_cap`]) with [`register_name`]. While one is kept, the
/// process's stream messages on that cap carry [`SENDER_NAMED`], and
/// [`log_call`] sends the name again to a receiver that answers
/// [`NAME_UNKNOWN`].
// restore: none
static REGISTERED_NAME: NameCell = NameCell::new();

/// The `STREAM_REGISTER_NAME` message carrying `name`, cut at
/// [`CHUNK_SIZE`] bytes.
fn name_message(name: &[u8]) -> IpcMessage
{
    let name = name.get(..CHUNK_SIZE).unwrap_or(name);
    let label = STREAM_REGISTER_NAME | ((name.len() as u64 & 0xFFFF) << 16);
    IpcMessage::builder(label).bytes(0, name).build()
}

/// [`SENDER_NAMED`] for a stream message on `cap` when `cap` is the
/// process's installed log cap and the process registered a name on it; 0
/// otherwise, a cap a caller passes for another endpoint included.
fn named_flag(cap: u64) -> u64
{
    if cap == BADGEED_CAP.load(Ordering::Acquire) && REGISTERED_NAME.is_set()
    {
        SENDER_NAMED
    }
    else
    {
        0
    }
}

// ── Process-global cap cache ────────────────────────────────────────────────

/// Badged SEND cap on the log endpoint, pre-installed at process
/// startup via [`install_badged_cap`]. Zero when no logger is
/// reachable (a process spawned before the log endpoint exists);
/// [`emit`] drops in that case. `AtomicU64` because a cap handle is `u64` in
/// the syscall ABI.
// restore: rebound
static BADGEED_CAP: AtomicU64 = AtomicU64::new(0);

/// Pre-install a badged SEND cap on the log endpoint. Called by
/// std's `_start` with the cap procmgr seeded in
/// `ProcessInfo.log_send_cap`. Idempotent — last writer wins.
pub fn install_badged_cap(cap: u64)
{
    BADGEED_CAP.store(cap, Ordering::Release);
}

/// Rebind the log surface to the process a restore created
/// (docs/checkpoint-restore.md § Restore entry and handle rebinding): install
/// `cap`, the new process's badged SEND, and forget what was learned of the
/// captured process's receiver. The registered name is kept: the new
/// receiver answers [`NAME_UNKNOWN`] and [`log_call`] sends it again.
// restore: reset
pub fn rebind_log(cap: u64)
{
    BADGEED_CAP.store(cap, Ordering::Release);
    RECEIVER_UNANSWERED.store(false, Ordering::Relaxed);
}

/// Return the pre-installed badged SEND cap, or zero. Caller is
/// expected to have set it via [`install_badged_cap`] before the
/// first log call. `_ipc_buf` is unused.
pub fn ensure_badged_cap(_ipc_buf: *mut u64) -> u64
{
    BADGEED_CAP.load(Ordering::Acquire)
}

// ── Process-global level filter ─────────────────────────────────────────────

/// The most verbose level [`emit`] sends, an `ipc::stream_labels::LEVEL_*`
/// code; a message at a more verbose level is neither formatted nor sent.
/// [`LEVEL_INFO`] until std's `_start` installs the level the process's
/// `SERAPH_LOG` environment entry names ([`set_max_level`]).
// restore: none
static MAX_LEVEL: AtomicU64 = AtomicU64::new(LEVEL_INFO);

/// The environment entry std's `_start` reads, once, for the process's
/// [`MAX_LEVEL`]; its value is a [`parse_level`] name.
pub const LEVEL_ENV_KEY: &[u8] = b"SERAPH_LOG";

/// Set the most verbose level [`emit`] sends. Called by std's `_start`.
pub fn set_max_level(level: u64)
{
    MAX_LEVEL.store(rank(level), Ordering::Relaxed);
}

/// Whether [`emit`] sends a message at `level`.
#[must_use]
pub fn enabled(level: u64) -> bool
{
    rank(level) <= MAX_LEVEL.load(Ordering::Relaxed)
}

/// The level a `SERAPH_LOG` value names, one of the eight RFC 5424
/// severities: `emergency`, `alert`, `critical`, `error`, `warn`,
/// `notice`, `info`, or `debug`; `None` for any other value.
#[must_use]
pub fn parse_level(name: &[u8]) -> Option<u64>
{
    match name
    {
        b"emergency" => Some(LEVEL_EMERGENCY),
        b"alert" => Some(LEVEL_ALERT),
        b"critical" => Some(LEVEL_CRITICAL),
        b"error" => Some(LEVEL_ERROR),
        b"warn" => Some(LEVEL_WARN),
        b"notice" => Some(LEVEL_NOTICE),
        b"info" => Some(LEVEL_INFO),
        b"debug" => Some(LEVEL_DEBUG),
        _ => None,
    }
}

/// The process's level: the most verbose level [`emit`] sends, an
/// `ipc::stream_labels::LEVEL_*` code from [`LEVEL_EMERGENCY`] to [`LEVEL_DEBUG`].
#[must_use]
pub fn max_level() -> u64
{
    MAX_LEVEL.load(Ordering::Relaxed)
}

/// The [`parse_level`] name of `level`; `None` for a code outside
/// [`LEVEL_EMERGENCY`] to [`LEVEL_DEBUG`].
fn level_name(level: u64) -> Option<&'static [u8]>
{
    match level
    {
        LEVEL_EMERGENCY => Some(b"emergency"),
        LEVEL_ALERT => Some(b"alert"),
        LEVEL_CRITICAL => Some(b"critical"),
        LEVEL_ERROR => Some(b"error"),
        LEVEL_WARN => Some(b"warn"),
        LEVEL_NOTICE => Some(b"notice"),
        LEVEL_INFO => Some(b"info"),
        LEVEL_DEBUG => Some(b"debug"),
        _ => None,
    }
}

/// The longest entry [`level_entry`] writes: `SERAPH_LOG=emergency`, the
/// longest name, and its terminating NUL.
pub const LEVEL_ENTRY_MAX: usize = LEVEL_ENV_KEY.len() + 1 + b"emergency".len() + 1;

/// Write the environment entry that sets a process's level to `level`,
/// `SERAPH_LOG=<name>` and its terminating NUL, the form of one entry of an
/// env blob (`services/logd/docs/ipc-interface.md` § Levels), into the start
/// of `out`. Returns the entry's length, NUL included; `None`, writing
/// nothing, for a code [`parse_level`] names no level for or an `out` shorter
/// than the entry ([`LEVEL_ENTRY_MAX`] always suffices).
pub fn level_entry(level: u64, out: &mut [u8]) -> Option<usize>
{
    let parts: [&[u8]; 4] = [LEVEL_ENV_KEY, b"=", level_name(level)?, b"\0"];
    let len = parts.iter().map(|p| p.len()).sum();
    let entry = out.get_mut(..len)?;
    for (dst, &src) in entry.iter_mut().zip(parts.iter().copied().flatten())
    {
        *dst = src;
    }
    Some(len)
}

/// `level` as an order of verbosity: the codes [`LEVEL_EMERGENCY`] to
/// [`LEVEL_DEBUG`], the RFC 5424 severities, are already in that order, and
/// any other code reads as [`LEVEL_INFO`], as a receiver reads it.
fn rank(level: u64) -> u64
{
    level_or_info(level)
}

// ── Wire-format primitives ──────────────────────────────────────────────────

/// The `STREAM_BYTES` label of a chunk of `len` bytes at `level`, a
/// `ipc::stream_labels::LEVEL_*` code (a code past the eight sent as none,
/// which a receiver reads as informational).
fn stream_label(len: usize, level: u64) -> u64
{
    labelled(STREAM_BYTES, len, level)
}

/// The `STREAM_RECORD` label of a record of `len` bytes at `level`.
fn record_label(len: usize, level: u64) -> u64
{
    labelled(STREAM_RECORD, len, level)
}

/// `id` with a payload length in bits 16-31 and `level` in the level field
/// (`ipc::stream_labels::level_bits`).
fn labelled(id: u64, len: usize, level: u64) -> u64
{
    id | ((len as u64 & 0xFFFF) << 16) | level_bits(level)
}

/// Send `bytes` at `level` (an `ipc::stream_labels::LEVEL_*` code) as one or
/// more `STREAM_BYTES` messages on `cap`. Splits across IPC calls when the
/// payload exceeds [`CHUNK_SIZE`]; the receiver concatenates the bytes of
/// answered calls in order, and a line takes the level of the chunk carrying
/// its first byte.
/// Silently drops on a zero `cap`, null `ipc_buf`, empty `bytes`, or
/// mid-chunk IPC failure, a call the receiver leaves unanswered for
/// its bound ([`LOG_CALL_TIMEOUT_MS`]) among them: the chunks after the
/// failed one are not sent, and the failed one's bytes are dropped unless the
/// receiver had already received them ([`LOG_CALL_TIMEOUT_MS`]).
///
/// # Safety
/// `ipc_buf` must be null or point to the calling thread's 4 KiB-aligned IPC
/// buffer page as registered via `syscall::ipc_buffer_set` (the contract of
/// `ipc::ipc_call`).
pub unsafe fn write_bytes(cap: u64, ipc_buf: *mut u64, level: u64, bytes: &[u8])
{
    // SAFETY: the caller's contract covers `ipc_buf`.
    let _ = unsafe { send_bytes(cap, ipc_buf, level, bytes) };
}

/// [`write_bytes`], reporting whether every chunk's call was answered: `false`
/// on a zero `cap`, a null `ipc_buf`, or a failed call. The chunks after a
/// failed call are not sent; a chunk whose call timed out may still have been
/// received, and then written, so a `false` does not say its bytes were
/// dropped ([`LOG_CALL_TIMEOUT_MS`]). Empty `bytes` sends nothing and succeeds.
///
/// # Safety
/// As for [`write_bytes`].
unsafe fn send_bytes(cap: u64, ipc_buf: *mut u64, level: u64, bytes: &[u8]) -> bool
{
    if cap == 0 || ipc_buf.is_null()
    {
        return false;
    }
    let named = named_flag(cap);
    for chunk in bytes.chunks(CHUNK_SIZE)
    {
        let msg = IpcMessage::builder(stream_label(chunk.len(), level) | named)
            .bytes(0, chunk)
            .build();
        // SAFETY: ipc_buf is non-null (checked above), so the caller's
        // contract makes it this thread's registered IPC buffer page.
        if !unsafe { log_call(cap, &msg, ipc_buf) }
        {
            return false;
        }
    }
    true
}

/// Send `record`, a record's payload (`ipc::log_record`), at `level` as one
/// `STREAM_RECORD` message on `cap`. A record fits one message, so nothing
/// is split. Silently drops on a zero `cap`, a null `ipc_buf`, or an IPC
/// failure, a call unanswered within its bound among them, unless the receiver
/// had already received the record ([`LOG_CALL_TIMEOUT_MS`]); the receiver's
/// reply, `RECORD_REJECTED` for a payload that is not a record, is
/// not reported.
///
/// # Safety
/// `ipc_buf` must be null or point to the calling thread's 4 KiB-aligned IPC
/// buffer page as registered via `syscall::ipc_buffer_set` (the contract of
/// `ipc::ipc_call`).
pub unsafe fn write_record(cap: u64, ipc_buf: *mut u64, level: u64, record: &[u8])
{
    if cap == 0 || ipc_buf.is_null()
    {
        return;
    }
    let record = record.get(..CHUNK_SIZE).unwrap_or(record);
    let msg = IpcMessage::builder(record_label(record.len(), level) | named_flag(cap))
        .bytes(0, record)
        .build();
    // SAFETY: ipc_buf is non-null (checked above), so the caller's contract
    // makes it this thread's registered IPC buffer page.
    let _ = unsafe { log_call(cap, &msg, ipc_buf) };
}

/// The record of `message` and `fields`, each field's value formatted with
/// `Display`. A record that does not fit is clipped as
/// `ipc::log_record::RecordWriter` describes, and a field whose key is not
/// a valid key is skipped (`seraph::log!` rejects one at compile time).
#[must_use]
pub fn build_record(
    message: core::fmt::Arguments<'_>,
    fields: &[(&str, &dyn core::fmt::Display)],
) -> RecordWriter
{
    let mut w = RecordWriter::new(message);
    for (key, value) in fields
    {
        w.field(key, format_args!("{value}"));
    }
    w
}

/// Send a `STREAM_REGISTER_NAME` message on `cap`. Names longer than
/// [`CHUNK_SIZE`] are truncated. The receiver stores the name for the
/// sender's badge, truncating it at its per-slot limit
/// (`services/logd/docs/ipc-interface.md` § `stream_labels::STREAM_REGISTER_NAME`).
/// When `cap` is the process's installed log cap ([`install_badged_cap`]),
/// the process keeps the name's first `ipc::log_query::SLOT_NAME_MAX` bytes,
/// marks its stream messages on that cap `ipc::stream_labels::SENDER_NAMED`,
/// and sends the name again to a receiver that answers one of them
/// `ipc::stream_labels::NAME_UNKNOWN`, as a restarted logd does. Of two
/// threads that register at once, either name may be the one kept, as
/// either may reach the receiver last.
///
/// # Safety
/// `ipc_buf` must be null or point to the calling thread's 4 KiB-aligned IPC
/// buffer page as registered via `syscall::ipc_buffer_set` (the contract of
/// `ipc::ipc_call`).
pub unsafe fn register_name(cap: u64, ipc_buf: *mut u64, name: &[u8])
{
    if cap == 0 || ipc_buf.is_null() || name.is_empty()
    {
        return;
    }
    if cap == BADGEED_CAP.load(Ordering::Acquire)
    {
        let _ = REGISTERED_NAME.store(name);
    }
    // SAFETY: ipc_buf is non-null (checked above), so the caller's contract
    // makes it this thread's registered IPC buffer page.
    let _ = unsafe { bounded_call(cap, &name_message(name), ipc_buf) };
}

/// Format `args` followed by a newline and emit it at `level` through
/// [`write_bytes`],
/// staging the text in a [`CHUNK_SIZE`]-byte stack buffer that is sent each
/// time it fills, so a message of any length is sent in full, newline
/// included; a failed send drops the chunks after it, and the receiver may
/// emit a long message as several lines. Non-allocating — safe to call from
/// heap-independent paths (panic handlers, pre-bootstrap diagnostics).
///
/// # Safety
/// `ipc_buf` must be null or point to the calling thread's 4 KiB-aligned IPC
/// buffer page as registered via `syscall::ipc_buffer_set` (the contract of
/// `ipc::ipc_call`).
pub unsafe fn write_args(cap: u64, ipc_buf: *mut u64, level: u64, args: core::fmt::Arguments<'_>)
{
    // SAFETY: the caller's contract covers `ipc_buf`.
    let send = |chunk: &[u8]| unsafe { send_bytes(cap, ipc_buf, level, chunk) };
    format_line(args, send);
}

/// Format `args` and a trailing newline into a [`STACK_BUF_LEN`]-byte
/// buffer, handing the buffer to `send` each time it fills and once at the
/// end. A `send` that returns `false` stops the message: nothing after it is
/// formatted or sent.
fn format_line(args: core::fmt::Arguments<'_>, send: impl FnMut(&[u8]) -> bool)
{
    use core::fmt::Write;

    struct ChunkWriter<F>
    {
        data: [u8; STACK_BUF_LEN],
        used: usize,
        send: F,
    }
    impl<F: FnMut(&[u8]) -> bool> ChunkWriter<F>
    {
        /// Hand the buffered bytes to `send` and empty the buffer.
        fn flush(&mut self) -> core::fmt::Result
        {
            let pending = self.data.get(..self.used).unwrap_or_default();
            let ok = pending.is_empty() || (self.send)(pending);
            self.used = 0;
            if ok { Ok(()) } else { Err(core::fmt::Error) }
        }
    }
    impl<F: FnMut(&[u8]) -> bool> Write for ChunkWriter<F>
    {
        fn write_str(&mut self, s: &str) -> core::fmt::Result
        {
            let mut rest = s.as_bytes();
            while !rest.is_empty()
            {
                if self.used >= self.data.len()
                {
                    self.flush()?;
                }
                let free = self.data.get_mut(self.used..).unwrap_or_default();
                let n = free.len().min(rest.len());
                for (dst, &src) in free.iter_mut().zip(rest)
                {
                    *dst = src;
                }
                // `used + n` is at most the buffer's length.
                self.used = self.used.saturating_add(n);
                rest = rest.get(n..).unwrap_or_default();
            }
            Ok(())
        }
    }

    let mut w = ChunkWriter {
        data: [0; STACK_BUF_LEN],
        used: 0,
        send,
    };
    // An Err means `send` failed; the rest of the message is dropped.
    if w.write_fmt(args).is_ok() && w.write_str("\n").is_ok()
    {
        let _ = w.flush();
    }
}

/// One-shot emit: format `args` and send it at `level` (an
/// `ipc::stream_labels::LEVEL_*` code) on the pre-installed badged SEND cap.
/// Drops a message more verbose than the process's level ([`enabled`])
/// before formatting it. Drops, in every build, when no cap is installed: a
/// process spawned before the log endpoint existed, or one given no log cap,
/// logs nowhere.
///
/// # Safety
/// `ipc_buf` must be null or point to the calling thread's 4 KiB-aligned IPC
/// buffer page as registered via `syscall::ipc_buffer_set` (the contract of
/// `ipc::ipc_call`).
pub unsafe fn emit(ipc_buf: *mut u64, level: u64, args: core::fmt::Arguments<'_>)
{
    let cap = ensure_badged_cap(ipc_buf);
    if cap == 0 || !enabled(level)
    {
        return;
    }
    // SAFETY: the caller's contract covers `ipc_buf`.
    unsafe { write_args(cap, ipc_buf, level, args) };
}

/// One-shot emit of a record: build it from `message` and `fields`
/// ([`build_record`]) and send it at `level` on the pre-installed badged
/// SEND cap. Drops a record more verbose than the process's level
/// ([`enabled`]) before formatting it, and drops, in every build, when no
/// cap is installed, as [`emit`] does. Non-allocating: the record is staged
/// in a `RECORD_MAX_BYTES` stack buffer.
///
/// # Safety
/// `ipc_buf` must be null or point to the calling thread's 4 KiB-aligned IPC
/// buffer page as registered via `syscall::ipc_buffer_set` (the contract of
/// `ipc::ipc_call`).
pub unsafe fn emit_record(
    ipc_buf: *mut u64,
    level: u64,
    message: core::fmt::Arguments<'_>,
    fields: &[(&str, &dyn core::fmt::Display)],
)
{
    let cap = ensure_badged_cap(ipc_buf);
    if cap == 0 || !enabled(level)
    {
        return;
    }
    let record = build_record(message, fields);
    // SAFETY: the caller's contract covers `ipc_buf`.
    unsafe { write_record(cap, ipc_buf, level, record.as_bytes()) };
}

#[cfg(test)]
mod tests
{
    use super::*;

    use ipc::stream_labels::RECORD_REJECTED;

    #[test]
    fn a_record_is_built_from_its_message_and_displayed_fields()
    {
        use ipc::log_record::Record;
        let reason = 0x17u64;
        let record = build_record(
            format_args!("child {} exiting", 3),
            &[("code", &reason), ("name", &"a b=c")],
        );
        let rec = Record::decode(record.as_bytes()).expect("a record");
        assert_eq!(rec.message(), b"child 3 exiting");
        let fields: Vec<(&[u8], &[u8])> = rec.fields().map(|f| (f.key, f.value)).collect();
        assert_eq!(fields, [(&b"code"[..], &b"23"[..]), (b"name", b"a b=c")]);
    }

    #[test]
    fn a_timeout_shortens_later_log_calls_until_one_is_answered()
    {
        let timeout: Result<(), i64> = Err(SyscallError::WouldBlock as i64);
        let other: Result<(), i64> = Err(SyscallError::InvalidCapability as i64);
        let answered: Result<(), i64> = Ok(());
        let own = Bound::Receiver(LOG_CALL_TIMEOUT_MS);

        assert_eq!(call_bound(false, None), Some(own));
        assert_eq!(
            call_bound(true, None),
            Some(Bound::Receiver(LOG_CALL_UNANSWERED_TIMEOUT_MS))
        );

        // A timeout sets the flag, from either state.
        assert!(unanswered_after(false, own, &timeout));
        assert!(unanswered_after(true, own, &timeout));
        // An answer clears it, from either state.
        assert!(!unanswered_after(true, own, &answered));
        assert!(!unanswered_after(false, own, &answered));
        // Any other failure leaves it as it was.
        assert!(unanswered_after(true, own, &other));
        assert!(!unanswered_after(false, own, &other));
    }

    // The defect caught: a log call made inside a call deadline that outlives
    // it, or that is made once it has passed; and a timeout at the caller's
    // deadline read as the receiver's silence, which would cut every later
    // log call of the process to the short bound.
    #[test]
    fn a_call_deadline_bounds_a_log_call_and_its_timeout_blames_no_receiver()
    {
        let timeout: Result<(), i64> = Err(SyscallError::WouldBlock as i64);
        let ms = Duration::from_millis;

        // A deadline nearer than the call's own bound bounds the call.
        assert_eq!(call_bound(false, Some(ms(30))), Some(Bound::Deadline(30)));
        assert_eq!(call_bound(true, Some(ms(3))), Some(Bound::Deadline(3)));
        // A farther one leaves the call's own bound.
        assert_eq!(
            call_bound(false, Some(ms(60_000))),
            Some(Bound::Receiver(LOG_CALL_TIMEOUT_MS))
        );
        assert_eq!(
            call_bound(true, Some(ms(30))),
            Some(Bound::Receiver(LOG_CALL_UNANSWERED_TIMEOUT_MS))
        );
        // A passed deadline makes no call.
        assert_eq!(call_bound(false, Some(Duration::ZERO)), None);

        // A timeout at the deadline leaves the flag as it was.
        assert!(!unanswered_after(false, Bound::Deadline(30), &timeout));
        assert!(unanswered_after(true, Bound::Deadline(3), &timeout));
        // An answer within it still clears the flag.
        assert!(!unanswered_after(
            true,
            Bound::Deadline(3),
            &Ok::<(), i64>(())
        ));
    }

    // Defect caught: the lines svcmgr holds for the death of a log sink that
    // died while it received nothing (in its handover from init-logd) dropped
    // by the restarted sink. A line of svcmgr's written while no receiver
    // received timed out, so every later call took the short bound, which the
    // restarted sink's start outlasts, and each held line timed out in turn.
    #[test]
    fn a_restarted_receiver_gets_the_full_bound_after_a_dead_one_timed_out()
    {
        let timeout = || Err::<(), i64>(SyscallError::WouldBlock as i64);
        // A receiver that starts receiving `start_ms` after a call is made:
        // it answers a call whose bound outlasts its start.
        let starting = |start_ms: u32| {
            move |bound: u32| {
                if bound > start_ms { Ok(()) } else { timeout() }
            }
        };
        // The restarted logd of the failed boot started receiving about 50 ms
        // after svcmgr wrote its first held line.
        let start_ms = 50;
        assert!(LOG_CALL_UNANSWERED_TIMEOUT_MS < start_ms && start_ms < LOG_CALL_TIMEOUT_MS);

        // A line written while no receiver receives times out.
        assert_eq!(bounded(None, |_| timeout()), None);
        // Its timeout shortens the next call below the restarted receiver's
        // start: the line is dropped.
        assert_eq!(bounded(None, starting(start_ms)), None);
        // Told of the restart, the process waits the full bound for the next
        // line, which the restarted receiver answers, and later lines keep the
        // full bound.
        receiver_restarted();
        assert_eq!(bounded(None, starting(start_ms)), Some(()));
        assert_eq!(bounded(None, starting(start_ms)), Some(()));
        assert!(!RECEIVER_UNANSWERED.load(Ordering::Relaxed));
    }

    #[test]
    fn a_record_label_carries_its_length_and_level()
    {
        use ipc::stream_labels::{LEVEL_ERROR, level_of};
        let label = record_label(37, LEVEL_ERROR);
        assert_eq!(label & 0xFFFF, STREAM_RECORD);
        assert_eq!((label >> 16) & 0xFFFF, 37);
        assert_eq!(level_of(label), LEVEL_ERROR);
    }

    /// Format `args` through [`format_line`], recording each chunk sent;
    /// `fail_at` makes that send (0-based) fail.
    fn chunks_of(args: core::fmt::Arguments<'_>, fail_at: Option<usize>) -> Vec<Vec<u8>>
    {
        let mut sent = Vec::new();
        format_line(args, |chunk| {
            if fail_at == Some(sent.len())
            {
                return false;
            }
            sent.push(chunk.to_vec());
            true
        });
        sent
    }

    #[test]
    fn a_message_longer_than_the_buffer_arrives_whole_with_its_newline()
    {
        let long = "x".repeat(3 * STACK_BUF_LEN + 7);
        let sent = chunks_of(format_args!("{long}"), None);
        assert!(sent.iter().all(|c| c.len() <= STACK_BUF_LEN));
        let joined: Vec<u8> = sent.concat();
        assert_eq!(joined.len(), long.len() + 1);
        assert_eq!(&joined[..long.len()], long.as_bytes());
        assert_eq!(joined.last(), Some(&b'\n'));
    }

    #[test]
    fn a_message_that_exactly_fills_the_buffer_keeps_its_newline()
    {
        let exact = "y".repeat(STACK_BUF_LEN);
        let sent = chunks_of(format_args!("{exact}"), None);
        assert_eq!(sent.len(), 2);
        assert_eq!(sent[1], b"\n");
    }

    #[test]
    fn a_chunk_label_carries_its_length_and_level()
    {
        use ipc::stream_labels::{LEVEL_SHIFT, level_of};
        let label = stream_label(CHUNK_SIZE, LEVEL_WARN);
        assert_eq!(label & 0xFFFF, STREAM_BYTES);
        assert_eq!((label >> 16) & 0xFFFF, CHUNK_SIZE as u64);
        assert_eq!(level_of(label), LEVEL_WARN);
        // A code past the eight is sent as none, read as info, and cannot
        // reach the bits above the level field.
        assert_eq!(level_of(stream_label(1, u64::MAX)), LEVEL_INFO);
        assert_eq!(stream_label(1, u64::MAX) >> LEVEL_SHIFT, 0);
        assert_eq!(level_of(stream_label(1, LEVEL_EMERGENCY)), LEVEL_EMERGENCY);
    }

    #[test]
    fn the_eight_level_names_parse_and_anything_else_does_not()
    {
        assert_eq!(parse_level(b"emergency"), Some(LEVEL_EMERGENCY));
        assert_eq!(parse_level(b"alert"), Some(LEVEL_ALERT));
        assert_eq!(parse_level(b"critical"), Some(LEVEL_CRITICAL));
        assert_eq!(parse_level(b"error"), Some(LEVEL_ERROR));
        assert_eq!(parse_level(b"warn"), Some(LEVEL_WARN));
        assert_eq!(parse_level(b"notice"), Some(LEVEL_NOTICE));
        assert_eq!(parse_level(b"info"), Some(LEVEL_INFO));
        assert_eq!(parse_level(b"debug"), Some(LEVEL_DEBUG));
        // The scale has no level past debug.
        assert_eq!(parse_level(b"trace"), None);
        assert_eq!(parse_level(b"WARN"), None);
        assert_eq!(parse_level(b""), None);
    }

    // Defect caught: an entry a child's `_start` would not parse back to the
    // level its spawner meant, so the child logs at another level.
    #[test]
    fn a_level_entry_parses_back_to_its_level()
    {
        for level in [
            LEVEL_EMERGENCY,
            LEVEL_ALERT,
            LEVEL_CRITICAL,
            LEVEL_ERROR,
            LEVEL_WARN,
            LEVEL_NOTICE,
            LEVEL_INFO,
            LEVEL_DEBUG,
        ]
        {
            let mut out = [0xAAu8; LEVEL_ENTRY_MAX + 4];
            let n = level_entry(level, &mut out).expect("a level's entry");
            assert!(n <= LEVEL_ENTRY_MAX);
            let entry = &out[..n];
            assert_eq!(entry.last(), Some(&0));
            let body = &entry[..n - 1];
            assert!(!body.contains(&0));
            let value = body
                .strip_prefix(LEVEL_ENV_KEY)
                .and_then(|r| r.strip_prefix(b"="))
                .expect("key=value");
            assert_eq!(parse_level(value), Some(level));
            // Nothing past the entry is written.
            assert!(out[n..].iter().all(|&b| b == 0xAA));
        }
        let mut out = [0u8; LEVEL_ENTRY_MAX];
        assert_eq!(
            level_entry(LEVEL_EMERGENCY, &mut out),
            Some(LEVEL_ENTRY_MAX)
        );
        assert_eq!(&out[..], b"SERAPH_LOG=emergency\0");
    }

    // Defect caught: an entry written past a short buffer, or for a code that
    // names no level.
    #[test]
    fn a_level_entry_needs_room_and_a_level()
    {
        let mut short = [0u8; LEVEL_ENTRY_MAX - 1];
        assert_eq!(level_entry(LEVEL_EMERGENCY, &mut short), None);
        assert!(short.iter().all(|&b| b == 0));
        let mut out = [0u8; LEVEL_ENTRY_MAX];
        assert_eq!(level_entry(LEVEL_DEBUG + 1, &mut out), None);
        assert_eq!(level_entry(u64::MAX, &mut out), None);
        // A shorter name fits a buffer the longest does not.
        let mut critical = [0u8; LEVEL_ENTRY_MAX - 1];
        assert_eq!(
            level_entry(LEVEL_CRITICAL, &mut critical),
            Some(LEVEL_ENTRY_MAX - 1)
        );
    }

    /// The one test that sets the process-global level, so no other test
    /// races it.
    #[test]
    fn the_filter_sends_its_level_and_every_less_verbose_one()
    {
        // The default is info.
        assert!(enabled(LEVEL_INFO) && enabled(LEVEL_NOTICE) && enabled(LEVEL_EMERGENCY));
        assert!(!enabled(LEVEL_DEBUG));
        assert_eq!(max_level(), LEVEL_INFO);
        set_max_level(LEVEL_WARN);
        assert_eq!(max_level(), LEVEL_WARN);
        assert!(enabled(LEVEL_EMERGENCY) && enabled(LEVEL_ERROR) && enabled(LEVEL_WARN));
        assert!(!enabled(LEVEL_NOTICE) && !enabled(LEVEL_INFO) && !enabled(LEVEL_DEBUG));
        // A code past the eight reads as info, as the receivers read it.
        assert!(!enabled(LEVEL_DEBUG + 1) && !enabled(u64::MAX));
        // A code past the eight sets info.
        set_max_level(LEVEL_DEBUG + 1);
        assert_eq!(max_level(), LEVEL_INFO);
        set_max_level(LEVEL_DEBUG);
        assert!(enabled(LEVEL_DEBUG) && enabled(LEVEL_DEBUG + 1));
        set_max_level(LEVEL_EMERGENCY);
        assert!(enabled(LEVEL_EMERGENCY) && !enabled(LEVEL_ALERT));
        set_max_level(LEVEL_INFO);
    }

    /// A [`deliver`] of a message labelled `label`, with `name` the
    /// process's kept name and `replies` the outcome of each call in turn
    /// (`None`: the call failed): the label of each call made, and the
    /// delivery's result.
    fn delivery(label: u64, name: Option<&[u8]>, replies: &[Option<u64>]) -> (Vec<u64>, bool)
    {
        let msg = IpcMessage::builder(label).bytes(0, b"line\n").build();
        let mut labels = Vec::new();
        let mut replies = replies.iter().copied();
        let delivered = deliver(
            &msg,
            || name.map(name_message),
            |m| {
                labels.push(m.label);
                replies
                    .next()
                    .expect("a call past the replies the test gives")
            },
        );
        (labels, delivered)
    }

    /// The label of the `STREAM_REGISTER_NAME` message carrying `name`.
    fn register_label(name: &[u8]) -> u64
    {
        STREAM_REGISTER_NAME | ((name.len() as u64) << 16)
    }

    // Defect caught: a refused line dropped, sent without the name first, or
    // refused again, so a sender's lines after a logd restart render as `[?]`
    // or are lost.
    #[test]
    fn a_refused_named_message_registers_the_name_then_is_resent_once_without_the_bit()
    {
        let named = stream_label(5, LEVEL_INFO) | SENDER_NAMED;
        let unnamed = stream_label(5, LEVEL_INFO);
        let (labels, delivered) = delivery(
            named,
            Some(b"svctest"),
            &[Some(NAME_UNKNOWN), Some(0), Some(0)],
        );
        assert_eq!(labels, [named, register_label(b"svctest"), unnamed]);
        assert!(delivered);
        // A receiver that refuses the resend too is not asked again.
        let (labels, _) = delivery(
            named,
            Some(b"svctest"),
            &[Some(NAME_UNKNOWN), Some(0), Some(NAME_UNKNOWN)],
        );
        assert_eq!(labels.len(), 3);
    }

    // Defect caught: a process that keeps no name loops on a refusal, or
    // drops the refused line instead of sending it unnamed.
    #[test]
    fn a_refused_message_with_no_name_kept_is_resent_without_a_registration()
    {
        let named = record_label(9, LEVEL_WARN) | SENDER_NAMED;
        let (labels, delivered) = delivery(named, None, &[Some(NAME_UNKNOWN), Some(0)]);
        assert_eq!(labels, [named, record_label(9, LEVEL_WARN)]);
        assert!(delivered);
    }

    // Defect caught: a failed registration that stops the resend, so the line
    // is lost, or a resend whose failure reads as delivered.
    #[test]
    fn the_resend_goes_whatever_the_registration_and_decides_the_outcome()
    {
        let named = stream_label(5, LEVEL_INFO) | SENDER_NAMED;
        let (labels, delivered) = delivery(named, Some(b"x"), &[Some(NAME_UNKNOWN), None, Some(0)]);
        assert_eq!(labels.len(), 3);
        assert!(delivered);
        let (_, delivered) = delivery(named, Some(b"x"), &[Some(NAME_UNKNOWN), Some(0), None]);
        assert!(!delivered);
    }

    // Defect caught: extra calls for a message the receiver consumed or
    // rejected for another reason, for a message from a sender that kept no
    // name (whose line a resend would duplicate), or after a failed call (a
    // wedged receiver then costs more than one bound per line).
    #[test]
    fn only_a_refusal_of_a_named_message_costs_further_calls()
    {
        let named = stream_label(5, LEVEL_INFO) | SENDER_NAMED;
        let unnamed = stream_label(5, LEVEL_INFO);
        assert_eq!(delivery(named, Some(b"x"), &[Some(0)]), (vec![named], true));
        let rejected = record_label(9, LEVEL_INFO) | SENDER_NAMED;
        assert_eq!(
            delivery(rejected, Some(b"x"), &[Some(RECORD_REJECTED)]),
            (vec![rejected], true)
        );
        assert_eq!(
            delivery(unnamed, Some(b"x"), &[Some(NAME_UNKNOWN)]),
            (vec![unnamed], true)
        );
        assert_eq!(delivery(named, Some(b"x"), &[None]), (vec![named], false));
    }

    // Defect caught: a kept name read back with another's length or bytes, or
    // past the width the receivers store, so the name sent again differs
    // from the one registered.
    #[test]
    fn a_kept_name_reads_back_as_stored_cut_at_the_receivers_width()
    {
        let cell = NameCell::new();
        let mut out = [0u8; NAME_KEPT_MAX];
        assert!(!cell.is_set());
        assert_eq!(cell.load(&mut out), None);

        assert!(cell.store(b"svctest"));
        assert!(cell.is_set());
        assert_eq!(cell.load(&mut out), Some(7));
        assert_eq!(&out[..7], b"svctest");

        let long: Vec<u8> = (0u8..=255).take(NAME_KEPT_MAX + 12).collect();
        assert!(cell.store(&long));
        assert_eq!(cell.load(&mut out), Some(NAME_KEPT_MAX));
        assert_eq!(&out[..], &long[..NAME_KEPT_MAX]);

        // A shorter name replaces a longer one whole.
        assert!(cell.store(b"ab"));
        assert_eq!(cell.load(&mut out), Some(2));
        assert_eq!(&out[..2], b"ab");
    }

    // Defect caught: a store that writes over one in progress, mixing two
    // names, or a load that takes a copy while a store writes it.
    #[test]
    fn a_store_in_progress_holds_off_another_store_and_every_load()
    {
        let cell = NameCell::new();
        let mut out = [0u8; NAME_KEPT_MAX];
        assert!(cell.store(b"first"));
        let stable = cell.seq.load(Ordering::Relaxed);
        // A store has begun: the sequence is odd.
        cell.seq.store(stable + 1, Ordering::Relaxed);
        assert!(!cell.store(b"second"));
        assert_eq!(cell.load(&mut out), None);
        // It ends without changing the name: the first stands.
        cell.seq.store(stable + 2, Ordering::Relaxed);
        assert_eq!(cell.load(&mut out), Some(5));
        assert_eq!(&out[..5], b"first");
    }

    #[test]
    fn a_short_message_is_one_chunk()
    {
        assert_eq!(
            chunks_of(format_args!("hi {}", 7), None),
            [b"hi 7\n".to_vec()]
        );
    }

    #[test]
    fn a_failed_send_drops_the_rest_of_the_message()
    {
        let long = "z".repeat(3 * STACK_BUF_LEN);
        let sent = chunks_of(format_args!("{long}"), Some(1));
        assert_eq!(sent.len(), 1);
    }
}
