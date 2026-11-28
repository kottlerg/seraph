// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/ipc/src/log_labels.rs

//! IPC labels for the system log endpoint's legacy discovery interface
//! and the one-shot init-logd → real-logd handover.
//!
//! Distinct from [`stream_labels`](crate::stream_labels): the latter carry payload (bytes,
//! names) on badged SEND caps that have already been minted; these
//! labels are spoken on caps that mediate cap acquisition or state
//! transfer.
//!
//! Every process receives a pre-installed badged SEND cap in
//! `ProcessInfo.log_send_cap` (init derives its own) and never calls
//! [`GET_LOG_CAP`]; the label is reserved, not served.

/// Legacy discovery label, reserved and not served.
///
/// Formerly requested a freshly minted badged SEND cap on the log
/// endpoint (`word(0) = LOG_LABELS_VERSION`). No caller issues it:
/// every process's badged cap arrives pre-installed in
/// `ProcessInfo.log_send_cap`. Init-logd and real-logd answer it
/// with an empty reply carrying no cap, so an out-of-tree caller
/// fails closed (see `services/logd/docs/ipc-interface.md`).
pub const GET_LOG_CAP: u64 = 12;

/// Handover drain: real-logd pulls init-logd's captured state.
///
/// Sent by real-logd, one chunk per call, on the single-use SEND cap
/// on the master log endpoint that svcmgr mints it for its first
/// launch (bootstrap `cap[1]`); init-logd still holds the endpoint's
/// RECV and serves every other sender between pulls. The replies
/// carry, in order:
///
/// * A header — the total history-entry count and the active slot
///   count.
/// * The badge table — for every active sender badge init-logd
///   has seen, the `(badge, display_name)` pair, and again for each
///   slot whose name changed after the table was sent.
/// * The captured-history ring — the complete text lines and records
///   init-logd still holds, oldest first, attributed by badge and
///   timestamped at the original receipt instant.
///
/// Wire encoding is documented in
/// `services/logd/docs/handover-protocol.md` and defined in
/// `logd-codec` (`services/logd/codec`). The data drain (`MORE`/`DONE`
/// chunks) only transfers state; init-logd's thread terminates on an
/// acknowledged [`HANDOVER_RELEASE`], not on the `DONE` chunk.
pub const HANDOVER_PULL: u64 = 13;

/// Terminal release: real-logd tells init-logd to exit.
///
/// Sent by real-logd on the same single-use SEND cap after its
/// [`HANDOVER_PULL`] drain settles (whether the drain ran to `DONE`,
/// aborted on an IPC error, or hit its iteration cap); a call that
/// fails is retried, within a wall-clock budget, until one is delivered
/// (see `services/logd/docs/handover-protocol.md` § Termination).
/// Init-logd replies with a status in the label:
///
/// * `RELEASE_ACK` (0) — it sets its handover-complete flag and
///   `sys_thread_exit`s on its next loop iteration.
/// * `RELEASE_PENDING` (1) — a display name changed after its slot was
///   sent; init-logd keeps serving, and real-logd drains again with
///   [`HANDOVER_PULL`] before it repeats the release. Init-logd defers
///   a bounded number of times (`MAX_RELEASE_DEFERRALS`) and then
///   acknowledges.
///
/// See `services/logd/docs/handover-protocol.md` § Name changes during
/// the drain.
///
/// Decoupling termination from the multi-chunk data drain keeps a
/// dropped data chunk (a kernel IPC rendezvous race on the shared,
/// multi-sender log endpoint) from wedging init-logd — which would
/// otherwise block procmgr's reap of init's Memory caps indefinitely.
pub const HANDOVER_RELEASE: u64 = 14;

/// Badge bit on a SEND on the master log endpoint that authorises
/// [`QUERY_SLOTS`], [`QUERY_HISTORY`] and [`LOG_SUBSCRIBE`], the last from
/// the pool of `SUBSCRIBERS_MAX` subscriptions. svcmgr mints it, with
/// `GRANT` for [`LOG_SUBSCRIBE`]'s signal, from its master-log source
/// and publishes it seed-only as [`crate::published_names::LOGD_QUERY`]. No
/// sender's badge carries it:
/// procmgr redraws a process badge carrying a
/// [`crate::VERB_BIT_MASK`] bit, and the reserved
/// [`crate::log_badges`] carry none.
pub const LOG_QUERY_AUTHORITY: u64 = 1u64 << 63;

/// Read logd's sender slots: its badge table and its retired slots,
/// ascending by badge and then state, a page of up to
/// [`crate::log_query::SLOTS_PAGE`] entries per call, each the badge, its
/// state (live, or evicted by a death with its exit reason, or by a
/// resync), its display name, its slot serial and its name generation.
/// Served only on a badge carrying [`LOG_QUERY_AUTHORITY`] or
/// [`LOG_FOLLOW_AUTHORITY`]. Wire format: [`crate::log_query`]; specified
/// in `services/logd/docs/ipc-interface.md` § Queries.
pub const QUERY_SLOTS: u64 = 16;

/// Read logd's history, newest first or oldest first from a `seq`: every
/// slot's entries or one badge's, at every level or at a level and the more
/// severe, as many whole entries per call as one reply holds, each its
/// sequence, receipt time, slot serial, level, kind, origin, name generation,
/// and bytes. Served only on a badge carrying [`LOG_QUERY_AUTHORITY`] or
/// [`LOG_FOLLOW_AUTHORITY`]. Wire format: [`crate::log_query`]; specified in
/// `services/logd/docs/ipc-interface.md` § Queries.
pub const QUERY_HISTORY: u64 = 17;

/// Badge bit on a SEND on the master log endpoint that authorises
/// [`LOG_FLUSH`]. svcmgr mints it from its master-log source and publishes it
/// seed-only as [`crate::published_names::LOGD_FLUSH`]. No sender's badge
/// carries it, as for [`LOG_QUERY_AUTHORITY`].
pub const LOG_FLUSH_AUTHORITY: u64 = 1u64 << 62;

/// The flush barrier: ask whether every line logd took before the call is
/// written by the sinks that hold the log, so that the caller can power the
/// system off without losing them. logd answers at once with a token and
/// `FLUSHED` or `FLUSH_PENDING` with a retry hint, and the caller asks again
/// with the token until it is flushed or its own bound passes. Served only
/// on a badge carrying [`LOG_FLUSH_AUTHORITY`]. Wire format:
/// [`crate::log_flush`]; specified in `services/logd/docs/ipc-interface.md`
/// § Flush barrier.
pub const LOG_FLUSH: u64 = 18;

/// Badge bit on a SEND on the master log endpoint that authorises the reads
/// [`LOG_QUERY_AUTHORITY`] does and [`LOG_SUBSCRIBE`] from the pool of
/// `SINK_SUBSCRIBERS_MAX` subscriptions, which no holder of
/// [`LOG_QUERY_AUTHORITY`] can take, kept for the external sinks. svcmgr
/// mints it with `GRANT` from its master-log source and publishes it
/// seed-only as [`crate::published_names::LOGD_FOLLOW`]. No sender's badge
/// carries it, as for [`LOG_QUERY_AUTHORITY`].
pub const LOG_FOLLOW_AUTHORITY: u64 = 1u64 << 60;

/// Follow the history: the request moves logd a signal, a capability to a
/// Notification logd signals each time it retains an entry. The reply carries
/// the subscription's token, a capability to an object of logd's whose
/// deletion ends the subscription, its index, the instance epoch, and the
/// oldest and the next `seq`. A full pool is refused. Served
/// only on a badge carrying [`LOG_QUERY_AUTHORITY`] or
/// [`LOG_FOLLOW_AUTHORITY`], each its own pool. Wire format:
/// [`crate::log_query`]; specified in `services/logd/docs/ipc-interface.md`
/// § Subscriptions.
pub const LOG_SUBSCRIBE: u64 = 19;

/// Badge bit on a SEND on the master log endpoint that authorises
/// [`SINK_LIST`] and [`SINK_SET`]. svcmgr mints it from its master-log
/// source and publishes it seed-only as
/// [`crate::published_names::LOGD_CONTROL`]. No sender's badge carries it, as
/// for [`LOG_QUERY_AUTHORITY`].
pub const LOG_CONTROL_AUTHORITY: u64 = 1u64 << 61;

/// List logd's device sinks, one per call by index: each its name, its
/// settings in the recipe's syntax, its cursor, its drop count and its state
/// (served, unserved, stalled). Served only on a badge carrying
/// [`LOG_CONTROL_AUTHORITY`]. Wire format: [`crate::log_control`]; specified
/// in `services/logd/docs/ipc-interface.md` § Sink control.
pub const SINK_LIST: u64 = 20;

/// Change a device sink's settings: its name and a settings string in the
/// recipe's syntax, applied over the sink's settings, or refused whole when
/// it does not parse. Served only on a badge carrying
/// [`LOG_CONTROL_AUTHORITY`]. Wire format: [`crate::log_control`]; specified
/// in `services/logd/docs/ipc-interface.md` § Sink control.
pub const SINK_SET: u64 = 21;
