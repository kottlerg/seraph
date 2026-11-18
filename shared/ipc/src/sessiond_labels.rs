// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/ipc/src/sessiond_labels.rs

//! sessiond's labels (services/sessiond/docs/ipc-interface.md): an interface
//! registers itself and opens operator sessions, and a stop-authority holder
//! lists and stops the programs of those sessions
//! (docs/session-supervision.md).
//!
//! sessiond serves every label on the one endpoint its recipe provides, as
//! [`crate::published_names::SESSIOND_OPERATOR`], badged
//! [`OPERATOR_AUTHORITY`]: the interface labels on a badge carrying that bit,
//! and [`crate::stop_labels`] on a badge carrying
//! [`crate::stop_labels::STOP_AUTHORITY`], which only the SEND svcmgr hands a
//! stop-authority holder carries. Each refuses every other badge with
//! [`UNAUTHORIZED`]. The interface labels avoid the stop labels' values.
//!
//! An interface names itself by a nonce, a random nonzero value it draws and
//! registers ([`REGISTER_INTERFACE`]); the nonce confers nothing beyond the
//! badge the call carries. A session is named, to its interface and to a
//! stop-authority holder alike, by its key: a value with bit 63 set, which
//! no procmgr process badge carries, so a stop-authority holder's key names
//! a session or, without that bit, a job (a child of a session's leader) by
//! its process badge.

/// The badge of the SEND svcmgr publishes under
/// [`crate::published_names::SESSIOND_OPERATOR`] (the recipe's `:grant`
/// entry): the authority to open operator sessions.
pub const OPERATOR_AUTHORITY: u64 = 1u64 << 63;

const _: () = core::assert!(
    OPERATOR_AUTHORITY & crate::VERB_BIT_MASK != 0
        && OPERATOR_AUTHORITY & crate::stop_labels::STOP_AUTHORITY == 0
);

/// Register an interface: `data[0]` its nonce, nonzero, `data[1]`
/// [`crate::SESSIOND_LABELS_VERSION`], `caps[0]` a RECV cap on the end
/// queue the interface registered on itself with procmgr
/// (`procmgr_labels::REGISTER_END_QUEUE`). sessiond ends the interface's
/// sessions when the queue receives the interface's end. Replies
/// [`SUCCESS`]; [`VERSION_MISMATCH`]; [`INVALID_ARGUMENT`] for a zero or
/// registered nonce or no cap; [`TABLE_FULL`] when no interface slot is
/// free. The cap of a refused request is deleted.
pub const REGISTER_INTERFACE: u64 = 1;

/// Open a session for the interface whose nonce is `data[0]`: `caps[0]` a
/// POST cap on an event queue of the interface's, which becomes the
/// leader's death relay. sessiond makes the session's budget node and
/// creates the leader, suspended, contained and charged to that node.
/// Replies [`SUCCESS`] with `data[0]` the session's key; [`UNKNOWN_INTERFACE`]
/// when no interface holds the nonce (sessiond restarted since it
/// registered); [`MEMORY_CRITICAL`] while memmgr's pressure level reads
/// `CRITICAL`; [`TABLE_FULL`]; [`INVALID_ARGUMENT`] without a cap;
/// [`CREATE_FAILED`] when the node or the leader is not made, with
/// `data[0]` the label of memmgr's or procmgr's refusal, or 0 for a step of
/// sessiond's own (the lookup of the leader's binary, a derivation). On every
/// refusal no leader exists: the relay is deleted, or posted when a leader
/// made was destroyed again (a death binding failed).
pub const OPEN_SESSION: u64 = 2;

/// Install one of the leader's standard streams: `data[0]` the nonce,
/// `data[1]` the session's key, `data[2]` the direction
/// (`procmgr_labels::PIPE_DIR_STDIN`, `PIPE_DIR_STDOUT` or
/// `PIPE_DIR_STDERR`), `data[3]` the ring capacity, and `caps[0..3]` the
/// ring's memory cap and its data and space notifications, which sessiond
/// passes to procmgr as `procmgr_labels::CONFIGURE_PIPE` on the leader.
/// Replies [`SUCCESS`]; [`UNKNOWN_INTERFACE`]; [`NO_SESSION`] when the key
/// names no session of the interface that has not started;
/// [`INVALID_ARGUMENT`] for a direction past `PIPE_DIR_STDERR` or a cap
/// missing; [`CREATE_FAILED`] with `data[0]` procmgr's error. The caps
/// are moved or deleted whatever the reply, and a refusal other than
/// [`UNKNOWN_INTERFACE`] and [`NO_SESSION`] ends the session, its relay
/// then posted.
pub const SESSION_STDIO: u64 = 3;

/// Start the session the key in `data[1]` names, of the interface whose
/// nonce is `data[0]`: sessiond hands the leader its own namespace root
/// and starts it. Replies [`SUCCESS`]; [`UNKNOWN_INTERFACE`];
/// [`NO_SESSION`]; [`CREATE_FAILED`] with `data[0]` procmgr's error, the
/// session then ended and its relay posted.
pub const START_SESSION: u64 = 4;

/// The reply label of a handled request.
pub const SUCCESS: u64 = 0;
/// The badge carries neither [`OPERATOR_AUTHORITY`] nor, for the stop
/// labels, `stop_labels::STOP_AUTHORITY`. Equal to
/// `stop_labels::UNAUTHORIZED`.
pub const UNAUTHORIZED: u64 = 1;
/// No registered interface holds the nonce: the interface registers again.
pub const UNKNOWN_INTERFACE: u64 = 2;
/// [`OPEN_SESSION`]: memory is critical. The interface waits for the level
/// to change and asks again.
pub const MEMORY_CRITICAL: u64 = 3;
/// No interface or session slot is free.
pub const TABLE_FULL: u64 = 4;
/// A request's words or caps are out of protocol.
pub const INVALID_ARGUMENT: u64 = 5;
/// memmgr or procmgr refused a step; `data[0]` carries its error.
pub const CREATE_FAILED: u64 = 6;
/// The key names no session of the interface that has not started.
pub const NO_SESSION: u64 = 7;
/// [`REGISTER_INTERFACE`]: `data[1]` is not
/// [`crate::SESSIOND_LABELS_VERSION`].
pub const VERSION_MISMATCH: u64 = 8;
/// The label is none of sessiond's.
pub const UNKNOWN_OPCODE: u64 = 9;

const _: () = core::assert!(
    UNAUTHORIZED == crate::stop_labels::UNAUTHORIZED
        && REGISTER_INTERFACE != crate::stop_labels::STOP_CANDIDATE
        && REGISTER_INTERFACE != crate::stop_labels::LIST_CANDIDATES
        && OPEN_SESSION != crate::stop_labels::STOP_CANDIDATE
        && OPEN_SESSION != crate::stop_labels::LIST_CANDIDATES
        && SESSION_STDIO != crate::stop_labels::STOP_CANDIDATE
        && SESSION_STDIO != crate::stop_labels::LIST_CANDIDATES
        && START_SESSION != crate::stop_labels::STOP_CANDIDATE
        && START_SESSION != crate::stop_labels::LIST_CANDIDATES
);
