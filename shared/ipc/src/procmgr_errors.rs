// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/ipc/src/procmgr_errors.rs

//! Error replies from procmgr.

/// Request handled.
pub const SUCCESS: u64 = 0;
/// ELF image validation failed.
pub const INVALID_ELF: u64 = 1;
/// Out of memory during process creation.
pub const OUT_OF_MEMORY: u64 = 2;
/// `START_PROCESS`: configuring the child's main thread
/// (`thread_configure_with_tls`) failed.
pub const THREAD_CONFIGURE_FAILED: u64 = 3;
/// Process handle badge not found in process table.
pub const INVALID_BADGE: u64 = 4;
/// Attempt to start a process that was already started.
pub const ALREADY_STARTED: u64 = 5;
/// `START_PROCESS`: starting the child's main thread (`thread_start`)
/// failed with an error other than `Interrupted`, which procmgr retries.
pub const THREAD_START_FAILED: u64 = 6;
/// Invalid argument to an IPC request.
pub const INVALID_ARGUMENT: u64 = 7;
/// File not found while walking a namespace cap on the spawner side.
/// Reserved for callers that want a structured error before issuing
/// `CREATE_FROM_FILE`.
pub const FILE_NOT_FOUND: u64 = 9;
/// I/O error during `CREATE_FROM_FILE`: the `FS_OPEN` of the supplied
/// file cap failed, or a read through procmgr's open of it did
/// (services/procmgr/docs/ipc-interface.md § Label 13).
pub const IO_ERROR: u64 = 10;
/// `mem_map` or scratch mapping failed during ELF page load.
pub const MAP_FAILED: u64 = 11;
/// Cap rights derivation failed (e.g. `derive_memory_for_prot`)
/// during ELF page load.
pub const INSUFFICIENT_RIGHTS: u64 = 12;
/// Caller's cap lacks the required authority badge for a gated
/// label (`REGISTER_DEATH_EQ` requires `DEATH_EQ_AUTHORITY`,
/// `RELEASE_HOLD` requires `HOLD_RELEASE_AUTHORITY`).
pub const UNAUTHORIZED: u64 = 13;
/// A create with `procmgr_labels::CREATE_ARGV_ENV` failed because procmgr
/// could not unmap a window it copied the argv and env through, so it may
/// still map pages of the caller's argv/env run. The caller MUST NOT
/// return that run to memmgr (`RELEASE_MEMORY_CAPS`); it stays charged to
/// the caller until it exits. Specified in
/// `services/procmgr/docs/ipc-interface.md` § Label 1: `CREATE_PROCESS`
/// (**argv and env**).
pub const ARGV_ENV_STILL_MAPPED: u64 = 14;
/// `procmgr_labels::ATTACH_PROCESS` or `procmgr_labels::REGISTER_THREAD`
/// refused: the target, or the sender, declared itself undebuggable
/// (`procmgr_labels::DECLARE_NO_DEBUG`).
pub const NOT_ATTACHABLE: u64 = 15;
/// `procmgr_labels::REGISTER_CRASH_SERVICE` refused: a registered crash
/// service still lives.
pub const CRASH_SERVICE_PRESENT: u64 = 16;
/// `procmgr_labels::REGISTER_THREAD` refused: the sender's process
/// already holds `procmgr_labels::REGISTERED_THREADS_MAX` registered
/// threads that procmgr could not prune.
pub const THREAD_LIMIT: u64 = 17;
/// A create refused because its object did not verify: it does not parse
/// as a signed object, no record chains to the trust store, or the record
/// that does fails a check, its name, roles (against the creator's
/// signature policy), architecture or body hash among them
/// (docs/signing.md § Signature Policy in procmgr). Nothing was created.
pub const SIGNATURE_REFUSED: u64 = 18;
/// `procmgr_labels::REGISTER_END_QUEUE` refused: the sender registered
/// an end queue before.
pub const END_QUEUE_PRESENT: u64 = 19;
/// `procmgr_labels::SNAPSHOT` refused: the target's address space is held
/// already, by another capture of it, or the hold was interrupted; nothing
/// was captured, and the sender may ask again.
pub const SPACE_HELD: u64 = 20;
/// A charge procmgr made for the request on a process's memmgr account (the
/// child's for a create, the sender's for a request on its own account) was
/// refused by the max of that account's budget node or of an ancestor
/// (`memmgr_errors::LIMIT`): the request asks for more than the node the
/// creator chose allows, where `OUT_OF_MEMORY` is the system's own
/// shortage. Nothing the request took is kept.
pub const LIMIT: u64 = 21;
/// `procmgr_labels::CHECKPOINT` refused: the process is at no quiesce point
/// (`procmgr_labels::QUIESCE`), or left it before the capture's hold;
/// nothing was captured.
pub const NOT_QUIESCED: u64 = 22;
/// No restore can be made of the process or object the request names
/// (docs/checkpoint-restore.md § Refusals): `procmgr_labels::QUIESCE` from a
/// process created pinned, phys-class or with a DMA hold; a
/// `procmgr_labels::CHECKPOINT` whose account memmgr does not recognise as
/// its own, so it refused the checkpoint mark; and a
/// `procmgr_labels::CREATE_RESTORE` create whose object carries no
/// checkpoint mark or is not a checkpoint of the verified body. Nothing is
/// created or kept.
pub const NOT_RESTORABLE: u64 = 23;
/// Unknown opcode on procmgr endpoint.
pub const UNKNOWN_OPCODE: u64 = 0xFFFF;
