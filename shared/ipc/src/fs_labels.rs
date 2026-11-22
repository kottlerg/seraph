// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/ipc/src/fs_labels.rs

//! IPC labels for filesystem drivers (FAT, ext4, etc.).

/// Read from a file node cap or open cap (driver-side). Inline reply:
/// `data[0]` = bytes read, payload follows starting at word 1. Drivers
/// cap per-call payload at the IPC inline ceiling; callers iterate.
pub const FS_READ: u64 = 2;
/// Close an open cap ([`FS_OPEN`]): the driver revokes that open's
/// outstanding [`FS_READ_MEMORY`] pages, deletes its recorded release
/// SEND, frees its record in its session's pages, and retires the open,
/// so the open cap answers `fs_errors::INVALID_BADGE` from then on.
/// Other opens of the file are untouched. A close that leaves its session
/// with no open, the session's liveness cap held nowhere outside the
/// driver, ends the session before the reply, its pages given back. A node
/// cap is answered `fs_errors::INVALID_BADGE`. The caller still cap-deletes the open cap
/// to drop the kernel-side reference. Specified in `services/fs/docs/fs-driver-protocol.md`
/// § Label 3: `FS_CLOSE`.
pub const FS_CLOSE: u64 = 3;
/// Inline write to a file node cap.
///
/// Request: `label = FS_WRITE | (byte_len << 16)` (bits 0-15 = label
/// ID, bits 16-31 = payload byte length, ≤ 504), `data[0]` = file
/// byte offset, payload bytes packed from word 1 onward via
/// `IpcMessageBuilder::bytes(1, &payload)`. Badge must carry the
/// `WRITE` namespace right (see `namespace-protocol::rights`). The 504
/// bytes are the `MSG_DATA_WORDS_MAX` data words less the offset word;
/// a larger write is split over more calls.
///
/// Reply (success label `fs_errors::SUCCESS`): `data[0]` =
/// `bytes_written` (may be short on `NO_SPACE` or on
/// partial-cluster failure; callers iterate). Error labels per
/// [`fs_errors`].
pub const FS_WRITE: u64 = 4;
/// End-of-directory marker in `NS_READDIR` replies.
pub const END_OF_DIR: u64 = 6;
/// Read file content into a cached Memory cap returned in the reply.
///
/// Request: badge identifies the open ([`FS_OPEN`]'s open cap; a node
/// cap is answered `fs_errors::INVALID_BADGE`), `data[0]` = byte offset
/// (no alignment requirement), `data[1]` = client-chosen release cookie
/// (must be non-zero; one full data word the client picks per page, so
/// its width bounds no count). No caps: the driver deletes any the
/// request carries. The page is the open's until released or the open
/// is closed (services/fs/docs/fs-driver-protocol.md § Label 7).
/// Reply: `data[0]` = bytes valid in the returned page starting at
/// the indicated page offset, `data[1]` = the same release cookie
/// echoed back, `data[2]` = byte offset within the returned page
/// where the file's content for the requested `offset` begins,
/// `caps[0]` = single-page Memory cap with `MAP` rights (read-only
/// mapping authority) covering the cached file page.
///
/// `bytes_valid` is bounded by file end, the current cluster
/// boundary on the underlying filesystem, and the page tail
/// (`PAGE_SIZE - memory_data_offset`); callers iterate forward from
/// `offset + bytes_valid` to read past those boundaries.
pub const FS_READ_MEMORY: u64 = 7;
/// Release of a previously-returned page, in either direction.
///
/// Driver-to-client (cooperative eviction): sent on the release endpoint
/// SEND that the [`FS_OPEN`] of the open that read the page carried;
/// `data[0]` = the release cookie naming
/// the Memory cap to unmap. The client unmaps it and replies
/// [`FS_RELEASE_ACK`], first letting a local copy from the page finish
/// within the watchdog window; any other reply label is no ack (the std
/// client sends `fs_errors::IO_ERROR`). After the reply, or the window
/// with none, the driver revokes the page's parent Memory cap.
///
/// Client-to-driver (synchronous release after a read): sent on the
/// open cap the page was read through; `data[0]` = the release cookie
/// from the [`FS_READ_MEMORY`] reply. The driver revokes the page's
/// derived caps and frees its cache slot. Reply: empty body on success
/// (a cookie matching no page of that open is a no-op success);
/// `fs_errors::PERMISSION_DENIED` when the badge carries no namespace
/// rights, `fs_errors::INVALID_BADGE` on a node cap or a closed open.
///
/// See `services/fs/docs/fs-driver-protocol.md` "Label 8:
/// `FS_RELEASE_MEMORY`" for the authoritative contract.
pub const FS_RELEASE_MEMORY: u64 = 8;
/// Client acknowledgement of [`FS_RELEASE_MEMORY`]: synchronous reply,
/// empty body.
pub const FS_RELEASE_ACK: u64 = 9;
/// Mount-time probe from vfsd. Specified in
/// `services/fs/docs/fs-driver-protocol.md` § Label 10: `FS_MOUNT`.
pub const FS_MOUNT: u64 = 10;
/// Write file content from a caller-supplied source Memory cap.
///
/// Mirror of [`FS_READ_MEMORY`] for the write direction. Caller maps,
/// fills, then transfers a Memory cap holding the bytes to write.
///
/// Request: badge identifies the file (per-file cap),
/// `data[0]` = file byte offset (no alignment requirement),
/// `data[1]` = bytes to write from the page (`≤ PAGE_SIZE -
/// memory_data_offset`), `data[2]` = byte offset within the source
/// page where the data begins. `caps[0]` = source Memory cap with
/// at least `MAP` rights, sized one page. Badge must carry the
/// `WRITE` namespace right.
///
/// Reply (label `fs_errors::SUCCESS`): `data[0]` = `bytes_written`
/// (short on `NO_SPACE` or cluster-boundary truncation; callers
/// iterate). `caps[0]` = the source Memory cap moved back to the
/// caller. Errors per [`fs_errors`].
pub const FS_WRITE_MEMORY: u64 = 12;
/// Create a new file in a directory.
///
/// Request: badge = parent-directory cap (must carry `MUTATE_DIR`),
/// `label = FS_CREATE | (name_len << 16)`, name bytes packed from
/// word 0 via `IpcMessageBuilder::bytes(0, name)`. Name validated
/// per `namespace-protocol::validate_name`.
///
/// Reply (label `fs_errors::SUCCESS`): `data[0]` = entry kind (per
/// `namespace_protocol::NodeKind`), `caps[0]` = node cap for the
/// newly-created file. Errors: as `services/fs/docs/fs-driver-protocol.md`
/// § Label 13: `FS_CREATE` lists them.
pub const FS_CREATE: u64 = 13;
/// Remove a file or empty directory from a directory.
///
/// Request: badge = parent-directory cap (must carry `MUTATE_DIR`),
/// `label = FS_REMOVE | (name_len << 16)`, name bytes from word 0.
///
/// Reply (label `fs_errors::SUCCESS`): empty body. Errors: as
/// `services/fs/docs/fs-driver-protocol.md` § Label 14: `FS_REMOVE`
/// lists them.
pub const FS_REMOVE: u64 = 14;
/// Create a new (empty) directory in a directory.
///
/// Request: identical shape to [`FS_CREATE`]. Badge must carry
/// `MUTATE_DIR`. Allocates one cluster zero-filled with `.` and
/// `..` entries.
///
/// Reply: identical shape to [`FS_CREATE`], `data[0]` = kind (Dir).
pub const FS_MKDIR: u64 = 15;
/// Rename a directory entry within a single directory.
///
/// Request: badge = directory cap (must carry `MUTATE_DIR`),
/// `data[0]` = source name length, `data[1]` = destination name
/// length, name bytes packed contiguously from word 2 via
/// `IpcMessageBuilder::bytes(2, &concat(src, dst))` — source bytes
/// first, destination bytes immediately after with no padding.
///
/// Cross-directory rename is deferred to Issue #89: the request
/// carries one directory cap, so a destination in another directory
/// cannot be named.
///
/// Not atomic: an interrupted rename can leave only the source, both
/// names, or only the destination present. See
/// `services/fs/fat/docs/crash-safety.md`.
///
/// Reply (label `fs_errors::SUCCESS`): empty body. Errors: as
/// `services/fs/docs/fs-driver-protocol.md` § Label 16: `FS_RENAME`
/// lists them.
pub const FS_RENAME: u64 = 16;
/// Truncate a file to a new length.
///
/// Request: badge = file-node cap (must carry `WRITE`),
/// `label = FS_TRUNCATE`, `data[0]` = new length in bytes; only zero
/// is supported. Specified, with its errors, in
/// `services/fs/docs/fs-driver-protocol.md` § Label 17: `FS_TRUNCATE`.
pub const FS_TRUNCATE: u64 = 17;
/// Open a file: mint a per-open cap on the driver's endpoint.
///
/// Request: badge = file-node cap (any non-empty rights), empty body,
/// `caps[0]` = a copy of the session cap ([`FS_SESSION`]), which the
/// driver reads and deletes: every open is made in a session. `caps[1]` =
/// optional release-endpoint SEND for the open's cooperative
/// [`FS_RELEASE_MEMORY`] (omitted to opt out). The open's records live in
/// the session's pages, charged to the session's node. Reply (label
/// `fs_errors::SUCCESS`): `caps[0]` = the open cap, carrying the node cap's
/// rights; its badge names the open (`namespace_protocol::OPEN_INSTANCE`).
/// The open lives until its [`FS_CLOSE`], its node's removal, or its
/// session's end. [`FS_READ_MEMORY`], [`FS_RELEASE_MEMORY`], and
/// [`FS_CLOSE`] go to the open cap; the stateless file labels accept either
/// cap. Errors: `INVALID_ARGUMENT` (no `caps[0]`, or one on another
/// endpoint, or memmgr refuses the session's handle), `INVALID_BADGE` (no such node, a directory, or a `caps[0]` on
/// the driver's endpoint that names no live session), `PERMISSION_DENIED`,
/// `LIMIT` (the session needs a page its node's max refuses),
/// `TOO_MANY_OPEN` (the driver's open ids are spent, or its heap or
/// `CSpace` cannot grow), `IO_ERROR` (the driver could not mint the open
/// cap, or memmgr has no page for the session). Every refusal deletes the
/// carried caps. Specified in
/// `services/fs/docs/fs-driver-protocol.md` § Label 18: `FS_OPEN`.
pub const FS_OPEN: u64 = 18;
/// Start a filesystem session: the records of the opens made in it live in
/// pages charged to a node of the client.
///
/// Request: badge = any node cap (any non-empty rights), empty body,
/// `caps[0]` = a charge-only handle to the client's node
/// (`services/memmgr/docs/ipc-interface.md` § Node Handles), which the
/// driver keeps for the session's life. The driver takes the session's
/// first page, charged to that node, and holds it until the session ends.
/// Reply (label `fs_errors::SUCCESS`): `caps[0]` = the session cap, a
/// SEND on the driver's endpoint with `IDENTIFY`, whose badge names the
/// session (`namespace_protocol::SESSION`): a copy of it is what [`FS_OPEN`]
/// carries, and the right lets its holder ask the kernel whether a node cap
/// is on this driver's endpoint (`SYS_ENDPOINT_IDENTIFY`); `caps[1]`
/// = the session's liveness cap, a zero-rights Notification cap: the
/// session lives while a copy of it lives outside the driver, and once every
/// copy is gone the driver may end the session, with every open made in it,
/// and give its pages back. An open handed to another process lives only
/// while that process, or another, holds a copy of the liveness cap.
/// Errors: `INVALID_BADGE` (an open cap or a session cap),
/// `PERMISSION_DENIED`, `INVALID_ARGUMENT` (no handle, or memmgr refuses
/// it), `LIMIT` (the node's max refuses the first page), `IO_ERROR`
/// (memmgr has no page), `TOO_MANY_OPEN` (the driver's session ids are
/// spent, or its heap or `CSpace` cannot grow, or it cannot create the
/// liveness object). Every refusal deletes the handle. Specified in
/// `services/fs/docs/fs-driver-protocol.md` § Label 23: `FS_SESSION`.
pub const FS_SESSION: u64 = 23;
/// Unmount: the driver ends its service and exits.
///
/// Request: un-badged, on the driver's service endpoint, as [`FS_MOUNT`];
/// `data[0]` = caller's compiled [`super::FS_LABELS_VERSION`]; the
/// [`UNMOUNT_FORCE`] flag in the label's flag bits. The driver ends
/// every session whose client is gone; when live opens remain and the
/// request is not forced, it replies `fs_errors::BUSY` with `data[0]` =
/// the live opens and keeps serving. Otherwise it releases every open,
/// as [`FS_CLOSE`] would, replies `fs_errors::SUCCESS`, and exits with
/// [`EXIT_UNMOUNTED`]. Specified in
/// `services/fs/docs/fs-driver-protocol.md` § Label 19: `FS_UNMOUNT`.
pub const FS_UNMOUNT: u64 = 19;
/// [`FS_UNMOUNT`] flag: unmount with live opens, releasing them.
pub const UNMOUNT_FORCE: u64 = 1 << 16;
/// Exit code of a driver that replied to [`FS_UNMOUNT`] and exited: the
/// exit reason its death observers receive is
/// `syscall_abi::encode_exit_code` of it. Specified, with
/// [`EXIT_DEVICE_GONE`], in `services/fs/docs/fs-driver-protocol.md`
/// § Driver exit.
pub const EXIT_UNMOUNTED: u32 = 0;
/// Exit code of a driver that found its block device capability revoked.
pub const EXIT_DEVICE_GONE: u32 = 1;
