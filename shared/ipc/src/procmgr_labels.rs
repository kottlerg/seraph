// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/ipc/src/procmgr_labels.rs

//! IPC labels for the process manager (`procmgr`).

// Under `rustc-dep-of-std` the crate is `no_core`, so this module, which
// defines a type and functions, imports the prelude the crate root
// imports.
#[cfg(feature = "rustc-dep-of-std")]
use core::prelude::rust_2024::*;

/// Create a new process from a signed object in a Memory cap, a boot
/// module's. Caps: `[module, creator_endpoint?, charge_node?, argv_env?,
/// death_relay?]`, `charge_node` present iff [`CREATE_CHARGE_NODE`] is
/// set, `argv_env` iff [`CREATE_ARGV_ENV`] is set, and `death_relay` iff
/// [`CREATE_DEATH_RELAY`] is set, as for [`CREATE_FROM_FILE`]. Data word
/// 0 is the object's exact length in bytes, which the cap, a whole number
/// of pages, must hold; the words after it are laid out as for
/// [`CREATE_FROM_FILE`], the name block ([`create_name_word`]) last.
/// procmgr copies the object, verifies it under the name the block
/// carries, and loads only its verified body. Label layout and reply as
/// for [`CREATE_FROM_FILE`].
/// Stdio pipes (stdin/stdout/stderr) are
/// configured through one or more [`CONFIGURE_PIPE`] calls against
/// the returned badged `process_handle` — procmgr's CREATE path
/// carries no stdio caps so stdout and stderr can be piped
/// independently and so the core process-creation primitive stays
/// stdio-agnostic.
pub const CREATE_PROCESS: u64 = 1;
/// Start a previously created (suspended) process.
pub const START_PROCESS: u64 = 2;
/// Create a new process from a caller-supplied file cap (a signed ELF
/// binary).
///
/// The caller already walked its own namespace cap to the binary node
/// and attaches the resulting badged file cap. Procmgr opens it
/// (`FS_OPEN`), copies the file's `file_size` bytes into memory of its
/// own with `FS_READ_MEMORY` against its open, closes it, verifies the
/// copy under the name the request's name block carries
/// (docs/signing.md § Signature Policy in procmgr), and loads only its
/// verified body. It never holds a namespace cap of its own.
///
/// Label layout:
/// * bits `[0..16]` — opcode (`CREATE_FROM_FILE`)
/// * bits `[16..18]` — flags ([`CREATE_PINNED`], [`CREATE_DEATH_RELAY`])
/// * bits `[18..23]` — `CREATE_PRIORITY` (see [`CREATE_PRIORITY_SHIFT`])
/// * bits `[23..28]` — `CREATE_BAND_MAX` (see [`CREATE_BAND_MAX_SHIFT`])
/// * bit `28` — [`CREATE_DMA_HOLD`]
/// * bit `29` — [`CREATE_ARGV_ENV`]
/// * bit `30` — [`CREATE_PHYS_ACCESS`]
/// * bit `31` — [`CREATE_MEMORY_MAX`]
/// * bit `32` — [`CREATE_RESERVE`]
/// * bit `33` — [`CREATE_NODE_HANDLE`]
/// * bit `34` — [`CREATE_CHARGE_NODE`]
/// * bit `35` — [`CREATE_CONTAIN`]
/// * bit `36` — [`CREATE_PRIVATE_IMAGE`]
/// * bits `[37..64]` — reserved (zero; see [`CREATE_RESERVED_MASK`])
///
/// IPC data words:
/// * `word 0` — `file_size` (u64), as reported by the caller's `NS_LOOKUP` size hint
/// * `words 1..5` — the [`ArgvEnvHeader`] (only when [`CREATE_ARGV_ENV`] is set)
/// * the next word — the child's memory max in pages (only when
///   [`CREATE_MEMORY_MAX`] is set): word 1, or word 5 after the header
/// * the name block, always, at [`create_name_word`]: the name's length in
///   bytes, from 1 to [`CREATE_NAME_MAX`], then its bytes packed
///   little-endian from the next word ([`create_name`])
///
/// The name is the install path the creator expects the file to have been
/// signed under; a create whose object does not verify under it, or
/// whose roles meet none the creator's signature policy allows, is refused
/// with `procmgr_errors::SIGNATURE_REFUSED`.
///
/// Reply: `data[0]` is the max the child's memmgr budget node took after
/// memmgr's clamp, `u64::MAX` for none.
///
/// Caps: `[file_cap, creator_endpoint?, charge_node?, argv_env?,
/// death_relay?]`. The `charge_node` handle is present iff
/// [`CREATE_CHARGE_NODE`] is set, and sits directly before the
/// `argv_env` cap, or before the relay without one, or last without
/// either. The `argv_env` Memory cap is present iff [`CREATE_ARGV_ENV`]
/// is set, and sits directly before the relay, or last without one. `file_cap`
/// ownership transfers to procmgr: procmgr opens it (`FS_OPEN`) and
/// `cap_delete`s it, then `FS_CLOSE`s and deletes its open after the load
/// (success or failure); a request refused before the open deletes
/// `file_cap` unopened. The
/// optional `death_relay` POST-only `EventQueue` cap is present iff
/// [`CREATE_DEATH_RELAY`] is set in the label; when present it is the
/// LAST cap in the message (procmgr peels it off the tail, so the
/// `creator_endpoint` slot stays positionally fixed regardless of
/// relay presence), and it is a cap of its own: a relay request whose
/// only cap is `file_cap` is refused with `INVALID_ARGUMENT`. Stdio
/// pipes are installed via separate [`CONFIGURE_PIPE`] calls between
/// create and start.
pub const CREATE_FROM_FILE: u64 = 13;
/// Label flag (bit 16) for [`CREATE_PROCESS`] / [`CREATE_FROM_FILE`]:
/// create the new process *pinned* — eager-mapped, with no system pager.
/// Demand paging is the default: when this flag is clear, procmgr binds the
/// child's main thread fault handler to memmgr (the system pager),
/// delegates the child `AddressSpace` cap to memmgr via
/// `memmgr_labels::DELEGATE_ASPACE`, and advertises the pager in
/// `ProcessInfo` (`pager_endpoint_cap` / `pager_badge`), which tells the
/// runtime the process is demand-paged; the runtime copies the spawning
/// thread's bindings, the pager among them, onto each thread it spawns
/// (`SYS_THREAD_INHERIT_FAULT_HANDLER`). Set this flag only for a process
/// that cannot depend on the fault path — a driver doing DMA, whose memory
/// a device may write before a demand fault could back it. Occupies bit 16
/// of the `[16..31]` label window. init, memmgr, and procmgr are pre-pager
/// and never routed through this binding path, so they are pinned by
/// construction regardless.
pub const CREATE_PINNED: u64 = 1 << 16;
/// Label flag (bit 17) for [`CREATE_PROCESS`] / [`CREATE_FROM_FILE`]:
/// the message carries a trailing death-relay POST-only `EventQueue` cap
/// (the LAST cap in the message, which then carries at least two caps).
/// procmgr keeps the relay for the child's life and posts the child's end
/// to it once, as the entry `(reason, 0)`: the fault class at the reap of
/// a terminal fault in any of the child's threads, the exit reason at the
/// reap of its main thread's exit or of a process exit (`SYS_ASPACE_EXIT`)
/// of any of its threads, or the reason a destroy tore it down
/// with (`EXIT_KILLED` for a running child), so `Child::wait()` returns
/// whoever ended the child. procmgr deletes its copy once it has posted,
/// and when the child is re-parented, its creator having ended
/// ([`CREATE_CONTAIN`]). Occupies bit 17 of the `[16..31]` label window.
pub const CREATE_DEATH_RELAY: u64 = 1 << 17;
/// Bit offset of the `CREATE_PRIORITY` field (bits `[18..23]`) in a
/// [`CREATE_PROCESS`] / [`CREATE_FROM_FILE`] label: the priority level
/// the child's initial thread is created at. `0` = unspecified —
/// procmgr places the child at
/// [`crate::sched_policy::DEFAULT_SPAWN_PRIORITY`] clamped to the
/// child's band. A nonzero value must satisfy
/// `1 <= priority <= band_max <= creator's band ceiling`; violations
/// reply `INVALID_ARGUMENT`. Occupies bits 18–22 of the
/// `[16..31]` label window.
pub const CREATE_PRIORITY_SHIFT: u32 = 18;
/// Bit offset of the `CREATE_BAND_MAX` field (bits `[23..28]`): the
/// upper bound of the baseline `SchedControl` band procmgr mints into
/// the child (`[1, band_max]`, delivered via
/// `ProcessInfo.sched_control_cap`). `0` = unspecified — the child
/// receives a copy of its creator's band. A nonzero value must not
/// exceed the creator's band ceiling. Occupies bits 23–27 of the
/// `[16..31]` label window.
pub const CREATE_BAND_MAX_SHIFT: u32 = 23;
/// Width mask of each 5-bit scheduling field in the create label. Five
/// bits hold every level of the kernel's 32-level priority space
/// (`syscall_abi::PRIORITY_MAX` is 30), so the width bounds nothing.
pub const CREATE_SCHED_FIELD_MASK: u64 = 0x1F;
/// Label flag (bit 28) for [`CREATE_PROCESS`] / [`CREATE_FROM_FILE`]:
/// once the child has been started, hold back its memory reclaim at its
/// teardown. procmgr tears the child down as any other, but sends memmgr
/// its `memmgr_labels::PROCESS_DIED` only when the creator sends
/// [`RELEASE_HOLD`] on the release token, a third cap of the create reply
/// badged with [`HOLD_RELEASE_AUTHORITY`]; until then memmgr keeps the
/// child's frames on its record, out of the free pool. Set it for a driver
/// whose device may DMA into its frames: the creator releases the hold
/// once it has confirmed the device's DMA stopped, and never when it
/// cannot. A child destroyed before [`START_PROCESS`] never ran and is
/// reclaimed at once. Specified in
/// `services/procmgr/docs/ipc-interface.md` § Label 1: `CREATE_PROCESS`
/// (**DMA hold flag**). Occupies bit 28 of the `[16..31]` label window.
pub const CREATE_DMA_HOLD: u64 = 1 << 28;
/// Label flag (bit 29) for [`CREATE_PROCESS`] / [`CREATE_FROM_FILE`]: the
/// request carries the child's argv and env in a Memory cap the caller
/// sizes, the argv blob at byte 0 and the env blob directly after it, and
/// their [`ArgvEnvHeader`] in four data words from word 1, after the
/// object's length (`CREATE_PROCESS`) or `file_size`
/// (`CREATE_FROM_FILE`). The cap is the last cap before the death relay,
/// or the last cap without one. procmgr copies the blobs into the child's
/// argv/env region through fixed windows and deletes its copy of the cap
/// before it replies; the caller then returns the cap's run to memmgr,
/// unless the reply is `procmgr_errors::ARGV_ENV_STILL_MAPPED`. procmgr
/// replies that when it cannot unmap a copy window, which may then still
/// map the caller's pages read-only and the child's writable: it keeps
/// the window's VA reserved and withholds the child's memmgr record, and
/// the caller withholds its run, so memmgr re-grants no frame procmgr may
/// still map. A spawner that cannot unmap its own write window withholds
/// its run the same way.
/// Specified in `services/procmgr/docs/ipc-interface.md` § Label 1:
/// `CREATE_PROCESS` (**argv and env**).
pub const CREATE_ARGV_ENV: u64 = 1 << 29;
/// Label flag (bit 30) for [`CREATE_PROCESS`] / [`CREATE_FROM_FILE`]:
/// create the child phys-class, so memmgr's grants to it keep
/// `RIGHTS_MEM_PHYS` and it can read physical addresses
/// (`CAP_INFO_MEMORY_PHYS_BASE`, `SYS_ASPACE_QUERY`). Honoured only from
/// an un-badged creator (init, svcmgr) or a phys-class one; procmgr
/// refuses it from any other creator (`INVALID_ARGUMENT`). init sets it
/// for devmgr and devmgr for the IOMMU driver. Specified in
/// `services/procmgr/docs/ipc-interface.md` § Label 1: `CREATE_PROCESS`
/// (**physical-address flag**).
pub const CREATE_PHYS_ACCESS: u64 = 1 << 30;
/// Label flag (bit 31) for [`CREATE_PROCESS`] / [`CREATE_FROM_FILE`]: the
/// request carries a memory max for the child, in pages, in one data word
/// after the others: after the [`ArgvEnvHeader`] when [`CREATE_ARGV_ENV`]
/// is set, so at word 1 or 5 of either label. procmgr registers the child's memmgr budget node
/// with that max (`memmgr_labels::REGISTER_MAX`), which memmgr clamps to
/// what the creator's node and every ancestor have left; the create reply
/// carries the max the node took in `data[0]`. A request that sets the
/// flag without delivering the word is refused (`INVALID_ARGUMENT`).
/// Specified in `services/procmgr/docs/ipc-interface.md` § Label 1:
/// `CREATE_PROCESS` (**Memory max and reserve**).
pub const CREATE_MEMORY_MAX: u64 = 1 << 31;
/// Label flag (bit 32) for [`CREATE_PROCESS`] / [`CREATE_FROM_FILE`]:
/// make the child's memmgr budget node a system-reserve node
/// (`memmgr_labels::REGISTER_RESERVE`). Honoured only from a creator
/// whose own node is a reserve node, and never with [`CREATE_CHARGE_NODE`];
/// procmgr refuses it from any other creator, and with that flag
/// (`INVALID_ARGUMENT`). A child of an un-badged creator (init) not
/// charged to a node handle is a reserve node with or without it.
/// Specified in `services/procmgr/docs/ipc-interface.md` § Label 1:
/// `CREATE_PROCESS` (**Memory max and reserve**).
pub const CREATE_RESERVE: u64 = 1 << 32;
/// Label flag (bit 33) for [`CREATE_PROCESS`] / [`CREATE_FROM_FILE`]: the
/// create reply carries the child's node handle as its last cap, a SEND on
/// memmgr's endpoint naming the child's budget node
/// (`memmgr_labels::NODE_HANDLE_TAG`), through which the creator sets the
/// node's max, reads its usage, makes sub-nodes and registers its limit
/// event while the child runs. procmgr registers the child with
/// `memmgr_labels::REGISTER_NODE_HANDLE` and passes the handle on. The
/// handle names the child's node only, and is refused once the child is
/// gone. Specified in `services/procmgr/docs/ipc-interface.md` § Label 1:
/// `CREATE_PROCESS` (**Memory max and reserve**).
pub const CREATE_NODE_HANDLE: u64 = 1 << 33;
/// Label flag (bit 34) for [`CREATE_PROCESS`] / [`CREATE_FROM_FILE`]: the
/// request carries a node handle (`memmgr_labels::NODE_HANDLE_TAG`) as a
/// tail cap, before the argv/env and death-relay caps, and the child's
/// budget node is made under the node it names instead of under the
/// creator's, so every process created on one handle shares that node's
/// max. procmgr passes the handle to memmgr with
/// `memmgr_labels::REGISTER_CHARGE_NODE`, which refuses a cap that is no
/// live node handle. The child's node is outside the system reserve:
/// procmgr refuses [`CREATE_RESERVE`] with this flag (`INVALID_ARGUMENT`).
/// Specified in `services/procmgr/docs/ipc-interface.md`
/// § Label 1: `CREATE_PROCESS` (**Memory max and reserve**).
pub const CREATE_CHARGE_NODE: u64 = 1 << 34;
/// Label flag (bit 35) for [`CREATE_PROCESS`] / [`CREATE_FROM_FILE`]:
/// create the child contained. When a contained process ends, by an
/// exit, a fault or a destroy, procmgr destroys what is left of its
/// subtree instead of re-parenting its children to its parent, so no
/// process it started outlives it. Without the flag, the children of a
/// process that ends take its nearest live ancestor as their parent.
/// Specified in `services/procmgr/docs/ipc-interface.md` § Process Tree.
pub const CREATE_CONTAIN: u64 = 1 << 35;
/// Label flag (bit 36) for [`CREATE_PROCESS`] / [`CREATE_FROM_FILE`]:
/// load the child's image private. Without it, a demand-paged child
/// attaches the pages of its image that no relocation touches (its text and
/// read-only data) shared with the binary's other instances, from one
/// memmgr memory object, and only its writable segments are its own; with
/// it, every segment is loaded into frames of the child's own, as for a
/// pinned child, which shares nothing. A key-holding service asks for it:
/// text it shares lets the other processes that map it observe, by cache
/// timing, which of its code runs. Specified
/// in `services/procmgr/docs/ipc-interface.md` § Label 1: `CREATE_PROCESS`
/// (**Private image**).
pub const CREATE_PRIVATE_IMAGE: u64 = 1 << 36;
/// Still-reserved bits `[37..64]` of a create label. Procmgr rejects
/// labels with any of these set (`INVALID_ARGUMENT`), so a future field
/// addition is provably additive: existing senders are known to send
/// zeros.
pub const CREATE_RESERVED_MASK: u64 = !((1 << 37) - 1);
/// Data words an [`ArgvEnvHeader`] takes in a create request.
pub const ARGV_ENV_HEADER_WORDS: usize = 4;
/// The first data word of a create request after its fixed word 0, the
/// object's length (`CREATE_PROCESS`) or `file_size`
/// (`CREATE_FROM_FILE`): where the [`ArgvEnvHeader`], the memory max and
/// the name block start, in that order, each present or not.
pub const CREATE_FIRST_WORD: usize = 1;
/// Longest name, in bytes, a create request's name block carries: an
/// install path, the longest name in the canonical form an object is
/// signed under (`objsig::NAME_MAX`, which procmgr's
/// host tests pin this to; docs/signing.md § Signed Attributes). 32 data
/// words; with the length word and the words before it a request stays
/// under `MSG_DATA_WORDS_MAX`.
pub const CREATE_NAME_MAX: usize = 256;

/// The data word that holds the name block's length in a create request
/// labelled `label` ([`CREATE_PROCESS`] or [`CREATE_FROM_FILE`]): after
/// word 0 (the object's length or `file_size`), the [`ArgvEnvHeader`]
/// when [`CREATE_ARGV_ENV`] is set, and the memory max when
/// [`CREATE_MEMORY_MAX`] is set. The name's bytes follow from the next
/// word.
#[must_use]
pub const fn create_name_word(label: u64) -> usize
{
    let mut word = CREATE_FIRST_WORD;
    if label & CREATE_ARGV_ENV != 0
    {
        word = word.saturating_add(ARGV_ENV_HEADER_WORDS);
    }
    if label & CREATE_MEMORY_MAX != 0
    {
        word = word.saturating_add(1);
    }
    word
}

/// Append the name block for `name` to a create request labelled
/// `label` whose earlier words are already set
/// ([`create_name_word`]). `None` when `name` is empty or longer than
/// [`CREATE_NAME_MAX`], which procmgr would refuse.
#[must_use]
pub fn with_create_name(
    builder: crate::IpcMessageBuilder,
    label: u64,
    name: &[u8],
) -> Option<crate::IpcMessageBuilder>
{
    crate::with_name_block(builder, create_name_word(label), name, CREATE_NAME_MAX)
}

/// The name a create request `req` carries in its name block
/// ([`create_name_word`]): `None` when the request delivers no length
/// word, the length is zero or above [`CREATE_NAME_MAX`], or the words
/// delivered do not cover the name's bytes.
#[must_use]
pub fn create_name(req: &crate::IpcMessage) -> Option<&[u8]>
{
    crate::name_block(req, create_name_word(req.label), CREATE_NAME_MAX)
}

/// The byte lengths and string counts of a create request's argv and env
/// blobs, carried in [`ARGV_ENV_HEADER_WORDS`] data words when the label
/// sets [`CREATE_ARGV_ENV`]. Each field is a full `u64`: a count cannot
/// exceed its blob's byte length (every string ends in its NUL), and the
/// lengths are bounded by the cap that carries them, so no blob outgrows
/// the fields.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ArgvEnvHeader
{
    /// Byte length of the argv blob, at byte 0 of the cap.
    pub args_bytes: u64,
    /// NUL-terminated strings in the argv blob.
    pub args_count: u64,
    /// Byte length of the env blob, at byte `args_bytes` of the cap.
    pub env_bytes: u64,
    /// NUL-terminated `KEY=VALUE` strings in the env blob.
    pub env_count: u64,
}

impl ArgvEnvHeader
{
    /// The header's data words, in wire order.
    #[must_use]
    pub const fn to_words(self) -> [u64; ARGV_ENV_HEADER_WORDS]
    {
        [
            self.args_bytes,
            self.args_count,
            self.env_bytes,
            self.env_count,
        ]
    }

    /// The header the data words `words` carry, in wire order.
    #[must_use]
    pub const fn from_words(words: [u64; ARGV_ENV_HEADER_WORDS]) -> Self
    {
        Self {
            args_bytes: words[0],
            args_count: words[1],
            env_bytes: words[2],
            env_count: words[3],
        }
    }

    /// Both blobs' combined byte length, or `None` when the sum
    /// overflows a `u64`.
    #[must_use]
    pub const fn total_bytes(self) -> Option<u64>
    {
        self.args_bytes.checked_add(self.env_bytes)
    }
}

/// Pack the scheduling fields of a [`CREATE_PROCESS`] /
/// [`CREATE_FROM_FILE`] label. `0` in either field means
/// "unspecified" (procmgr applies its defaults; see
/// [`CREATE_PRIORITY_SHIFT`] / [`CREATE_BAND_MAX_SHIFT`]).
#[must_use]
pub const fn create_sched_bits(priority: u8, band_max: u8) -> u64
{
    (((priority as u64) & CREATE_SCHED_FIELD_MASK) << CREATE_PRIORITY_SHIFT)
        | (((band_max as u64) & CREATE_SCHED_FIELD_MASK) << CREATE_BAND_MAX_SHIFT)
}

/// Release the held memory reclaim of a child created with
/// [`CREATE_DMA_HOLD`], sent on the child's release token (the create
/// reply's third cap, badged with [`HOLD_RELEASE_AUTHORITY`]) once the
/// child is torn down: procmgr sends memmgr `PROCESS_DIED` for it.
/// Replies `SUCCESS`; `UNAUTHORIZED` when the sender's badge lacks
/// [`HOLD_RELEASE_AUTHORITY`] (the process handle, or the child's own
/// procmgr cap), the hold staying; or `INVALID_BADGE` when procmgr holds
/// no reclaim for the token (the child is live, was never held, or was
/// released already). Specified in
/// `services/procmgr/docs/ipc-interface.md` § Label 3: `RELEASE_HOLD`.
pub const RELEASE_HOLD: u64 = 3;

/// Badge bit of a release token, the SEND on procmgr's endpoint the
/// create reply of a [`CREATE_DMA_HOLD`] child carries as its third cap,
/// badged with the child's process badge and this bit: procmgr serves
/// [`RELEASE_HOLD`] only on a badge carrying it, so only the creator can
/// release the hold. No process badge carries a
/// [`VERB_BIT_MASK`](crate::VERB_BIT_MASK) bit, so the token names no
/// live process for any other label. Specified in
/// `services/procmgr/docs/ipc-interface.md` § Label 3: `RELEASE_HOLD`.
pub const HOLD_RELEASE_AUTHORITY: u64 = 1u64 << 61;
const _: () = core::assert!(
    HOLD_RELEASE_AUTHORITY & crate::VERB_BIT_MASK != 0
        && HOLD_RELEASE_AUTHORITY != DEATH_EQ_AUTHORITY
);

/// Destroy a process together with every process below it, sent on its
/// badged `process_handle`: once the destroy begins, procmgr refuses a
/// create from any process of that subtree, then deletes each one's
/// kernel objects, sends memmgr `PROCESS_DIED` for it unless
/// [`CREATE_DMA_HOLD`] holds the reclaim back, and posts its end to its
/// death relay and end queue. A process that has already ended and that
/// procmgr has not reaped yet is reaped instead, its children re-parented
/// as at its reap. Replies `SUCCESS` once the subtree is torn down, also
/// when the process was gone already; a child whose create procmgr has
/// not answered yet is left to that create, which is refused and tears
/// the child down.
/// Specified in `services/procmgr/docs/ipc-interface.md` § Label 8:
/// `DESTROY_PROCESS`.
pub const DESTROY_PROCESS: u64 = 8;
/// Query a process's state. Caller identifies the target via the badged
/// `process_handle` (delivered by `ipc_recv` on procmgr's side). Reply
/// carries one data word encoding the state (see
/// [`procmgr_process_state`]) and a second word carrying the exit reason
/// if known (zero for still-alive processes). Intended for monitoring
/// tools and `std::process::Child::try_wait`-style probes that want to
/// peek without blocking on a death event.
pub const QUERY_PROCESS: u64 = 9;
/// Bind the caller's event queue as a terminal-end death observer on
/// a child's address space, sent on the child's badged
/// `process_handle` only: `caps[0]` a `POST` cap on the queue,
/// `data[0]` the correlator the post carries. The first terminal end (a
/// fault or an exit) of any of the child's threads then posts
/// `(exit reason, correlator)` to the queue, once; a child that has already
/// ended posts its retained reason at once. procmgr keeps the address space's `Control` right
/// and deletes its copy of the cap whatever the outcome. Replies
/// `SUCCESS`; `UNAUTHORIZED` on a cap other than a process handle;
/// `INVALID_BADGE` when the handle names no live process;
/// `INVALID_ARGUMENT` without a queue cap or on one that lacks `POST`;
/// `OUT_OF_MEMORY` when the queue has no free observer node. Specified
/// in `services/procmgr/docs/ipc-interface.md` § Label 25:
/// `BIND_DEATH_OBSERVER`.
pub const BIND_DEATH_OBSERVER: u64 = 25;
/// List the children of a process, sent on its badged `process_handle`
/// only (`UNAUTHORIZED` on any other cap), one page per call: the
/// processes whose parent it is, by creation or by re-parenting, without
/// those a destroy has begun on. `data[0]` is 0 to start the walk or 1 to
/// resume after the badge in `data[1]`, as for [`LIST_PROCESSES`]. The
/// reply carries the page's count in `data[0]`, then per child, in
/// ascending badge order, [`LIST_CHILDREN_WORDS_PER_ENTRY`] words: its
/// badge, its name as [`LIST_PROCESSES`] lists it, and the pages charged
/// to its memmgr budget node and every node below it
/// ([`pack_child_entry`]), `0` for a child memmgr no longer knows; at most
/// [`LIST_CHILDREN_PAGE`] entries, and a page shorter than that ends the
/// walk. `INVALID_BADGE` when the handle names no live process;
/// `INVALID_ARGUMENT` for a `data[0]` other than 0 or 1. Specified in
/// `services/procmgr/docs/ipc-interface.md` § Label 27: `LIST_CHILDREN`.
pub const LIST_CHILDREN: u64 = 27;
/// Data words one [`LIST_CHILDREN`] entry takes: a [`LIST_PROCESSES`]
/// entry, then the subtree's pages.
pub const LIST_CHILDREN_WORDS_PER_ENTRY: usize = LIST_PROCESSES_WORDS_PER_ENTRY + 1;
/// Entries one [`LIST_CHILDREN`] reply carries at most: as many as fit the
/// data words after the count.
pub const LIST_CHILDREN_PAGE: usize =
    (super::MSG_DATA_WORDS_MAX - 1) / LIST_CHILDREN_WORDS_PER_ENTRY;
/// Destroy one child of a process, named by its badge in `data[0]`,
/// together with every process below it, as [`DESTROY_PROCESS`] destroys
/// a process; sent on the parent's badged `process_handle` only
/// (`UNAUTHORIZED` on any other cap). The handle is the authority: its
/// holder may destroy the parent with everything below it, and the badge
/// only names one of its children. Replies `SUCCESS` once the subtree is
/// torn down, as [`DESTROY_PROCESS`] does; `INVALID_BADGE` when `data[0]` names no live child of the
/// process, or one a destroy has marked. Specified in `services/procmgr/docs/ipc-interface.md`
/// § Label 28: `DESTROY_CHILD`.
pub const DESTROY_CHILD: u64 = 28;
/// Register an end queue on the sender itself, sent on its own procmgr
/// cap (its process badge names it; `INVALID_BADGE` on a
/// [`PROCESS_HANDLE_TAG`] badge): `caps[0]` a `POST` cap on an
/// `EventQueue` (not checked: a post to any other cap fails), `data[0]`
/// the correlator. procmgr posts the process's end to the queue once, as the entry `(reason, correlator)` a death
/// observer receives: the fault class, the exit reason, or the reason a
/// destroy tore it down with, whoever ended it. Replies `SUCCESS`;
/// `INVALID_ARGUMENT` without a queue cap; `INVALID_BADGE` when the badge
/// names no live process; `END_QUEUE_PRESENT` when the
/// process registered one before, so no process replaces the queue another
/// holder watches its end through. Caps past `caps[0]`, and the queue of a
/// refused request, are deleted. Specified in
/// `services/procmgr/docs/ipc-interface.md` § Label 29:
/// `REGISTER_END_QUEUE`.
pub const REGISTER_END_QUEUE: u64 = 29;
/// Install one direction's shmem-backed stdio pipe on a child
/// created via [`CREATE_PROCESS`] / [`CREATE_FROM_FILE`] but not yet
/// started.
///
/// Called on the badged `process_handle`, with the direction in
/// `data[0]` ([`PIPE_DIR_STDIN`] / [`PIPE_DIR_STDOUT`] /
/// [`PIPE_DIR_STDERR`]). Specified, with its caps, ordering, and replies,
/// in `services/procmgr/docs/ipc-interface.md` § Label 11:
/// `CONFIGURE_PIPE`.
///
/// Spawners call this 0–3 times depending on which directions are
/// piped. The 3 caps × 3 directions = 9 caps total exceeds
/// `MSG_CAP_SLOTS_MAX = 4`, so per-direction is the minimal-call
/// shape — non-piped directions cost zero IPC round trips.
pub const CONFIGURE_PIPE: u64 = 11;

/// Direction selector for [`CONFIGURE_PIPE`] — child stdin (parent
/// is the writer, child is the reader).
pub const PIPE_DIR_STDIN: u64 = 0;
/// Direction selector for [`CONFIGURE_PIPE`] — child stdout (child
/// is the writer, parent is the reader).
pub const PIPE_DIR_STDOUT: u64 = 1;
/// Direction selector for [`CONFIGURE_PIPE`] — child stderr (child
/// is the writer, parent is the reader).
pub const PIPE_DIR_STDERR: u64 = 2;

/// Install the namespace caps delivered to a suspended child via
/// `ProcessInfo.system_root_cap` and `ProcessInfo.current_dir_cap`.
///
/// Procmgr holds no namespace cap of its own. Without this call,
/// both child slots stay zero — `std::os::seraph::root_dir_cap()`
/// reads zero, `std::fs` absolute paths return `Unsupported`,
/// `current_dir_cap()` reads zero, and relative paths return
/// `Unsupported`. The spawner is the cap-distribution authority;
/// this IPC is the only path that installs namespace caps on the
/// child.
///
/// Request: caller invokes on the badged `process_handle` returned
/// by [`CREATE_PROCESS`] or [`CREATE_FROM_FILE`]; procmgr uses
/// `recv.badge` to find the entry. Wire format:
/// * `caps[0]` — root cap to deliver to the child (mandatory).
/// * `caps[1]` — cwd cap to deliver to the child (optional). When
///   absent the child's `current_dir_cap` slot stays zero.
///
/// Spawners obtain these caps by `cap_copy` of their own
/// `root_dir_cap()` / `current_dir_cap()` (parent-inherit default)
/// or by walk-and-attenuate against a sub-tree. procmgr does not
/// validate cap shape — any badged SEND on a namespace endpoint
/// is accepted.
///
/// procmgr stores the IPC-delivered copies in per-process state
/// and `cap_copy`s each into the child's `CSpace` at
/// `START_PROCESS` time. The caller's source slots are independent
/// of this transfer (kernel `cap_derive` semantics); callers that
/// wanted to relinquish authority over a cap MUST `cap_delete` the
/// source slot themselves after the call.
///
/// Ordering: valid only between create and `START_PROCESS`.
/// Replies `ALREADY_STARTED` if the target is running.
/// `INVALID_BADGE` if the `process_handle` is unknown.
/// `INVALID_ARGUMENT` if no cap was provided in `caps[0]`.
/// Idempotent before start; later calls overwrite the previous
/// caps (the prior caps are `cap_delete`'d procmgr-side).
pub const CONFIGURE_NAMESPACE: u64 = 12;

/// Register a death-notification `EventQueue` cap (`caps[0]`, POST
/// right) with procmgr, which posts to it the death entry
/// `(exit_reason, process badge)` of every process it tears down, so the
/// queue needs no death-observer nodes. Real-logd uses it to evict the
/// slot of a dead sender. Specified, with its replies, in
/// `services/procmgr/docs/ipc-interface.md` § `REGISTER_DEATH_EQ` —
/// install logd's death queue.
pub const REGISTER_DEATH_EQ: u64 = 14;

/// Badge bit on procmgr service caps that authorises
/// `REGISTER_DEATH_EQ`; un-badged or differently-badged callers are
/// rejected. Who holds it is in `services/procmgr/docs/ipc-interface.md`
/// § `REGISTER_DEATH_EQ` — install logd's death queue.
pub const DEATH_EQ_AUTHORITY: u64 = 1u64 << 62;

/// List the badges of the live processes procmgr tracks, one page per
/// call, for real-logd's death-queue resync; callers whose badge is not
/// [`DEATH_EQ_AUTHORITY`] are refused. `data[0]` is 0 to start the walk
/// or 1 to resume after the badge in `data[1]`. The reply carries the
/// page's count in `data[0]` and the badges, in ascending order, in
/// `data[1..=count]`, at most [`LIVE_PROCESSES_PAGE`]; a page shorter
/// than that ends the walk. Specified in
/// `services/procmgr/docs/ipc-interface.md` § `QUERY_LIVE_PROCESSES`.
pub const QUERY_LIVE_PROCESSES: u64 = 18;

/// Badges one [`QUERY_LIVE_PROCESSES`] reply carries at most: every data
/// word after the count.
pub const LIVE_PROCESSES_PAGE: usize = super::MSG_DATA_WORDS_MAX - 1;

/// Register the caller as the crash service: the receiver of procmgr's
/// crash endpoint, which procmgr binds the exception class of every
/// process it creates to, badged with its process badge, until the
/// process sends [`DECLARE_NO_DEBUG`]. Served only on a badge carrying
/// [`DEBUG_AUTHORITY`]
/// (`UNAUTHORIZED` otherwise). Caps: `[thread]`, a Thread cap of the
/// service's main thread, which procmgr keeps to tell when the service is
/// gone and take the receive side back. Replies `SUCCESS` with
/// one cap, `RECV` on the crash endpoint; `CRASH_SERVICE_PRESENT` while a
/// registered service lives; `INVALID_ARGUMENT` without the thread cap
/// or with no crash endpoint; `OUT_OF_MEMORY` when the `RECV` cap cannot
/// be derived or the decliner cannot be parked. Specified in
/// `services/procmgr/docs/ipc-interface.md` § `REGISTER_CRASH_SERVICE`.
pub const REGISTER_CRASH_SERVICE: u64 = 19;

/// Attach to a process: the Thread caps procmgr holds for it, each with
/// `OBSERVE`, `CONTROL`, and `UPCALL`, and where its image lies. Served
/// only on a badge carrying [`DEBUG_AUTHORITY`] (`UNAUTHORIZED`
/// otherwise). `data[0]` names the target: its process badge, or the badge
/// a fault message on the crash endpoint carries for one of its threads;
/// `data[1]` is the index of the first thread to return. `caps[0]`, when
/// sent, is a Thread cap of the caller's own main thread, of any rights
/// (procmgr only reads the thread's state): procmgr keeps it as the
/// target's debugger, and once that thread has exited it restores the
/// target's crash bindings as [`DETACH_PROCESS`] does, so a debugger that
/// dies attached leaves no thread bound to its dead endpoint. Replies
/// `SUCCESS` with `data[0]` the number of live threads procmgr holds for
/// the target (its main thread, then each registered one, [`REGISTER_THREAD`]),
/// `data[1]` its load bias, `data[2]`/`data[3]` the start and end of its
/// biased text, `data[4]` the address of its `ProcessInfo` page,
/// `data[`[`ATTACH_WORD_PROCESS_BADGE`]`]` the target's process badge,
/// `data[`[`ATTACH_WORD_NAMED_THREAD`]`]` the index of the thread the
/// request's badge names, and `data[`[`ATTACH_WORD_FLAGS`]`]` the
/// target's declarations and placement ([`ATTACH_FLAG_NO_CORE`],
/// [`ATTACH_FLAG_RESERVE`]), and with the caps of
/// threads `data[1]..` of the request, at most [`ATTACH_THREADS_PAGE`];
/// `INVALID_BADGE` when no live process carries the badge (memmgr and
/// procmgr, which procmgr did not create, among them); `NOT_ATTACHABLE`
/// when the target sent [`DECLARE_NO_DEBUG`]. Specified in
/// `services/procmgr/docs/ipc-interface.md` § `ATTACH_PROCESS`.
pub const ATTACH_PROCESS: u64 = 20;

/// [`ATTACH_PROCESS`] reply word: the target's process badge, the
/// request's `data[0]` when that named the process itself.
pub const ATTACH_WORD_PROCESS_BADGE: usize = 5;

/// [`ATTACH_PROCESS`] reply word: the index, in the reply's thread list,
/// of the thread the request's `data[0]` names: `0`, the main thread, for
/// a process badge; the registered thread a crash badge was bound to; or
/// [`ATTACH_NO_THREAD`] when that thread is no longer listed.
pub const ATTACH_WORD_NAMED_THREAD: usize = 6;

/// [`ATTACH_WORD_NAMED_THREAD`] value: the named thread is not listed.
pub const ATTACH_NO_THREAD: u64 = u64::MAX;

/// [`ATTACH_PROCESS`] reply word: the target's declarations and
/// placement, a set of `ATTACH_FLAG_*` bits.
pub const ATTACH_WORD_FLAGS: usize = 7;

/// [`ATTACH_WORD_FLAGS`] bit: the target sent [`DECLARE_NO_CORE`].
pub const ATTACH_FLAG_NO_CORE: u64 = 1;

/// [`ATTACH_WORD_FLAGS`] bit: the target's memmgr budget node is a
/// system-reserve node ([`CREATE_RESERVE`]), so its charges may take the
/// free pages memmgr keeps in reserve.
pub const ATTACH_FLAG_RESERVE: u64 = 1 << 1;

/// The caller declares itself on the core path, the processes a core dump
/// waits on, on its own procmgr cap (its process badge names it): procmgr
/// marks it, and every [`ATTACH_PROCESS`] reply for it from then on
/// carries [`ATTACH_FLAG_NO_CORE`], so the crash service writes no core of
/// it, a dump that would wait on the process it describes. Sent at startup
/// by vfsd, each filesystem driver, each block driver, devmgr and each
/// IOMMU driver, through which a core is written, and by the log sink,
/// which the dump's outcome line and every process's log output wait on
/// while the dump holds its threads. No data, no caps. Replies `SUCCESS`,
/// or `INVALID_BADGE` when the badge names no live process or carries
/// [`PROCESS_HANDLE_TAG`]. Specified in
/// `services/procmgr/docs/ipc-interface.md` § `DECLARE_NO_CORE`.
pub const DECLARE_NO_CORE: u64 = 26;

/// The tag of a debugger's binding: a debugger that binds a thread
/// [`ATTACH_PROCESS`] listed, on its exception or upcall class, binds it
/// under a badge carrying this bit and not bit 63, which procmgr's own
/// crash badges carry. procmgr tells a debugger's binding by this bit
/// alone: it binds such a thread back to the crash endpoint when it
/// registers ([`REGISTER_THREAD`]) while no debugger is watched, when its
/// registration is refused at [`REGISTERED_THREADS_MAX`] or for
/// procmgr's heap (under the process badge), and on [`DETACH_PROCESS`];
/// it unbinds it on [`DECLARE_NO_DEBUG`], and when its registration is
/// refused because its process sent that declaration. Specified
/// in `services/procmgr/docs/ipc-interface.md` § `ATTACH_PROCESS`.
pub const DEBUGGER_BADGE_TAG: u64 = 1 << 62;

/// Register the calling thread with procmgr, so [`ATTACH_PROCESS`]
/// returns it. Sent on the sender's own procmgr cap (its process badge
/// names the process) by each thread the runtime spawns, before it runs
/// its code. Caps: `[thread]`, a Thread cap of the sending thread with
/// `OBSERVE`, `CONTROL`, and `UPCALL`, which procmgr keeps until the
/// thread exits, its cap is revoked, or the process is torn down. procmgr
/// binds the thread's exception class to the crash endpoint under a
/// badge of the thread's own when the thread's binding is the process's,
/// or a debugger's ([`DEBUGGER_BADGE_TAG`]) while the process has no
/// debugger watched ([`ATTACH_PROCESS`] `caps[0]`). Replies `SUCCESS`;
/// `INVALID_BADGE` when the badge names no live process or carries
/// [`PROCESS_HANDLE_TAG`]; `NOT_ATTACHABLE` when the process sent
/// [`DECLARE_NO_DEBUG`], after unbinding the thread as the declaration
/// does when the cap carries the rights above;
/// `INVALID_ARGUMENT` without a Thread cap carrying those rights;
/// `THREAD_LIMIT` at [`REGISTERED_THREADS_MAX`]; `OUT_OF_MEMORY` when the
/// heap cannot hold the entry. At those two
/// refusals a debugger's binding on the thread is bound back to the crash
/// endpoint under the process badge, whether or not a debugger is
/// watched. A refused request's cap is deleted.
/// Specified in `services/procmgr/docs/ipc-interface.md`
/// § `REGISTER_THREAD`.
pub const REGISTER_THREAD: u64 = 22;

/// Registered threads procmgr holds for one process at most
/// ([`REGISTER_THREAD`]): above one thread per default stack the Sv39
/// arena zone holds (about 16 000). Past it a thread runs unregistered,
/// so no spawn fails for it; it bounds the `CSpace` slots and heap one
/// process can make procmgr hold.
pub const REGISTERED_THREADS_MAX: usize = 16384;

/// The caller declares itself undebuggable, on its own procmgr cap (its
/// process badge names it): procmgr unbinds the exception class of its
/// main thread and of every thread it registered ([`REGISTER_THREAD`])
/// wherever procmgr or a debugger ([`DEBUGGER_BADGE_TAG`]) bound it, and
/// the upcall class wherever a debugger bound it, releases the registered
/// threads, drops the debugger it watched for the process, and refuses
/// [`ATTACH_PROCESS`] and [`REGISTER_THREAD`] on it from then on, so no
/// [`DEBUG_AUTHORITY`] holder stops it. Sent, before
/// it spawns a thread, by each process a stop of which would deadlock a
/// debug-authority holder: the debug port's driver and every
/// debug-authority holder. No
/// data, no caps. Replies `SUCCESS`, or
/// `INVALID_BADGE` when the badge names no live process or carries
/// [`PROCESS_HANDLE_TAG`]. Specified in
/// `services/procmgr/docs/ipc-interface.md` § `DECLARE_NO_DEBUG`.
pub const DECLARE_NO_DEBUG: u64 = 21;

/// Badge bit of a process handle, the SEND on procmgr's endpoint a
/// create reply carries as its first cap: badged with the child's process
/// badge and this bit. procmgr clears it before it serves any label, so
/// the handle names the child as before, and refuses [`DECLARE_NO_DEBUG`],
/// [`DECLARE_NO_CORE`] and [`REGISTER_THREAD`] on a badge carrying it,
/// since those name the sender itself: only the child's own procmgr cap,
/// badged with the process badge alone, sends them. Specified in
/// `services/procmgr/docs/ipc-interface.md` § Messages.
pub const PROCESS_HANDLE_TAG: u64 = 1u64 << 59;
const _: () = core::assert!(
    PROCESS_HANDLE_TAG & crate::VERB_BIT_MASK != 0
        && PROCESS_HANDLE_TAG != DEBUG_AUTHORITY
        && PROCESS_HANDLE_TAG != DEATH_EQ_AUTHORITY
        && PROCESS_HANDLE_TAG != HOLD_RELEASE_AUTHORITY
);

/// Thread caps one [`ATTACH_PROCESS`] reply carries at most.
pub const ATTACH_THREADS_PAGE: usize = super::MSG_CAP_SLOTS_MAX;

/// List the live processes procmgr tracks with their names, one page
/// per call, so a debugger finds the process a host names. Served only
/// on a badge carrying [`DEBUG_AUTHORITY`] (`UNAUTHORIZED` otherwise).
/// `data[0]` is 0 to start the walk or 1 to resume after the badge in
/// `data[1]`, as for [`QUERY_LIVE_PROCESSES`]. The reply carries the
/// page's count in `data[0]`, then per entry, in ascending badge order,
/// [`LIST_PROCESSES_WORDS_PER_ENTRY`] words: the process badge, its
/// name's length, and the name's bytes ([`pack_list_entry`]); at most
/// [`LIST_PROCESSES_PAGE`] entries, and a page shorter than that ends the
/// walk. A name is the first string of the argv the process's creator
/// passed, truncated to [`super::svcmgr_labels::NAME_MAX`] bytes, or
/// empty: a label the creator chose, not an identity. A process that
/// declared itself undebuggable is listed and refuses the attach.
/// `INVALID_ARGUMENT` for a `data[0]` other than 0 or 1. Specified in
/// `services/procmgr/docs/ipc-interface.md` § `LIST_PROCESSES`.
pub const LIST_PROCESSES: u64 = 23;

/// Data words one [`LIST_PROCESSES`] entry takes: the badge, the name's
/// length, and the name in [`super::svcmgr_labels::NAME_MAX`] bytes.
pub const LIST_PROCESSES_WORDS_PER_ENTRY: usize = 2 + super::svcmgr_labels::NAME_MAX / 8;

/// Entries one [`LIST_PROCESSES`] reply carries at most: as many as fit
/// the data words after the count.
pub const LIST_PROCESSES_PAGE: usize =
    (super::MSG_DATA_WORDS_MAX - 1) / LIST_PROCESSES_WORDS_PER_ENTRY;

/// Write entry `index` of a [`LIST_PROCESSES`] reply into `words` (the
/// reply's data words, the count in word 0, which the caller sets): the
/// badge, the name's length, and the name's bytes little-endian,
/// zero-padded. A name past [`super::svcmgr_labels::NAME_MAX`] bytes is
/// truncated. Returns `false`, writing nothing, when the entry does not
/// fit `words`.
pub fn pack_list_entry(words: &mut [u64], index: usize, badge: u64, name: &[u8]) -> bool
{
    entry_words_mut(words, index, LIST_PROCESSES_WORDS_PER_ENTRY)
        .is_some_and(|entry| pack_named(entry, badge, name))
}

/// Read entry `index` of a [`LIST_PROCESSES`] reply's data words
/// `words`: its badge, and its name, written to the front of `name`,
/// whose length it returns. `None` when `index` is past the reply's
/// count or its words, or the entry's length is past
/// [`super::svcmgr_labels::NAME_MAX`].
#[must_use]
pub fn unpack_list_entry(
    words: &[u64],
    index: usize,
    name: &mut [u8; super::svcmgr_labels::NAME_MAX],
) -> Option<(u64, usize)>
{
    unpack_named(
        entry_words(words, index, LIST_PROCESSES_WORDS_PER_ENTRY)?,
        name,
    )
}

/// Write entry `index` of a [`LIST_CHILDREN`] reply into `words` (the
/// reply's data words, the count in word 0, which the caller sets): the
/// child's badge, its name as [`pack_list_entry`] writes it, and the pages
/// of its subtree. Returns `false`, writing nothing, when the entry does
/// not fit `words`.
pub fn pack_child_entry(
    words: &mut [u64],
    index: usize,
    badge: u64,
    name: &[u8],
    subtree_pages: u64,
) -> bool
{
    let Some((pages_word, named)) = entry_words_mut(words, index, LIST_CHILDREN_WORDS_PER_ENTRY)
        .and_then(|entry| entry.split_last_mut())
    else
    {
        return false;
    };
    *pages_word = subtree_pages;
    pack_named(named, badge, name)
}

/// Read entry `index` of a [`LIST_CHILDREN`] reply's data words
/// `words`: the child's badge, its name, written to the front of `name`,
/// the name's length, and the pages of its subtree. `None` as for
/// [`unpack_list_entry`].
#[must_use]
pub fn unpack_child_entry(
    words: &[u64],
    index: usize,
    name: &mut [u8; super::svcmgr_labels::NAME_MAX],
) -> Option<(u64, usize, u64)>
{
    let (pages, named) = entry_words(words, index, LIST_CHILDREN_WORDS_PER_ENTRY)?.split_last()?;
    let (badge, len) = unpack_named(named, name)?;
    Some((badge, len, *pages))
}

/// Write a badge and a name into `entry`, the
/// [`LIST_PROCESSES_WORDS_PER_ENTRY`] words of one list entry: the badge,
/// the name's length, and the name's bytes little-endian, zero-padded, a
/// name past [`super::svcmgr_labels::NAME_MAX`] bytes truncated. Returns
/// `false`, writing nothing, when `entry` is shorter.
fn pack_named(entry: &mut [u64], badge: u64, name: &[u8]) -> bool
{
    let Some([badge_word, len_word, name_words @ ..]) =
        entry.get_mut(..LIST_PROCESSES_WORDS_PER_ENTRY)
    else
    {
        return false;
    };
    let name = name.get(..super::svcmgr_labels::NAME_MAX).unwrap_or(name);
    *badge_word = badge;
    *len_word = name.len() as u64;
    name_words.fill(0);
    for (word, chunk) in name_words.iter_mut().zip(name.chunks(8))
    {
        *word = u64::from_le_bytes(crate::padded_word(chunk));
    }
    true
}

/// Read the badge and the name [`pack_named`] wrote into `entry`, the name
/// to the front of `name`; returns the badge and the name's length.
fn unpack_named(
    entry: &[u64],
    name: &mut [u8; super::svcmgr_labels::NAME_MAX],
) -> Option<(u64, usize)>
{
    let [badge, len_word, name_words @ ..] = entry.get(..LIST_PROCESSES_WORDS_PER_ENTRY)?
    else
    {
        return None;
    };
    let len = usize::try_from(*len_word)
        .ok()
        .filter(|&l| l <= super::svcmgr_labels::NAME_MAX)?;
    for (chunk, word) in name.get_mut(..len)?.chunks_mut(8).zip(name_words)
    {
        for (byte, src) in chunk.iter_mut().zip(word.to_le_bytes())
        {
            *byte = src;
        }
    }
    Some((*badge, len))
}

/// The `stride` words of entry `index` of a list reply's data words
/// `words`, past the count in word 0; `None` when `index` is past the
/// count or the words.
fn entry_words(words: &[u64], index: usize, stride: usize) -> Option<&[u64]>
{
    let count = usize::try_from(*words.first()?).ok()?;
    if index >= count
    {
        return None;
    }
    words.get(entry_base(index, stride)?..)?.get(..stride)
}

/// The `stride` words of entry `index` of a list reply's data words
/// `words`, for writing; `None` when they do not fit.
fn entry_words_mut(words: &mut [u64], index: usize, stride: usize) -> Option<&mut [u64]>
{
    words
        .get_mut(entry_base(index, stride)?..)?
        .get_mut(..stride)
}

/// The first data word of entry `index` of a list reply whose entries take
/// `stride` words each, past the count in word 0; `None` when it does not
/// fit a `usize`.
fn entry_base(index: usize, stride: usize) -> Option<usize>
{
    index.checked_mul(stride)?.checked_add(1)
}

/// Hand a process's crash bindings back after a debugger's attach:
/// procmgr binds the exception class of its main thread, and of each
/// registered thread ([`REGISTER_THREAD`]), that a debugger bound
/// ([`DEBUGGER_BADGE_TAG`]) or that is unbound, back to the crash endpoint
/// under the process badge or the thread's crash badge, minting one for a
/// thread that has none, unbinds each upcall class a debugger bound, and
/// forgets the debugger it watched for the process ([`ATTACH_PROCESS`]
/// `caps[0]`). A debugger holds no SEND on the
/// crash endpoint, so it cannot restore those bindings itself. Served
/// only on a badge carrying [`DEBUG_AUTHORITY`]. `data[0]` is the
/// target's process badge. Replies `SUCCESS`; `UNAUTHORIZED` without the
/// authority; `INVALID_BADGE` when no live process carries the badge;
/// `NOT_ATTACHABLE` when it declared itself undebuggable. Specified in
/// `services/procmgr/docs/ipc-interface.md` § `DETACH_PROCESS`.
pub const DETACH_PROCESS: u64 = 24;

/// Make a range of a process's memory resident for a debugger: memmgr
/// restores each chunk of the range it evicted into its compressed store
/// and maps an attachment's page with no copy of its own to its origin,
/// read-only, so a `SYS_THREAD_READ_MEM` that failed with `InvalidAddress`
/// on such a page succeeds when the reader retries; a page of an ordinary
/// region no fault has backed stays not present. Served only on a badge carrying [`DEBUG_AUTHORITY`].
/// `data[0]` is the target's process badge, `data[1]` the address and
/// `data[2]` the length in bytes, nonzero. Replies `SUCCESS` with `data[0]`
/// where memmgr stopped, which does a bounded part of the range per
/// request: the range's end when it is all done, else the address to ask
/// again from (`ipc::make_resident` asks until it is done), and `data[1]`
/// memmgr's: `memmgr_labels::RESIDENT_PENDING` when that address is a chunk
/// on disk the swap service was asked to restore, which the sender asks for
/// again after a pause, else `0`; and `data[2]` memmgr's: where its walk
/// stopped, past the chunks on disk it posted, from which a sender whose
/// pauses are spent asks again, passing those chunks over;
/// `UNAUTHORIZED` without the authority; `INVALID_BADGE` when no live
/// process carries the badge; `INVALID_ARGUMENT` for a zero length or a
/// range past the address space; `OUT_OF_MEMORY` when a chunk could not be
/// restored. A process that declared itself undebuggable is served too,
/// since the request reads and writes nothing of it.
/// Specified in `services/procmgr/docs/ipc-interface.md` § `MAKE_RESIDENT`.
pub const MAKE_RESIDENT: u64 = 30;

/// Read a signed data file for the sender and give it the body read-only,
/// once it verifies (docs/signing.md § Verifier Discipline). Sent on the
/// sender's own procmgr cap: a process handle, which names another
/// process, is refused `INVALID_BADGE`, as is a badge no live process
/// carries.
///
/// `data[0]` is the file's length in bytes, 1 to [`READ_VERIFIED_MAX`];
/// from word [`READ_VERIFIED_NAME_WORD`] the name block
/// (`crate::with_name_block`, at most [`CREATE_NAME_MAX`] bytes): the
/// install path the file must be signed under, in the data role. `caps[0]`
/// is the file cap, which procmgr opens, reads once (`FS_READ_MEMORY`) into
/// one run of frames it requests on the sender's memmgr account and maps
/// in its own address space alone, and deletes. procmgr verifies the copy
/// in the data role under the name, for this architecture.
///
/// Replies `SUCCESS` with `data[0]` the body's length, `data[1]` the
/// run's region id on the sender's account and `data[2]` its pages, and
/// `caps[0]` a Memory cap on the run carrying `RIGHTS_MEM_MAP` alone, whose
/// first `data[0]` bytes are the verified body; procmgr keeps no cap on the
/// run, so no process but memmgr can write it. The sender unmaps it,
/// deletes the cap and releases the region (`memmgr_labels::RELEASE_MEMORY_CAPS`
/// on its own memmgr cap) when done; its death releases it with its
/// record. Refusals: `INVALID_ARGUMENT` for a missing cap, a length of zero
/// or past the bound, or a missing or non-canonical name, before any read;
/// `SIGNATURE_REFUSED` when the copy does not verify; `IO_ERROR`,
/// `OUT_OF_MEMORY` and `MAP_FAILED` as for [`CREATE_FROM_FILE`]'s read.
/// Specified in `services/procmgr/docs/ipc-interface.md` § `READ_VERIFIED`.
pub const READ_VERIFIED: u64 = 31;

/// Give each page of a range of a process's memory-object attachments that
/// maps its object's frame a copy of its own, for a debugger about to
/// patch it: a `SYS_THREAD_WRITE_MEM` text write to such a page fails with
/// `InvalidState` while the page maps a frame the object's other attachers
/// map too, and succeeds once the page holds the copy. Served only on a
/// badge carrying [`DEBUG_AUTHORITY`]. `data[0]` is the target's process
/// badge, `data[1]` the address and `data[2]` the length in bytes, nonzero.
/// Pages outside every attachment, and pages that hold a copy already, are
/// passed over. Replies `SUCCESS` with `data[0]` where memmgr stopped,
/// which makes a bounded number of copies per request: the range's end when
/// it is all done, else the address to ask again from (`ipc::make_private`
/// asks until it is done); `UNAUTHORIZED` without the authority;
/// `INVALID_BADGE` when no live process carries the badge;
/// `NOT_ATTACHABLE` for a process that declared itself undebuggable
/// ([`DECLARE_NO_DEBUG`]), whose memory no debugger may write;
/// `INVALID_ARGUMENT` for a zero length or a range past the address space;
/// `OUT_OF_MEMORY` when a copy could not be made.
/// Specified in `services/procmgr/docs/ipc-interface.md` § `MAKE_PRIVATE`.
pub const MAKE_PRIVATE: u64 = 32;

/// Capture a live process's pages into a memory object for a debugger or a
/// core writer: procmgr holds the target's address space
/// (`SYS_ASPACE_HOLD`), so no thread of it runs, whether it registered or
/// not, records every page of its user half that a read could reach, each
/// as bytes copied into frames granted on the sender's memmgr account, as
/// zero, as the page of the target's image object the layout names, as a
/// page with no copy (device memory) or as absent, releases the space, and
/// seals the copy into an immutable memory object on that account
/// (`memmgr_labels::SEAL_OBJECT`), charged in full to it. Served only on a
/// badge carrying [`DEBUG_AUTHORITY`]. `data[0]` is the target's process
/// badge; `caps[0]` the sender's own memmgr SEND, the account procmgr
/// requests the frames on and seals through, each call on it bounded. The
/// object starts with a layout of the space's regions and runs, laid out as
/// `crate::procmgr_snapshot` states. Replies `SUCCESS` with `caps[0]` the
/// object's handle, `data[0]` the object's pages and `data[1]`
/// `crate::procmgr_snapshot::SNAPSHOT_COMPLETE` when no run is absent, else
/// `0`; `UNAUTHORIZED` without the authority;
/// `INVALID_ARGUMENT` without `caps[0]`; `INVALID_BADGE` when no live
/// process carries the badge, or it ended during the capture;
/// `NOT_ATTACHABLE` when it declared itself undebuggable; `SPACE_HELD` when
/// its space is held already; `OUT_OF_MEMORY` when the account refused or
/// failed a call, granted a run procmgr refuses, or the object would take
/// more grants than one seal names. Specified in
/// `services/procmgr/docs/ipc-interface.md` § Label 33: `SNAPSHOT`.
pub const SNAPSHOT: u64 = 33;

/// The most bytes a [`READ_VERIFIED`] file may hold, its trailer included:
/// 32 KiB, room for a platform description table
/// (`MAX_TABLE_BYTES`, 8 KiB) and the other policy-bearing configuration
/// files. procmgr refuses a longer request before it reads anything.
pub const READ_VERIFIED_MAX: u64 = 32 * 1024;

/// The data word of a [`READ_VERIFIED`] request holding the name block's
/// length, whose bytes follow.
pub const READ_VERIFIED_NAME_WORD: usize = 1;

/// The name a [`READ_VERIFIED`] request carries in its name block: `None`
/// when the request delivers no length word, the length is zero or above
/// [`CREATE_NAME_MAX`], or the words delivered do not cover the name's
/// bytes.
#[must_use]
pub fn read_verified_name(req: &crate::IpcMessage) -> Option<&[u8]>
{
    crate::name_block(req, READ_VERIFIED_NAME_WORD, CREATE_NAME_MAX)
}

/// Badge bit on procmgr service caps that authorises
/// [`REGISTER_CRASH_SERVICE`], [`ATTACH_PROCESS`], [`LIST_PROCESSES`],
/// [`DETACH_PROCESS`], [`MAKE_RESIDENT`], [`MAKE_PRIVATE`] and [`SNAPSHOT`]. svcmgr mints it for
/// a service whose definition sets `debug_authority = yes`; no other
/// path mints it. Who holds it is in
/// `services/procmgr/docs/ipc-interface.md` § `ATTACH_PROCESS`.
pub const DEBUG_AUTHORITY: u64 = 1u64 << 60;
const _: () = core::assert!(
    DEBUG_AUTHORITY & crate::VERB_BIT_MASK != 0
        && DEBUG_AUTHORITY != DEATH_EQ_AUTHORITY
        && DEBUG_AUTHORITY != HOLD_RELEASE_AUTHORITY
);

/// Hand init's kernel-object caps and reclaimable Memory caps to
/// procmgr for the reap after init exits; init calls it on its exit
/// path, then `sys_thread_exit`s. The rounds, the death-EQ binding on
/// both init threads (correlator [`INIT_REAP_CORRELATOR`]), and the
/// replies are specified in `services/procmgr/docs/ipc-interface.md`
/// § `REGISTER_INIT_TEARDOWN` — init reap handoff.
pub const REGISTER_INIT_TEARDOWN: u64 = 15;

/// Notification end of init's reap-handoff cap stream. After this call
/// init has no caps left to transfer; procmgr's state machine
/// transitions to "armed". Init calls `sys_thread_exit` immediately
/// after this IPC replies. Replies `UNAUTHORIZED` from a badged sender,
/// and `INVALID_ARGUMENT` when no handoff is open or the state machine
/// is already armed.
pub const INIT_TEARDOWN_DONE: u64 = 16;

/// Report the outcome of init's reap. Any caller; no caps, no state
/// change. Reply `SUCCESS` with `data[0]` = 1 once the reap has run (0
/// before) and `data[1]` = the release probe's outcome, one of
/// [`INIT_REAP_PROBE_UNCHECKED`], [`INIT_REAP_PROBE_RELEASED`], or
/// [`INIT_REAP_PROBE_HELD`]. Specified in
/// `services/procmgr/docs/ipc-interface.md` § `QUERY_INIT_REAP`.
pub const QUERY_INIT_REAP: u64 = 17;

/// [`QUERY_INIT_REAP`] probe outcome: no probe result (the reap has not
/// run, or procmgr could not place the probe).
pub const INIT_REAP_PROBE_UNCHECKED: u64 = 0;
/// [`QUERY_INIT_REAP`] probe outcome: deleting procmgr's cap on init's
/// `CSpace` freed it, releasing the probe endpoint init's `CSpace` held.
pub const INIT_REAP_PROBE_RELEASED: u64 = 1;
/// [`QUERY_INIT_REAP`] probe outcome: the probe endpoint survived the
/// deletion, so init's `CSpace` was not freed.
pub const INIT_REAP_PROBE_HELD: u64 = 2;

/// Reserved death-notification correlator used by `REGISTER_INIT_TEARDOWN`.
/// Per-child correlators are the full process badge; procmgr redraws a
/// random badge below `log_badges::LOG_BADGE_FIRST_CHILD`, equal to this
/// value, or carrying a `VERB_BIT_MASK` bit (this value carries all of
/// them), so the two never collide.
pub const INIT_REAP_CORRELATOR: u64 = u64::MAX;

#[cfg(test)]
mod tests
{
    use crate::{IpcMessage, MSG_DATA_WORDS_MAX, procmgr_labels, svcmgr_labels};

    #[test]
    fn a_create_name_block_follows_every_other_create_word()
    {
        use procmgr_labels::{
            CREATE_ARGV_ENV, CREATE_FROM_FILE, CREATE_MEMORY_MAX, CREATE_PROCESS, create_name_word,
        };
        assert_eq!(create_name_word(CREATE_PROCESS), 1);
        assert_eq!(create_name_word(CREATE_FROM_FILE | CREATE_MEMORY_MAX), 2);
        assert_eq!(create_name_word(CREATE_PROCESS | CREATE_ARGV_ENV), 5);
        assert_eq!(
            create_name_word(CREATE_FROM_FILE | CREATE_ARGV_ENV | CREATE_MEMORY_MAX),
            6
        );
    }

    #[test]
    fn a_create_name_round_trips_at_every_length()
    {
        use procmgr_labels::{
            CREATE_ARGV_ENV, CREATE_FROM_FILE, CREATE_MEMORY_MAX, CREATE_NAME_MAX, create_name,
            with_create_name,
        };
        let label = CREATE_FROM_FILE | CREATE_ARGV_ENV | CREATE_MEMORY_MAX;
        let mut name = [0u8; CREATE_NAME_MAX];
        for (i, byte) in name.iter_mut().enumerate()
        {
            *byte = b'a' + (i % 26) as u8;
        }
        for len in [1, 7, 8, 9, 16, 17, CREATE_NAME_MAX]
        {
            let builder = IpcMessage::builder(label).word(0, 4096).word(5, 9);
            let msg = with_create_name(builder, label, &name[..len])
                .unwrap()
                .build();
            assert_eq!(create_name(&msg), Some(&name[..len]), "length {len}");
            // The words before the block are untouched.
            assert_eq!((msg.word(0), msg.word(5)), (4096, 9));
        }
    }

    #[test]
    fn a_create_name_block_that_is_missing_empty_long_or_short_is_refused()
    {
        use procmgr_labels::{
            CREATE_FROM_FILE, CREATE_NAME_MAX, CREATE_PROCESS, create_name, with_create_name,
        };
        let long = [b'x'; CREATE_NAME_MAX + 1];
        let builder = || IpcMessage::builder(CREATE_PROCESS).word(0, 4096);
        assert!(with_create_name(builder(), CREATE_PROCESS, b"").is_none());
        assert!(with_create_name(builder(), CREATE_PROCESS, &long).is_none());
        // No length word delivered.
        assert_eq!(create_name(&builder().build()), None);
        // A zero or over-long length word.
        assert_eq!(create_name(&builder().word(1, 0).build()), None);
        let over = builder()
            .word(1, CREATE_NAME_MAX as u64 + 1)
            .bytes(2, &long);
        assert_eq!(create_name(&over.build()), None);
        // A length the delivered words do not cover.
        let short = IpcMessage::builder(CREATE_FROM_FILE)
            .word(0, 1)
            .word(1, 9)
            .bytes(2, b"/abcdefg");
        assert_eq!(create_name(&short.build()), None);
    }

    #[test]
    fn a_process_list_page_round_trips_names_of_every_length()
    {
        use procmgr_labels::{LIST_PROCESSES_PAGE, pack_list_entry, unpack_list_entry};
        let long = [b'x'; svcmgr_labels::NAME_MAX];
        let names: [&[u8]; 4] = [b"svctest", &long, b"", b"seven77"];
        let mut words = [0u64; MSG_DATA_WORDS_MAX];
        for (i, name) in names.iter().enumerate()
        {
            assert!(pack_list_entry(&mut words, i, 0x100 + i as u64, name));
        }
        words[0] = names.len() as u64;
        for (i, name) in names.iter().enumerate()
        {
            let mut out = [0u8; svcmgr_labels::NAME_MAX];
            let (badge, len) = unpack_list_entry(&words, i, &mut out).unwrap();
            assert_eq!((badge, &out[..len]), (0x100 + i as u64, *name));
        }
        assert!(
            unpack_list_entry(&words, names.len(), &mut [0; svcmgr_labels::NAME_MAX]).is_none()
        );
        // A full page fits the message, and the entry past it does not.
        assert!(pack_list_entry(
            &mut words,
            LIST_PROCESSES_PAGE - 1,
            1,
            b"a"
        ));
        assert!(!pack_list_entry(&mut words, LIST_PROCESSES_PAGE, 1, b"a"));
    }

    #[test]
    fn a_process_list_entry_truncates_a_long_name_and_refuses_a_long_length()
    {
        use procmgr_labels::{pack_list_entry, unpack_list_entry};
        let mut words = [0u64; MSG_DATA_WORDS_MAX];
        let long = [b'n'; svcmgr_labels::NAME_MAX + 9];
        assert!(pack_list_entry(&mut words, 0, 7, &long));
        words[0] = 1;
        let mut out = [0u8; svcmgr_labels::NAME_MAX];
        assert_eq!(
            unpack_list_entry(&words, 0, &mut out),
            Some((7, svcmgr_labels::NAME_MAX))
        );
        words[2] = svcmgr_labels::NAME_MAX as u64 + 1;
        assert!(unpack_list_entry(&words, 0, &mut out).is_none());
    }

    // The defect caught: an entry index whose word offset overflows `usize`,
    // which wrapped to a small offset and wrote or read another entry.
    #[test]
    fn a_process_list_index_whose_offset_overflows_is_refused()
    {
        use procmgr_labels::{LIST_PROCESSES_WORDS_PER_ENTRY, pack_list_entry, unpack_list_entry};
        let index = usize::MAX / LIST_PROCESSES_WORDS_PER_ENTRY + 1;
        let mut words = [0u64; MSG_DATA_WORDS_MAX];
        assert!(!pack_list_entry(&mut words, index, 7, b"a"));
        assert_eq!(words, [0; MSG_DATA_WORDS_MAX]);
        words[0] = u64::MAX;
        let mut out = [0u8; svcmgr_labels::NAME_MAX];
        assert!(unpack_list_entry(&words, index, &mut out).is_none());
    }
}
