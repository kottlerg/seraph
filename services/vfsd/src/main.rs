// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/vfsd/src/main.rs

//! Seraph virtual filesystem daemon.
//!
//! vfsd presents a unified virtual filesystem namespace to all other
//! processes via a synthetic system-root cap. A mount installs a
//! badged SEND on the underlying driver's namespace endpoint into
//! `VfsdRootBackend`; clients walk that root via `NS_LOOKUP` and reach
//! per-file node caps directly on the driver. After the walk vfsd is
//! out of the path: file reads, memory-cap requests, and closes go straight
//! from client to driver.
//!
//! vfsd self-mounts the Seraph root partition at `/` (and the ESP at
//! `/esp` and the data partition at `/data`) during startup, before
//! serving any request; the runtime `MOUNT` IPC remains for
//! explicit/foreign-GUID mounts.
//!
//! See `services/vfsd/README.md` for the design and
//! `services/fs/docs/fs-driver-protocol.md` for the driver-side protocol.

mod driver;
mod partition;
mod role_guids;
mod worker;
mod worker_pool;

use std::os::seraph::startup_info;
use std::sync::{Mutex, PoisonError};

use ipc::{IpcMessage, blk_labels, ns_labels};
use namespace_protocol::{GateError, compose_forward_lookup_rights, gate};
use root_backend::VfsdRootBackend;
use worker_pool::WorkerPool;

/// Number of threads that recv on the service endpoint. A concurrency
/// knob that bounds no capacity: a request that finds every handler busy
/// waits in the endpoint's queue for the next free thread. No
/// service-endpoint request waits on another one, so the count cannot
/// deadlock: what a `MOUNT` handler blocks on (the worker pool, procmgr's
/// `CREATE_FROM_FILE`, whose binary reads go to the fs driver that minted
/// the file cap, the `NS_LOOKUP` walk the namespace thread serves, and the
/// driver's `FS_MOUNT` probe) never calls the service endpoint.
const SERVICE_THREAD_COUNT: usize = 4;

/// Longest mount path a `MOUNT` request can name: the bytes the request's
/// data words carry after the role and length words. Set by the IPC
/// message size, not a table; vfsd's only path limit, with each component
/// bounded by `namespace_protocol::MAX_NAME_LEN`.
const MAX_MOUNT_PATH_LEN: usize = (syscall_abi::MSG_DATA_WORDS_MAX - 2) * 8;

// ── Data structures ────────────────────────────────────────────────────────

pub struct VfsdCaps
{
    pub procmgr_ep: u32,
    pub memmgr_ep: u32,
    pub registry_ep: u32,
    pub service_ep: u32,
    pub fatfs_module_cap: u32,
    pub self_aspace: u32,
    /// Worker-owned bootstrap endpoint. Populated after the bootstrap worker
    /// thread is spawned. Main derives badged SEND caps on this slot to hand
    /// to each fatfs child as its creator endpoint.
    pub bootstrap_ep: u32,
}

// ── Bootstrap ──────────────────────────────────────────────────────────────
//
// init → vfsd bootstrap plan:
//   Round 1 (2 caps, 0 data words):
//     caps[0]: service endpoint (vfsd receives on this)
//     caps[1]: devmgr registry endpoint
//   Round 2 (1 cap, 0 data words):
//     caps[0]: fatfs module memory cap
//
// log_ep and procmgr_ep arrive via `ProcessInfo`/`StartupInfo`, not through
// this protocol.

fn bootstrap_caps(info: &std::os::seraph::StartupInfo, ipc_buf: *mut u64) -> Option<VfsdCaps>
{
    if info.creator_endpoint == 0
    {
        return None;
    }
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let round1 = unsafe { ipc::bootstrap::request_round(info.creator_endpoint, ipc_buf) }.ok()?;
    if round1.cap_count < 2 || round1.done
    {
        return None;
    }
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let round2 = unsafe { ipc::bootstrap::request_round(info.creator_endpoint, ipc_buf) }.ok()?;
    if round2.cap_count < 1 || !round2.done
    {
        return None;
    }

    Some(VfsdCaps {
        service_ep: round1.caps[0],
        registry_ep: round1.caps[1],
        procmgr_ep: info.procmgr_endpoint,
        memmgr_ep: info.memmgr_endpoint,
        fatfs_module_cap: round2.caps[0],
        self_aspace: info.self_aspace,
        bootstrap_ep: 0,
    })
}

// ── Entry point ────────────────────────────────────────────────────────────

// clippy::too_many_lines: vfsd's main is the in-order startup
// transcript — bootstrap caps, worker pool, devmgr query, GPT scratch
// alloc, GPT parse, namespace endpoint create, runtime leak,
// namespace-thread spawn, service-thread fanout, then the calling
// thread's own service loop. Each step depends on the prior step's
// locals; splitting introduces threading those locals through helper
// arguments without buying any structural clarity.
#[allow(clippy::too_many_lines)]
fn main() -> !
{
    std::os::seraph::log::register_name(b"vfsd");
    let info = startup_info();

    // IPC buffer is registered by `std::os::seraph::_start` and page-aligned
    // by the boot protocol; `info.ipc_buffer` carries the same VA as a
    // `*mut u8` we reinterpret as `*mut u64` (4 KiB page alignment ≫ u64).
    #[allow(clippy::cast_ptr_alignment)]
    let ipc_buf = info.ipc_buffer.cast::<u64>();

    let Some(mut caps) = bootstrap_caps(info, ipc_buf)
    else
    {
        syscall::thread_exit();
    };

    std::os::seraph::log!("starting");

    if caps.service_ep == 0 || caps.registry_ep == 0
    {
        std::os::seraph::log!("missing required endpoints");
        idle_loop();
    }

    // Spawn the worker pool before any MOUNT can arrive.
    let Some(pool) = WorkerPool::new()
    else
    {
        std::os::seraph::log!("FATAL: worker pool setup failed");
        idle_loop();
    };
    caps.bootstrap_ep = pool.bootstrap_ep();

    // Query devmgr for the block device endpoint.
    std::os::seraph::log!("querying devmgr for block device");
    let query_msg = IpcMessage::builder(ipc::devmgr_labels::QUERY_BLOCK_DEVICE)
        .word(0, u64::from(ipc::DEVMGR_LABELS_VERSION))
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer.
    let Ok(query_reply) = (unsafe { ipc::ipc_call(caps.registry_ep, &query_msg, ipc_buf) })
    else
    {
        std::os::seraph::log!("QUERY_BLOCK_DEVICE ipc_call failed");
        idle_loop();
    };
    if query_reply.label != 0
    {
        std::os::seraph::log!("no block device available");
        idle_loop();
    }

    let reply_caps = query_reply.caps();
    if reply_caps.is_empty()
    {
        std::os::seraph::log!("QUERY_BLOCK_DEVICE returned no caps");
        idle_loop();
    }
    let blk_ep = reply_caps[0];
    std::os::seraph::log!("block device endpoint acquired");

    // Allocate a single scratch memory cap for GPT block reads. The
    // BLK_READ_INTO_MEMORY contract requires the caller to supply the DMA
    // target memory cap; vfsd reuses one scratch page across all GPT reads.
    // The memory cap and its VA reservation are process-lifetime-leaked.
    let Some((mut scratch_cap, scratch_va)) =
        partition::alloc_scratch(caps.memmgr_ep, caps.self_aspace, ipc_buf)
    else
    {
        std::os::seraph::log!("FATAL: GPT scratch allocation failed");
        idle_loop();
    };

    // Parse GPT partition table — stored for UUID lookups on MOUNT requests.
    let gpt_parts = match partition::parse_gpt(blk_ep, ipc_buf, &mut scratch_cap, scratch_va)
    {
        Ok(parts) =>
        {
            std::os::seraph::log!("GPT parsed, {} partitions", parts.len());
            parts
        }
        Err(e) =>
        {
            match e
            {
                gpt::GptError::IoError => std::os::seraph::log!("GPT parse failed: I/O error"),
                gpt::GptError::InvalidSignature =>
                {
                    std::os::seraph::log!("GPT parse failed: invalid signature");
                }
                gpt::GptError::InvalidEntrySize =>
                {
                    std::os::seraph::log!("GPT parse failed: invalid entry size");
                }
                gpt::GptError::InvalidEntryArray =>
                {
                    std::os::seraph::log!(
                        "GPT parse failed: entry array outside LBA 2..first_usable_lba"
                    );
                }
            }
            Vec::new()
        }
    };

    // Namespace endpoint: separate recv surface for the cap-native
    // protocol (`NS_LOOKUP` / `NS_STAT` / `NS_READDIR`) against vfsd's
    // synthetic root. The service endpoint carries only `MOUNT` and
    // `GET_SYSTEM_ROOT_CAP`; the namespace endpoint is separated so
    // a single dispatcher thread can serve every walk without
    // contending with mount-table mutations.
    let Some(namespace_ep) =
        std::os::seraph::object_slab_retype(std::os::seraph::ENDPOINT_RETYPE_BYTES, |slab| {
            syscall::cap_create_endpoint(slab).ok()
        })
    else
    {
        std::os::seraph::log!("FATAL: cannot create namespace endpoint");
        idle_loop();
    };

    // Vfsd-internal system-root cap. Used for vfsd's own walks (e.g.
    // resolving `/services/fs/fatfs` before a worker spawns a fresh fatfs
    // instance via procmgr `CREATE_FROM_FILE`). Mirrors the cap shape
    // returned by `GET_SYSTEM_ROOT_CAP` to external callers.
    let badge = namespace_protocol::pack(
        namespace_protocol::NodeId::ROOT,
        namespace_protocol::NamespaceRights::ALL,
    );
    let Ok(system_root_cap) =
        syscall::cap_derive_badge(namespace_ep, syscall::RIGHTS_EP_SEND, badge)
    else
    {
        std::os::seraph::log!("FATAL: vfsd internal system-root cap derive failed");
        idle_loop();
    };

    let boot_module_cap = caps.fatfs_module_cap;
    let runtime: &'static VfsdRuntime = Box::leak(Box::new(VfsdRuntime {
        caps,
        blk_ep,
        gpt_parts,
        pool,
        boot_module_cap: Mutex::new(boot_module_cap),
        namespace_ep,
        system_root_cap,
        root_backend: Mutex::new(VfsdRootBackend::new()),
    }));

    // Spawn the namespace dispatcher first: the `/esp` self-mount below
    // takes the VFS spawn path, which re-enters vfsd's namespace endpoint
    // to resolve `/services/fs/fatfs`.
    if std::thread::Builder::new()
        .name("vfsd-namespace".into())
        .spawn(move || namespace_loop(runtime))
        .is_err()
    {
        std::os::seraph::log!("FATAL: namespace thread spawn failed");
        idle_loop();
    }

    // Self-mount the root filesystem (and the ESP) before any service
    // thread can serve `GET_SYSTEM_ROOT_CAP`, so the seed system-root cap
    // is never handed out against an unmounted root. On failure vfsd still
    // serves: `GET_SYSTEM_ROOT_CAP` replies `NO_MOUNT` so init FATALs
    // promptly rather than blocking forever.
    if !self_mount(runtime, ipc_buf)
    {
        std::os::seraph::log!("root unavailable; system-root requests will fail");
    }

    // Spawn N-1 helper service threads; main becomes the Nth handler. Each
    // thread runs the same recv/dispatch loop on the shared service endpoint.
    for i in 1..SERVICE_THREAD_COUNT
    {
        let name = std::format!("vfsd-service-{i}");
        if std::thread::Builder::new()
            .name(name)
            .spawn(move || service_loop(runtime))
            .is_err()
        {
            std::os::seraph::log!("FATAL: service helper thread spawn failed");
            idle_loop();
        }
    }

    std::os::seraph::log!("entering service loop");
    service_loop(runtime);
}

/// Live state shared by every service-handler thread. `Box::leak`ed at
/// startup so workers and helper threads can reference it as `'static`
/// without per-thread `Arc` clones.
pub struct VfsdRuntime
{
    pub caps: VfsdCaps,
    pub blk_ep: u32,
    /// Every used GPT partition entry, parsed once at startup.
    pub gpt_parts: Vec<gpt::GptEntry>,
    pub pool: WorkerPool,
    /// Boot-module fatfs cap consumed (and zeroed) by the very first MOUNT.
    /// Mutex-guarded because that MOUNT may land on any handler thread.
    pub boot_module_cap: Mutex<u32>,
    /// Un-badged SEND on vfsd's own namespace endpoint. Source of every
    /// node cap minted on the synthetic root (the system-root cap and
    /// any descendants that resolve to vfsd-local nodes — currently
    /// none, since the synthetic root only carries External entries).
    pub namespace_ep: u32,
    /// Badged SEND on `namespace_ep` addressing the synthetic root at
    /// full namespace rights. Vfsd's own copy of the system-root cap,
    /// minted at boot. Used by worker threads to walk the namespace
    /// (e.g. resolving `/services/fs/fatfs`) before issuing
    /// `procmgr_labels::CREATE_FROM_FILE`.
    pub system_root_cap: u32,
    /// Synthetic system-root backend. Service handlers append entries
    /// on each successful MOUNT; the namespace dispatcher reads on each
    /// `NS_*` request.
    pub root_backend: Mutex<VfsdRootBackend>,
}

// ── Service loop ───────────────────────────────────────────────────────────

/// `RecvGuard` diagnostic hook: one line at the start of a failure streak,
/// one more before the fatal exit. Shared by the service, namespace, and
/// bootstrap-worker receive loops.
pub(crate) fn recv_diag(stage: ipc::recv_guard::RecvFailureStage, err: i64)
{
    match stage
    {
        ipc::recv_guard::RecvFailureStage::First =>
        {
            std::os::seraph::log!("ipc_recv failing (err={err}); backing off");
        }
        ipc::recv_guard::RecvFailureStage::Fatal =>
        {
            std::os::seraph::log!("ipc_recv wedged (err={err}); exiting");
        }
    }
}

/// Service-handler entry. One copy of this loop runs per
/// [`SERVICE_THREAD_COUNT`] thread; all share the [`VfsdRuntime`].
/// The threads let independent requests proceed while one handler waits
/// on a fatfs spawn; correctness does not depend on their count (see
/// [`SERVICE_THREAD_COUNT`]).
///
/// Concurrency invariants. `MOUNT` routes into `do_mount`, and a
/// successful root `MOUNT` then auto-mounts `/esp` and `/data` through
/// `auto_mount_role`; all of them reach `do_mount_internal`, which
/// mutates shared runtime state under the `VfsdRuntime` mutexes:
/// - `rt.boot_module_cap` — Mutex; swapped to zero by the first mount
///   that reaches the driver spawn, whether or not it succeeds.
/// - `rt.root_backend` — Mutex; the synthetic-root tree's only
///   mutator. `VfsdRootBackend::can_install` and
///   `VfsdRootBackend::install` reject an already-terminal entry, so
///   two concurrent MOUNTs targeting the same path serialise on the
///   lock and the loser sees `can_install` (or, if both pass that
///   check before either installs, `install`) reject.
///
/// No `do_mount`-touched state is shared without one of these locks.
fn service_loop(rt: &'static VfsdRuntime) -> !
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    if ipc_buf.is_null()
    {
        std::os::seraph::log!("service thread has no registered IPC buffer");
        syscall::thread_exit();
    }

    let mut guard = ipc::recv_guard::RecvGuard::new(recv_diag);
    loop
    {
        // SAFETY: ipc_buf is the thread-registered IPC buffer page.
        let recv = match unsafe { ipc::ipc_recv(rt.caps.service_ep, ipc_buf) }
        {
            Ok(recv) => recv,
            Err(e) =>
            {
                guard.on_failure(e);
                continue;
            }
        };
        guard.on_success();

        let label = recv.label;
        let opcode = label & 0xFFFF;
        let badge = recv.badge;

        match opcode
        {
            ipc::vfsd_labels::MOUNT =>
            {
                // Verb-bit gate (docs/capability-model.md): MOUNT spawns a
                // driver and installs a mount, so only a MOUNT_AUTHORITY
                // badge reaches the handler.
                if badge & ipc::vfsd_labels::MOUNT_AUTHORITY == 0
                {
                    std::os::seraph::log!("MOUNT rejected: badge lacks MOUNT_AUTHORITY");
                    let err = IpcMessage::new(ipc::vfsd_errors::UNAUTHORIZED);
                    // SAFETY: ipc_buf is the thread-registered IPC buffer page.
                    let _ = unsafe { ipc::ipc_reply(&err, ipc_buf) };
                }
                else
                {
                    handle_mount_request(&recv, ipc_buf, rt);
                }
            }
            ipc::vfsd_labels::GET_SYSTEM_ROOT_CAP =>
            {
                if badge & ipc::vfsd_labels::SEED_AUTHORITY == 0
                {
                    std::os::seraph::log!(
                        "GET_SYSTEM_ROOT_CAP rejected: badge lacks SEED_AUTHORITY"
                    );
                    let err = IpcMessage::new(ipc::vfsd_errors::UNAUTHORIZED);
                    // SAFETY: ipc_buf is the thread-registered IPC buffer page.
                    let _ = unsafe { ipc::ipc_reply(&err, ipc_buf) };
                }
                else if recv.word(0) != u64::from(ipc::VFSD_LABELS_VERSION)
                {
                    std::os::seraph::log!(
                        "GET_SYSTEM_ROOT_CAP rejected: caller VFSD_LABELS_VERSION={} expected {}",
                        recv.word(0),
                        ipc::VFSD_LABELS_VERSION
                    );
                    let err = IpcMessage::new(ipc::vfsd_errors::LABEL_VERSION_MISMATCH);
                    // SAFETY: ipc_buf is the thread-registered IPC buffer page.
                    let _ = unsafe { ipc::ipc_reply(&err, ipc_buf) };
                }
                else
                {
                    handle_get_system_root_cap(ipc_buf, rt);
                }
            }
            _ =>
            {
                let err = IpcMessage::new(ipc::vfsd_errors::UNKNOWN_OPCODE);
                // SAFETY: ipc_buf is the thread-registered IPC buffer page.
                let _ = unsafe { ipc::ipc_reply(&err, ipc_buf) };
            }
        }
    }
}

// ── Namespace dispatcher ──────────────────────────────────────────────────

/// Dedicated thread that serves `NS_*` requests against vfsd's
/// synthetic root.
///
/// One thread is sufficient: every backend operation is an in-memory walk
/// of one node's children, or of one node's ancestors; the only blocking
/// call is the optional fall-through
/// `ipc_call` to a root-fs cap, which yields like any other IPC. A
/// multi-threaded recv on `namespace_ep` would only buy concurrency
/// between independent `NS_*` requests and is not load-bearing today.
///
/// Load-bearing single-thread invariant: [`try_forward_lookup_fallthrough`]
/// reuses this thread's registered `ipc_buf` page to receive the upstream
/// fall-through reply, overwriting the original inbound message in place.
/// A second dispatcher thread sharing the same `namespace_ep` (or a worker
/// pool servicing namespace requests) would corrupt that buffer mid-call.
/// Any future parallelism here must either give each worker its own
/// `ipc_buf` page (and an own-cap derivation) or move the fall-through to
/// a buffer-disjoint shape.
fn namespace_loop(rt: &'static VfsdRuntime) -> !
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    if ipc_buf.is_null()
    {
        std::os::seraph::log!("namespace thread has no registered IPC buffer");
        syscall::thread_exit();
    }

    let mut guard = ipc::recv_guard::RecvGuard::new(recv_diag);
    loop
    {
        // SAFETY: ipc_buf is the thread-registered IPC buffer page.
        let recv = match unsafe { ipc::ipc_recv(rt.namespace_ep, ipc_buf) }
        {
            Ok(recv) => recv,
            Err(e) =>
            {
                guard.on_failure(e);
                continue;
            }
        };
        guard.on_success();

        // Fall-through delegation: an `NS_LOOKUP` on any synthetic
        // tree node (the synthetic root or a multi-component
        // intermediate) for a name that does not match any local
        // child forwards verbatim to that node's `fallthrough_cap`.
        // The cap addresses the corresponding directory in the root
        // filesystem, captured at install time. This preserves the
        // namespace-model invariant that root-fs entries remain
        // reachable unless explicitly shadowed by a registered mount.
        if try_forward_lookup_fallthrough(rt, &recv, ipc_buf)
        {
            continue;
        }

        // Fall-through enumeration: an `NS_READDIR` on a synthetic node
        // with a `fallthrough_cap` lists its local children first, then
        // the underlying root-fs directory's entries, so a listing shows
        // both mounts and root-fs contents (mirroring lookup fall-through).
        if try_forward_readdir_fallthrough(rt, &recv, ipc_buf)
        {
            continue;
        }

        let mut backend = rt
            .root_backend
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        // SAFETY: ipc_buf invariant carried through; rt.namespace_ep is
        // the un-badged source for child caps minted by the protocol
        // crate's `cap_derive_badge` calls.
        unsafe {
            namespace_protocol::dispatch_request(&mut *backend, &recv, rt.namespace_ep, ipc_buf);
        }
    }
}

/// If `recv` is an `NS_LOOKUP` whose parent `NodeId` resolves to a
/// synthetic tree node that has no local child matching the requested
/// name, forward the request to that node's `fallthrough_cap` and
/// reply with the upstream response. Returns `true` when the request
/// was handled (caller skips normal dispatch).
///
/// The outbound message is rebuilt with the same label, name bytes,
/// and shape, but its `caller_requested` word (`word(0)`) is replaced
/// by the intersection of the caller's parent rights (extracted from
/// `recv.badge`) with the caller's original `caller_requested` —
/// computed via [`compose_forward_lookup_rights`]. Forwarding the
/// caller's `word(0)` verbatim would launder authority because the
/// receiving fs driver composes against the *destination cap's*
/// badge (the fall-through cap, full rights), not the caller's. The
/// reply travels back unchanged: any cap it surfaces is the upstream
/// fs's freshly-minted node cap, handed to the original caller
/// directly. vfsd performs no cap derivation here, so no per-lookup
/// cap leak in vfsd's `CSpace`.
fn try_forward_lookup_fallthrough(
    rt: &'static VfsdRuntime,
    recv: &IpcMessage,
    ipc_buf: *mut u64,
) -> bool
{
    let opcode = recv.label & 0xFFFF;
    if opcode != ns_labels::NS_LOOKUP
    {
        return false;
    }
    // Gate the request through namespace-protocol's per-label rights
    // table. On `Err`, fall through to the main path: `dispatch_request`
    // will produce the matching `NsError` reply (PermissionDenied or
    // NotSupported). Forwarding a request the caller could not have
    // issued locally would launder authority across the mount.
    let parent = match gate(recv.label, recv.badge)
    {
        Ok((node, _)) => node,
        Err(GateError::PermissionDenied | GateError::UnknownLabel) => return false,
    };
    // Cast is range-safe: name_len lives in bits 16..32 of the label.
    let name_len = ((recv.label >> 16) & 0xFFFF) as usize;
    let data_bytes = recv.data_bytes();
    if name_len == 0 || data_bytes.len() < 8 + name_len
    {
        return false;
    }
    let name = &data_bytes[8..8 + name_len];

    let backend = rt
        .root_backend
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let Some(parent_idx) = backend.resolve(parent)
    else
    {
        return false;
    };
    if backend.has_local_child(parent_idx, name)
    {
        return false;
    }
    let fallthrough = backend.fallthrough_of(parent_idx);
    drop(backend);
    if fallthrough == 0
    {
        return false;
    }

    // Repack the request: replace the caller's `word(0)` with the
    // intersection of their parent rights and their original request,
    // so the receiving fs driver's
    // `parent_rights ∩ entry.max_rights ∩ caller_requested`
    // composition reflects the original caller's authority rather
    // than the fall-through cap's full-rights badge.
    let composed_rights = compose_forward_lookup_rights(recv.badge, recv.word(0));
    let forward = IpcMessage::builder(recv.label)
        .word(0, u64::from(composed_rights))
        .bytes(1, name)
        .build();

    // SAFETY: ipc_buf is the thread-registered IPC buffer.
    let Ok(reply) = (unsafe { ipc::ipc_call(fallthrough, &forward, ipc_buf) })
    else
    {
        return false;
    };
    // SAFETY: ipc_buf is the thread-registered IPC buffer.
    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
    true
}

/// If `recv` is an `NS_READDIR` on a synthetic tree node that carries a
/// `fallthrough_cap`, serve the merged enumeration and return `true`
/// (caller skips normal dispatch). The node's local children occupy
/// indices `0..local_count` and are served by normal dispatch; this
/// handler serves higher indices from the fall-through directory,
/// skipping any name shadowed by a local child. Without it, listing a
/// synthetic node would show only its in-tree mounts and hide root-fs
/// entries reachable by name (e.g. `/programs`, `/data` under the
/// synthetic root), making enumeration inconsistent with lookup. An
/// index beyond `u32` is answered `END_OF_DIR` here, on any node the
/// caller may read, as the protocol crate answers it.
///
/// `NS_READDIR` surfaces names only — no caps — so, unlike lookup
/// fall-through, there is no authority to launder: the caller's
/// `READDIR` right is checked via [`gate`], and the fall-through probe
/// rides vfsd's own full-rights root cap.
///
/// Assumption: the probe applies no per-entry visibility filter (the
/// backend's `visible_requires` per `docs/namespace-model.md`). That is
/// sound only because no current fs backend hides entries by rights; a
/// backend that did would need the probe to compose the caller's rights
/// (as the lookup path does) before enumerating. Per client `NS_READDIR`
/// this re-probes the fall-through dir from index 0, so a full listing is
/// O(n²); acceptable for the small synthetic nodes (root, `/esp`).
fn try_forward_readdir_fallthrough(
    rt: &'static VfsdRuntime,
    recv: &IpcMessage,
    ipc_buf: *mut u64,
) -> bool
{
    let opcode = recv.label & 0xFFFF;
    if opcode != ns_labels::NS_READDIR
    {
        return false;
    }
    // Enforce the caller's READDIR right and resolve the directory node.
    // On `Err`, fall through to normal dispatch, which emits the matching
    // error reply.
    let dir = match gate(recv.label, recv.badge)
    {
        Ok((node, _)) => node,
        Err(GateError::PermissionDenied | GateError::UnknownLabel) => return false,
    };
    // An index beyond u32 cannot name an entry; answer `END_OF_DIR` as
    // namespace-protocol's `handle_readdir` does for the local children,
    // so both readdir paths agree.
    let Ok(idx) = u32::try_from(recv.word(0))
    else
    {
        let end = IpcMessage::new(ipc::fs_labels::END_OF_DIR);
        // SAFETY: ipc_buf is the thread-registered IPC buffer.
        let _ = unsafe { ipc::ipc_reply(&end, ipc_buf) };
        return true;
    };

    let backend = rt
        .root_backend
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let Some(parent_idx) = backend.resolve(dir)
    else
    {
        return false;
    };
    let fallthrough = backend.fallthrough_of(parent_idx);
    let local_count = backend.local_child_count(parent_idx);
    drop(backend);

    // No fall-through, or still within the local children: normal dispatch
    // serves it (a local child, then `END_OF_DIR` past the last one).
    if fallthrough == 0 || idx < local_count
    {
        return false;
    }

    // Enumerate the fall-through directory, skipping names shadowed by a
    // local child, until the `(idx - local_count)`-th survivor.
    let target = idx - local_count;
    let mut matched = 0u32;
    let mut probe = 0u32;
    loop
    {
        let req = IpcMessage::builder(ns_labels::NS_READDIR)
            .word(0, u64::from(probe))
            .build();
        // SAFETY: ipc_buf is the thread-registered IPC buffer.
        let Ok(reply) = (unsafe { ipc::ipc_call(fallthrough, &req, ipc_buf) })
        else
        {
            return false;
        };
        // `END_OF_DIR` or any upstream error terminates the merged
        // enumeration; forward it verbatim as the client's terminator.
        if reply.label != 0
        {
            // SAFETY: ipc_buf is the thread-registered IPC buffer.
            let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
            return true;
        }
        // Cast is range-safe: name_len rides word 1, bounded by the
        // protocol's max name length.
        #[allow(clippy::cast_possible_truncation)]
        let name_len = reply.word(1) as usize;
        let data = reply.data_bytes();
        // Reply layout: word 0 = kind, word 1 = name_len, name at byte 16.
        if name_len == 0 || data.len() < 16 + name_len
        {
            // Malformed upstream reply: terminate enumeration cleanly.
            let end = IpcMessage::new(ipc::fs_labels::END_OF_DIR);
            // SAFETY: ipc_buf is the thread-registered IPC buffer.
            let _ = unsafe { ipc::ipc_reply(&end, ipc_buf) };
            return true;
        }
        let name = &data[16..16 + name_len];
        let shadowed = {
            let backend = rt
                .root_backend
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            backend.has_local_child(parent_idx, name)
        };
        if !shadowed
        {
            if matched == target
            {
                // SAFETY: ipc_buf is the thread-registered IPC buffer.
                let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
                return true;
            }
            matched += 1;
        }
        probe += 1;
    }
}

// ── System-root cap delivery ─────────────────────────────────────────────

/// Handle [`vfsd_labels::GET_SYSTEM_ROOT_CAP`]: mint a fresh badged SEND
/// on vfsd's namespace endpoint addressing the synthetic root at full
/// rights and reply with it.
///
/// Source for the seed cap init holds at bootstrap and from which all
/// later tier-3 namespace-cap distribution flows. The dispatcher gates
/// this entry on [`vfsd_labels::SEED_AUTHORITY`] in the caller's
/// service-endpoint badge: holding the bit is equivalent to holding
/// the system-root cap, so only consumers explicitly entrusted with
/// seed authority reach this handler.
///
/// Replies [`vfsd_errors::NO_MOUNT`] when the root filesystem is not
/// mounted. vfsd self-mounts root before any service thread starts, so
/// this fires only when the self-mount failed (no `SERAPH_ROOT`
/// partition, or fatfs bring-up failed); init then FATALs instead of
/// receiving a system-root cap that resolves against an empty root.
fn handle_get_system_root_cap(ipc_buf: *mut u64, rt: &VfsdRuntime)
{
    if rt
        .root_backend
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .root_mount_cap()
        == 0
    {
        std::os::seraph::log!("GET_SYSTEM_ROOT_CAP rejected: root not mounted");
        let err = IpcMessage::new(ipc::vfsd_errors::NO_MOUNT);
        // SAFETY: ipc_buf is the thread-registered IPC buffer page.
        let _ = unsafe { ipc::ipc_reply(&err, ipc_buf) };
        return;
    }

    let badge = namespace_protocol::pack(
        namespace_protocol::NodeId::ROOT,
        namespace_protocol::NamespaceRights::ALL,
    );
    let reply = if let Ok(cap) =
        syscall::cap_derive_badge(rt.namespace_ep, syscall::RIGHTS_EP_SEND, badge)
    {
        IpcMessage::builder(ipc::vfsd_errors::SUCCESS)
            .cap(cap)
            .build()
    }
    else
    {
        std::os::seraph::log!("GET_SYSTEM_ROOT_CAP derive failed");
        IpcMessage::new(ipc::vfsd_errors::IO_ERROR)
    };
    // SAFETY: ipc_buf is the thread-registered IPC buffer page.
    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
}

// ── MOUNT handler ──────────────────────────────────────────────────────────

/// Mount role decoded from the MOUNT IPC wire byte. The producer
/// (init) declares which partition role it wants; vfsd resolves the
/// role to a GPT type-GUID via [`MountRole::type_guid`] and then to a
/// partition entry via [`gpt::lookup_partition_by_type_guid`].
#[derive(Clone, Copy, Debug)]
enum MountRole
{
    /// Seraph rootfs (`role_guids::SERAPH_ROOT`).
    Root,
    /// Seraph data partition (`role_guids::SERAPH_DATA`), auto-mounted at
    /// `/data`.
    Data,
}

impl MountRole
{
    fn from_wire(byte: u8) -> Option<Self>
    {
        match byte
        {
            0 => Some(MountRole::Root),
            1 => Some(MountRole::Data),
            _ => None,
        }
    }

    fn type_guid(self) -> &'static [u8; 16]
    {
        match self
        {
            MountRole::Root => &role_guids::SERAPH_ROOT,
            MountRole::Data => &role_guids::SERAPH_DATA,
        }
    }
}

/// Mount the Seraph root partition at `/`, then auto-mount the ESP at
/// `/esp` and the data partition at `/data`, during vfsd startup.
///
/// Runs on the main thread before any service handler exists, so a
/// `GET_SYSTEM_ROOT_CAP` request can never observe an unmounted root.
/// The namespace dispatcher must already be running: the `/esp` and
/// `/data` mounts take the VFS spawn path, which re-enters vfsd's
/// namespace endpoint to resolve `/services/fs/fatfs`. Returns whether
/// the root mount succeeded; `/esp` and `/data` are best-effort and never
/// gate the return value.
fn self_mount(rt: &VfsdRuntime, ipc_buf: *mut u64) -> bool
{
    match do_mount_internal(rt, ipc_buf, &role_guids::SERAPH_ROOT, b"/")
    {
        Ok(caller_root_cap) =>
        {
            // The per-mount caller cap rides back to an IPC caller; the
            // self-mount has none, and vfsd reaches root through the
            // synthetic backend, so drop it.
            log_cap_delete("self-mount caller_root_cap", caller_root_cap);
            std::os::seraph::log!("root self-mounted at /");
        }
        Err(code) =>
        {
            std::os::seraph::log!("FATAL: root self-mount failed: code={code:#x}");
            return false;
        }
    }

    auto_mount_role(rt, ipc_buf, &role_guids::EFI_SYSTEM_PARTITION, "/esp");
    auto_mount_role(rt, ipc_buf, &role_guids::SERAPH_DATA, "/data");
    true
}

/// Handle a runtime MOUNT request from an authorized client.
///
/// vfsd self-mounts root, `/esp`, and `/data` at startup ([`self_mount`]);
/// MOUNT remains the explicit / runtime-mount surface (foreign-GUID disks,
/// user-invoked mounts), and svctest is its only in-tree caller. The
/// service loop admits a request here only when the caller's badge carries
/// `vfsd_labels::MOUNT_AUTHORITY`.
///
/// IPC data layout (boot protocol v8+):
/// - `data[0]` low byte: [`MountRole`] discriminant
/// - `data[1]`: mount path length
/// - `data[2..]`: mount path bytes (packed into u64 words)
///
/// Decodes the wire payload and delegates to [`do_mount`] for the
/// real work. When the requested role is [`MountRole::Root`], vfsd
/// additionally auto-mounts the EFI System Partition at `/esp` and the
/// data partition at `/data`.
// cast_possible_truncation: the role byte is the low byte of data[0] by wire
// contract, and the path length is checked against 1..=MAX_MOUNT_PATH_LEN
// right after its cast, so neither `as` loses a value the handler accepts.
#[allow(clippy::cast_possible_truncation)]
fn handle_mount_request(recv: &IpcMessage, ipc_buf: *mut u64, rt: &VfsdRuntime)
{
    let role_byte = recv.word(0) as u8;
    let Some(role) = MountRole::from_wire(role_byte)
    else
    {
        std::os::seraph::log!("MOUNT: unknown role byte {role_byte}");
        let err = IpcMessage::new(ipc::vfsd_errors::NOT_FOUND);
        // SAFETY: ipc_buf is the registered IPC buffer.
        let _ = unsafe { ipc::ipc_reply(&err, ipc_buf) };
        return;
    };

    let path_len = recv.word(1) as usize;
    if path_len == 0 || path_len > MAX_MOUNT_PATH_LEN
    {
        std::os::seraph::log!("MOUNT: invalid path length");
        let err = IpcMessage::new(ipc::vfsd_errors::NOT_FOUND);
        // SAFETY: ipc_buf is the registered IPC buffer.
        let _ = unsafe { ipc::ipc_reply(&err, ipc_buf) };
        return;
    }

    let path_bytes = recv.data_bytes();
    // Path bytes start at word 2 (byte offset 16) under the new wire shape.
    let path_src_start = 2 * 8;
    let Some(path) = path_bytes.get(path_src_start..path_src_start + path_len)
    else
    {
        // The data words carry fewer path bytes than `data[1]` claims;
        // mounting the bytes that are there would name a different path.
        std::os::seraph::log!("MOUNT: path shorter than its stated length");
        let err = IpcMessage::new(ipc::vfsd_errors::NOT_FOUND);
        // SAFETY: ipc_buf is the registered IPC buffer.
        let _ = unsafe { ipc::ipc_reply(&err, ipc_buf) };
        return;
    };

    let reply = match do_mount(rt, ipc_buf, role, path)
    {
        Ok(0) => IpcMessage::new(ipc::vfsd_errors::SUCCESS),
        Ok(cap) => IpcMessage::builder(ipc::vfsd_errors::SUCCESS)
            .cap(cap)
            .build(),
        Err(label) => IpcMessage::new(label),
    };

    // Auto-mount the EFI System Partition at /esp and the data partition
    // at /data once root is up, so userspace can read kernel + bundle +
    // bootloader and the data tree without a separate MOUNT call.
    // Best-effort — failure does not propagate into the root mount's reply.
    if matches!(role, MountRole::Root) && reply.label == ipc::vfsd_errors::SUCCESS
    {
        auto_mount_role(rt, ipc_buf, &role_guids::EFI_SYSTEM_PARTITION, "/esp");
        auto_mount_role(rt, ipc_buf, &role_guids::SERAPH_DATA, "/data");
    }

    // SAFETY: ipc_buf is the registered IPC buffer.
    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
}

/// One-shot best-effort mount of the partition tagged `type_guid` at
/// `mount_path`. Scans the parsed GPT for a matching partition; if
/// none is present (or its role lookup is ambiguous), logs a diagnostic
/// and returns without mounting, leaving `mount_path` to resolve through
/// the root-fs fall-through. On a match, runs the mount transaction and
/// logs the outcome. Never fatal — distinct from the root self-mount,
/// whose failure gates boot. Idempotent if invoked twice: a mount on an
/// already-terminal mount path is rejected by
/// [`VfsdRootBackend::can_install`] before any partition is registered or
/// driver spawned.
fn auto_mount_role(rt: &VfsdRuntime, ipc_buf: *mut u64, type_guid: &[u8; 16], mount_path: &str)
{
    let present = rt.gpt_parts.iter().any(|p| &p.type_guid == type_guid);
    if !present
    {
        std::os::seraph::log!("MOUNT: no partition for {mount_path}; skipping auto-mount");
        return;
    }
    match do_mount_internal(rt, ipc_buf, type_guid, mount_path.as_bytes())
    {
        Ok(caller_cap) =>
        {
            // The auto-mount has no IPC caller for the returned badged SEND;
            // vfsd reaches the mount through its synthetic backend.
            log_cap_delete("auto-mount caller cap", caller_cap);
            std::os::seraph::log!("MOUNT: {mount_path} auto-mounted");
        }
        Err(code) => std::os::seraph::log!("MOUNT: {mount_path} auto-mount failed: code={code:#x}"),
    }
}

/// Delete `slot` and log the kernel error code on failure. A no-op on
/// `slot == 0` (sentinel for "no cap held"). Used at every `cap_delete`
/// site whose failure would otherwise be operator-invisible: the kernel
/// reports invalid-slot / table-corruption via the returned code and
/// silent discards leak that notification.
fn log_cap_delete(context: &str, slot: u32)
{
    if slot == 0
    {
        return;
    }
    if let Err(code) = syscall::cap_delete(slot)
    {
        std::os::seraph::log!("MOUNT: cap_delete({context}, slot={slot}) failed: code={code}");
    }
}

/// Whether `path` denotes the mount root — `/`, the empty path, or an
/// all-separator string like `///` — i.e. has no non-empty component.
/// Mirrors [`VfsdRootBackend::install`]'s root-vs-terminal split so the
/// mount transaction stores the matching cap kind for each role: a
/// badged fall-through SEND for the root, the unbadged driver endpoint
/// for a terminal mount.
fn mount_path_is_root(path: &[u8]) -> bool
{
    path.split(|&b| b == b'/').all(<[u8]>::is_empty)
}

/// Mount a partition identified by `uuid` at `path`.
///
/// Looks up the UUID in the GPT table, registers the partition bound
/// with virtio-blk, spawns a fatfs driver, registers a mount entry,
/// and captures the driver's namespace endpoint (terminal mounts) or a
/// badged SEND on the root fs (the root mount) into [`VfsdRootBackend`]
/// so the system-root cap can resolve through the new mount.
///
/// On success returns a fresh badged SEND for the caller (zero if
/// minting failed; the mount itself still landed). On failure
/// returns the matching `vfsd_errors::*` label.
pub(crate) fn do_mount(
    rt: &VfsdRuntime,
    ipc_buf: *mut u64,
    role: MountRole,
    path: &[u8],
) -> Result<u32, u64>
{
    do_mount_internal(rt, ipc_buf, role.type_guid(), path)
}

/// Shared implementation for both role-driven (`do_mount`) and
/// internally-triggered (`auto_mount_role`) mounts. Takes a type-GUID
/// directly so callers without a [`MountRole`] (the `/esp` and `/data`
/// auto-mounts) can reuse the transaction body.
// too_many_lines: the mount-and-publish transaction runs inline. The
// install pre-check, partition registration with virtio-blk, fatfs spawn,
// synthetic-root install, and namespace-root cap minting share the
// `partition_ep` / `fatfs` / `driver_ep` locals, and every failure arm after
// the spawn tears the driver down through `fatfs.endpoint`; folding a subset
// into helpers would thread those locals through and hide which arm releases
// what.
#[allow(clippy::too_many_lines)]
fn do_mount_internal(
    rt: &VfsdRuntime,
    ipc_buf: *mut u64,
    type_guid: &[u8; 16],
    path: &[u8],
) -> Result<u32, u64>
{
    let (partition_lba, partition_len) =
        match gpt::lookup_partition_by_type_guid(type_guid, &rt.gpt_parts)
        {
            Ok(pair) => pair,
            Err(gpt::GptLookupError::NotFound) =>
            {
                std::os::seraph::log!("MOUNT: partition role GUID not found");
                return Err(ipc::vfsd_errors::NO_MOUNT);
            }
            Err(gpt::GptLookupError::DuplicateTie) =>
            {
                // Non-fatal here; the caller decides (root self-mount treats
                // the returned error as fatal, the /esp and /data auto-mounts
                // skip and fall through).
                std::os::seraph::log!(
                    "MOUNT: role GUID matched by multiple tied-priority partitions; not mounting"
                );
                return Err(ipc::vfsd_errors::NO_MOUNT);
            }
        };
    std::os::seraph::log!(
        "MOUNT: partition LBA={partition_lba:#018x} length={partition_len:#018x}"
    );

    // Reject a mount the synthetic root would refuse (root already mounted,
    // `path` already a mount point, or a component the namespace protocol
    // cannot name) before registering a partition or spawning a driver for
    // it.
    let installable = rt
        .root_backend
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .can_install(path);
    if !installable
    {
        std::os::seraph::log!("MOUNT: mount point taken or path not installable");
        return Err(ipc::vfsd_errors::TABLE_FULL);
    }

    let Some(partition_ep) =
        derive_and_register_partition(rt, partition_lba, partition_len, ipc_buf)
    else
    {
        std::os::seraph::log!("MOUNT: partition cap registration failed");
        return Err(ipc::vfsd_errors::SPAWN_FAILED);
    };

    // First MOUNT (root) consumes the boot module cap; later mounts pass 0
    // and the spawn path walks vfsd's own system-root cap to /services/fs/fatfs
    // and uses procmgr `CREATE_FROM_FILE` via a worker. Hold the lock
    // only across the swap so other handlers can read it (and observe
    // 0) immediately.
    let module_cap_for_spawn = {
        let mut bmc = rt
            .boot_module_cap
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let v = *bmc;
        *bmc = 0;
        v
    };

    // `spawn_fatfs_driver` owns `partition_ep` from here: it is the child's
    // on success and released on failure.
    let Some(fatfs) = driver::spawn_fatfs_driver(
        &rt.caps,
        &rt.pool,
        partition_ep,
        module_cap_for_spawn,
        rt.system_root_cap,
        ipc_buf,
    )
    else
    {
        std::os::seraph::log!("MOUNT: failed to spawn fatfs");
        log_cap_delete("module_cap (spawn-fail)", module_cap_for_spawn);
        return Err(ipc::vfsd_errors::SPAWN_FAILED);
    };
    let driver_ep = fatfs.send;

    // Root MOUNT succeeded — drop the boot module cap. The IPC has already
    // transferred a derived child to procmgr; this releases vfsd's outer slot.
    log_cap_delete("module_cap (post-spawn)", module_cap_for_spawn);

    // The MOUNT caller receives a full-rights badged SEND on this
    // mount's root (the mounter holds full authority over the mount it
    // requested); internal/auto callers drop it. Revocation is
    // destroy-the-fs-driver: `cap_revoke` on the driver's namespace
    // endpoint cascades through the kernel derivation graph and
    // invalidates every cap ever derived from it — the namespace-model
    // `kill the server` shape (see `docs/namespace-model.md`
    // § Revocation). Per-cap revocation is not supported by this scheme.
    let root_badge = namespace_protocol::pack(
        namespace_protocol::NodeId::ROOT,
        namespace_protocol::NamespaceRights::ALL,
    );
    let caller_root_cap =
        syscall::cap_derive_badge(driver_ep, syscall::RIGHTS_EP_SEND, root_badge).ok();

    // What the backend retains for this mount depends on its role:
    //   - Root mount (`/`): a *badged* full-rights SEND on the root fs,
    //     kept as the synthetic root's `fallthrough_cap`. The
    //     fall-through forwarder pre-composes each forwarded request
    //     with the caller's own rights (`compose_forward_lookup_rights`),
    //     so a full-rights badge here cannot over-grant; `driver_ep` is
    //     not retained, and is deleted once the badged caps exist (they
    //     stay derived from `fatfs.endpoint`).
    //   - Terminal mount (`/esp`, `/data`, …): the *unbadged* driver
    //     endpoint itself. Every `NS_LOOKUP` crossing the mount mints a
    //     freshly-attenuated badged SEND from it (the
    //     `EntryTarget::External` arm of `handle_lookup`). Storing the
    //     endpoint rather than a pre-badged root cap is what carries
    //     attenuation across the mount boundary: the kernel forbids
    //     re-badging an already-badged cap, so a stored badged cap
    //     could only ever be `cap_derive`-copied at full rights.
    let install_cap = if mount_path_is_root(path)
    {
        let Ok(c) = syscall::cap_derive_badge(driver_ep, syscall::RIGHTS_EP_SEND, root_badge)
        else
        {
            std::os::seraph::log!("MOUNT: root fall-through cap derive failed");
            // Revoking the endpoint also invalidates `caller_root_cap` and
            // stops the driver, which nothing would reach otherwise.
            driver::teardown_driver(fatfs.endpoint);
            return Err(ipc::vfsd_errors::IO_ERROR);
        };
        c
    }
    else
    {
        driver_ep
    };

    // Install the mount; capture any synthetic intermediates created
    // along the path so we can populate their fall-through caps after
    // releasing the lock (the walk needs IPC and we must not block
    // other namespace traffic on it).
    let install_result = {
        let mut backend = rt
            .root_backend
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        backend.install(path, install_cap)
    };
    let Some(install_result) = install_result
    else
    {
        // A concurrent MOUNT took the mount point after the `can_install`
        // check, or the tree could not grow. Revoking the endpoint invalidates
        // `install_cap` and `caller_root_cap` (both derive from it) and
        // stops the driver nothing would reach.
        std::os::seraph::log!(
            "MOUNT: synthetic-root install failed (no memory or mount point taken)"
        );
        driver::teardown_driver(fatfs.endpoint);
        return Err(ipc::vfsd_errors::TABLE_FULL);
    };

    if install_cap != driver_ep
    {
        // Root mount: the badged fall-through and caller caps are derived,
        // so the unbadged SEND_GRANT has no further use.
        log_cap_delete("root mount driver_ep", driver_ep);
    }
    // `fatfs.endpoint` stays in vfsd's CSpace for the life of the mount
    // (every mount is permanent): it is the one handle that can revoke
    // the driver, per `driver::FatfsDriver`.

    populate_fallthrough_caps(rt, ipc_buf, install_result.as_slice());

    std::os::seraph::log!("MOUNT: registered");
    Ok(caller_root_cap.unwrap_or(0))
}

/// For each newly-created synthetic intermediate, walk the root mount
/// to the corresponding directory and record the resulting cap as
/// that intermediate's `fallthrough_cap`.
///
/// A walk that fails (root mount not yet installed, or the path does
/// not exist in the root filesystem) leaves `fallthrough_cap = 0`;
/// subsequent unmatched lookups against that intermediate then reply
/// `NotFound` instead of forwarding. Every skip is logged.
fn populate_fallthrough_caps(rt: &VfsdRuntime, ipc_buf: *mut u64, intermediates: &[u32])
{
    for &node_idx in intermediates
    {
        let (path, root_mount_cap) = {
            let backend = rt
                .root_backend
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            (backend.path_of(node_idx), backend.root_mount_cap())
        };
        let Some(path) = path
        else
        {
            std::os::seraph::log!(
                "MOUNT: fallthrough skip node_idx={node_idx}: no memory for its path",
            );
            continue;
        };
        if root_mount_cap == 0
        {
            std::os::seraph::log!(
                "MOUNT: fallthrough skip node_idx={node_idx}: no root mount installed",
            );
            continue;
        }
        if let Some(cap) = walk_root_mount_path(root_mount_cap, &path, ipc_buf)
        {
            let mut backend = rt
                .root_backend
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            backend.set_fallthrough_cap(node_idx, cap);
        }
        else
        {
            // Install validated every component as UTF-8 (`validate_name`).
            let shown = core::str::from_utf8(&path).unwrap_or("<non-UTF-8>");
            std::os::seraph::log!(
                "MOUNT: fallthrough skip node_idx={node_idx}: no directory {shown} in the root fs",
            );
        }
    }
}

/// Walk `root_mount_cap` to `path` (a `/`-prefixed slash-separated
/// component list) via per-component `NS_LOOKUP`. Each intermediate
/// cap is dropped as the walk descends; only the final cap survives,
/// returned to the caller. Returns `None` on any walk failure or if
/// any intermediate is not a directory.
fn walk_root_mount_path(root_mount_cap: u32, path: &[u8], ipc_buf: *mut u64) -> Option<u32>
{
    let stripped = path.strip_prefix(b"/").unwrap_or(path);
    if stripped.is_empty()
    {
        return None;
    }
    let mut current_cap: u32 = root_mount_cap;
    let mut current_owned = false;
    for component in stripped.split(|&b| b == b'/')
    {
        if component.is_empty()
        {
            continue;
        }
        // Components are bounded by `namespace_protocol::MAX_NAME_LEN`
        // (255), which `install` enforces, so the length fits the label's
        // 16-bit name-length field and the request's data words.
        let name_len = component.len() as u64;
        let label = ns_labels::NS_LOOKUP | (name_len << 16);
        let msg = IpcMessage::builder(label)
            .word(0, 0xFFFF)
            .bytes(1, component)
            .build();
        // SAFETY: ipc_buf is the thread-registered IPC buffer page.
        let reply = unsafe { ipc::ipc_call(current_cap, &msg, ipc_buf) };
        if current_owned
        {
            let _ = syscall::cap_delete(current_cap);
        }
        let Ok(reply) = reply
        else
        {
            return None;
        };
        if reply.label != 0
        {
            return None;
        }
        // word(0) is the entry kind; word(1) the size hint. We require
        // a directory at every walk step; a file at an intermediate
        // path means the install is structurally inconsistent.
        let kind = reply.word(0);
        if kind != namespace_protocol::NodeKind::Dir as u64
        {
            if let Some(&cap) = reply.caps().first()
            {
                let _ = syscall::cap_delete(cap);
            }
            return None;
        }
        let &next = reply.caps().first()?;
        current_cap = next;
        current_owned = true;
    }
    if current_owned
    {
        Some(current_cap)
    }
    else
    {
        None
    }
}

fn idle_loop() -> !
{
    loop
    {
        let _ = syscall::thread_yield();
    }
}

/// Register a partition bound with virtio-blk and receive back a
/// badged `SEND_GRANT` cap scoped to that partition.
///
/// vfsd's `rt.blk_ep` is itself a badged cap (the `blk_labels::MOUNT_AUTHORITY` cap
/// minted by devmgr), so vfsd cannot mint partition caps locally — the
/// kernel rejects re-badging of a badged source. Partition cap
/// derivation lives server-side in virtio-blk; this call just sends the
/// bounds and consumes the cap from the reply.
fn derive_and_register_partition(
    rt: &VfsdRuntime,
    base_lba: u64,
    length_lba: u64,
    ipc_buf: *mut u64,
) -> Option<u32>
{
    let msg = IpcMessage::builder(blk_labels::REGISTER_PARTITION)
        .word(0, u64::from(ipc::BLK_LABELS_VERSION))
        .word(1, base_lba)
        .word(2, length_lba)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let Ok(reply) = (unsafe { ipc::ipc_call(rt.blk_ep, &msg, ipc_buf) })
    else
    {
        std::os::seraph::log!("REGISTER_PARTITION ipc_call failed");
        return None;
    };
    if reply.label != ipc::blk_errors::SUCCESS
    {
        std::os::seraph::log!("REGISTER_PARTITION rejected (code={})", reply.label);
        return None;
    }
    reply.caps().first().copied()
}
