// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// vfsd/src/main.rs

//! Seraph virtual filesystem daemon.
//!
//! vfsd presents a unified virtual filesystem namespace to all other
//! processes via a synthetic system-root cap. A mount installs a
//! tokened SEND on the underlying driver's namespace endpoint into
//! `VfsdRootBackend`; clients walk that root via `NS_LOOKUP` and reach
//! per-file node caps directly on the driver. After the walk vfsd is
//! out of the path: file reads, frame requests, and closes go straight
//! from client to driver.
//!
//! vfsd self-mounts the Seraph root partition at `/` (and the ESP at
//! `/esp`) during startup, before serving any request; the runtime
//! `MOUNT` IPC remains for explicit/foreign-GUID mounts.
//!
//! See `vfsd/README.md` for the design and `fs/docs/fs-driver-protocol.md`
//! for the driver-side protocol.

// The `seraph` target is not in rustc's recognised-OS list, so `std` is
// `restricted_std`-gated for downstream bins. Every std-built service on
// seraph carries this preamble.
#![feature(restricted_std)]
#![allow(clippy::cast_possible_truncation)]

mod driver;
mod gpt;
mod role_guids;
mod root_backend;
mod worker;
mod worker_pool;

use std::os::seraph::startup_info;
use std::sync::{Mutex, PoisonError};

use gpt::MAX_GPT_PARTS;
use ipc::{IpcMessage, blk_labels, ns_labels};
use namespace_protocol::{GateError, compose_forward_lookup_rights, gate};
use root_backend::VfsdRootBackend;
use worker_pool::WorkerPool;

/// Number of threads that recv on the service endpoint. More than one
/// is required for correctness: when one thread blocks waiting on a
/// worker pool order (e.g. `CREATE_FROM_FILE` for a fatfs respawn),
/// procmgr re-enters vfsd's namespace dispatcher (via `FS_READ` on
/// the supplied file cap) to load the binary; another thread must be
/// available to service the in-flight MOUNT reply, otherwise the
/// system deadlocks.
const SERVICE_THREAD_COUNT: usize = 4;

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
    /// thread is spawned. Main derives tokened SEND caps on this slot to hand
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
//     caps[0]: fatfs module frame cap
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

    // Allocate a single scratch frame for GPT block reads. The
    // BLK_READ_INTO_FRAME contract requires the caller to supply the DMA
    // target frame; vfsd reuses one scratch page across all GPT reads.
    // The frame and its VA reservation are process-lifetime-leaked.
    let Some((mut scratch_cap, scratch_va)) =
        gpt::alloc_scratch(caps.memmgr_ep, caps.self_aspace, ipc_buf)
    else
    {
        std::os::seraph::log!("FATAL: GPT scratch allocation failed");
        idle_loop();
    };

    // Parse GPT partition table — stored for UUID lookups on MOUNT requests.
    let mut gpt_parts = gpt::new_gpt_table();
    match gpt::parse_gpt(
        blk_ep,
        ipc_buf,
        &mut gpt_parts,
        &mut scratch_cap,
        scratch_va,
    )
    {
        Ok(count) => std::os::seraph::log!("GPT parsed, {count} partitions"),
        Err(gpt::GptError::IoError) => std::os::seraph::log!("GPT parse failed: I/O error"),
        Err(gpt::GptError::InvalidSignature) =>
        {
            std::os::seraph::log!("GPT parse failed: invalid signature");
        }
        Err(gpt::GptError::InvalidEntrySize) =>
        {
            std::os::seraph::log!("GPT parse failed: invalid entry size");
        }
    }

    // Namespace endpoint: separate recv surface for the cap-native
    // protocol (`NS_LOOKUP` / `NS_STAT` / `NS_READDIR`) against vfsd's
    // synthetic root. The service endpoint carries only `MOUNT` and
    // `GET_SYSTEM_ROOT_CAP`; the namespace endpoint is separated so
    // a single dispatcher thread can serve every walk without
    // contending with mount-table mutations.
    let Some(namespace_slab) = std::os::seraph::object_slab_acquire(88)
    else
    {
        std::os::seraph::log!("FATAL: cannot acquire namespace endpoint slab");
        idle_loop();
    };
    let Ok(namespace_ep) = syscall::cap_create_endpoint(namespace_slab)
    else
    {
        std::os::seraph::log!("FATAL: cannot create namespace endpoint");
        idle_loop();
    };

    // Vfsd-internal system-root cap. Used for vfsd's own walks (e.g.
    // resolving `/services/fs/fatfs` before a worker spawns a fresh fatfs
    // instance via procmgr `CREATE_FROM_FILE`). Mirrors the cap shape
    // returned by `GET_SYSTEM_ROOT_CAP` to external callers.
    let token = namespace_protocol::pack(
        namespace_protocol::NodeId::ROOT,
        namespace_protocol::NamespaceRights::ALL,
    );
    let Ok(system_root_cap) = syscall::cap_derive_token(namespace_ep, syscall::RIGHTS_SEND, token)
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
    pub gpt_parts: [gpt::GptEntry; MAX_GPT_PARTS],
    pub pool: WorkerPool,
    /// Boot-module fatfs cap consumed (and zeroed) by the very first MOUNT.
    /// Mutex-guarded because that MOUNT may land on any handler thread.
    pub boot_module_cap: Mutex<u32>,
    /// Un-tokened SEND on vfsd's own namespace endpoint. Source of every
    /// node cap minted on the synthetic root (the system-root cap and
    /// any descendants that resolve to vfsd-local nodes — currently
    /// none, since the synthetic root only carries External entries).
    pub namespace_ep: u32,
    /// Tokened SEND on `namespace_ep` addressing the synthetic root at
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

/// Service-handler entry. One copy of this loop runs per
/// [`SERVICE_THREAD_COUNT`] thread; all share the [`VfsdRuntime`].
/// Multi-threaded recv on the service endpoint is required so that a
/// handler blocked on a worker pool order (notably `CREATE_FROM_FILE`
/// for a fatfs respawn, which triggers procmgr → vfsd namespace
/// re-entry via `FS_READ` while loading a driver from the now-mounted
/// root) does not deadlock.
///
/// Concurrency invariants. `MOUNT` routes into `do_mount` (and
/// `do_mount` calls itself recursively for the ESP auto-mount), which
/// mutates shared runtime state under the `VfsdRuntime` mutexes:
/// - `rt.boot_module_cap` — Mutex; swapped to zero on the first
///   successful mount.
/// - `rt.root_backend` — Mutex; the synthetic-root tree's only
///   mutator. `root_backend.install_mount` rejects on an already-
///   terminal entry, so two concurrent MOUNTs targeting the same
///   path serialise on the lock and the loser sees `install` reject.
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

    loop
    {
        // SAFETY: ipc_buf is the thread-registered IPC buffer page.
        let Ok(recv) = (unsafe { ipc::ipc_recv(rt.caps.service_ep, ipc_buf) })
        else
        {
            std::os::seraph::log!("ipc_recv failed, retrying");
            continue;
        };

        let label = recv.label;
        let opcode = label & 0xFFFF;
        let token = recv.token;

        match opcode
        {
            ipc::vfsd_labels::MOUNT => handle_mount_request(&recv, ipc_buf, rt),
            ipc::vfsd_labels::GET_SYSTEM_ROOT_CAP =>
            {
                if token & ipc::vfsd_labels::SEED_AUTHORITY == 0
                {
                    std::os::seraph::log!(
                        "GET_SYSTEM_ROOT_CAP rejected: token lacks SEED_AUTHORITY"
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
/// One thread is sufficient: the synthetic-root tree is bounded by
/// [`MAX_TREE_NODES`] and every backend operation is constant work in
/// the tree; the only blocking call is the optional fall-through
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
///
/// [`MAX_TREE_NODES`]: root_backend::MAX_TREE_NODES
fn namespace_loop(rt: &'static VfsdRuntime) -> !
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    if ipc_buf.is_null()
    {
        std::os::seraph::log!("namespace thread has no registered IPC buffer");
        syscall::thread_exit();
    }

    loop
    {
        // SAFETY: ipc_buf is the thread-registered IPC buffer page.
        let Ok(recv) = (unsafe { ipc::ipc_recv(rt.namespace_ep, ipc_buf) })
        else
        {
            continue;
        };

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

        let mut backend = rt
            .root_backend
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        // SAFETY: ipc_buf invariant carried through; rt.namespace_ep is
        // the un-tokened source for child caps minted by the protocol
        // crate's `cap_derive_token` calls.
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
/// `recv.token`) with the caller's original `caller_requested` —
/// computed via [`compose_forward_lookup_rights`]. Forwarding the
/// caller's `word(0)` verbatim would launder authority because the
/// receiving fs driver composes against the *destination cap's*
/// token (the fall-through cap, full rights), not the caller's. The
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
    let parent = match gate(recv.label, recv.token)
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
    // than the fall-through cap's full-rights token.
    let composed_rights = compose_forward_lookup_rights(recv.token, recv.word(0));
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

// ── System-root cap delivery ─────────────────────────────────────────────

/// Handle [`vfsd_labels::GET_SYSTEM_ROOT_CAP`]: mint a fresh tokened SEND
/// on vfsd's namespace endpoint addressing the synthetic root at full
/// rights and reply with it.
///
/// Source for the seed cap init holds at bootstrap and from which all
/// later tier-3 namespace-cap distribution flows. The dispatcher gates
/// this entry on [`vfsd_labels::SEED_AUTHORITY`] in the caller's
/// service-endpoint token: holding the bit is equivalent to holding
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

    let token = namespace_protocol::pack(
        namespace_protocol::NodeId::ROOT,
        namespace_protocol::NamespaceRights::ALL,
    );
    let reply = if let Ok(cap) =
        syscall::cap_derive_token(rt.namespace_ep, syscall::RIGHTS_SEND, token)
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
/// role to a GPT type-GUID via [`role_for_type_guid`] and then to a
/// partition entry via [`gpt::lookup_partition_by_type_guid`].
#[derive(Clone, Copy, Debug)]
enum MountRole
{
    /// Seraph rootfs (`role_guids::SERAPH_ROOT`).
    Root,
}

impl MountRole
{
    fn from_wire(byte: u8) -> Option<Self>
    {
        match byte
        {
            0 => Some(MountRole::Root),
            _ => None,
        }
    }

    fn type_guid(self) -> &'static [u8; 16]
    {
        match self
        {
            MountRole::Root => &role_guids::SERAPH_ROOT,
        }
    }
}

/// Mount the Seraph root partition at `/`, then auto-mount the ESP at
/// `/esp`, during vfsd startup.
///
/// Runs on the main thread before any service handler exists, so a
/// `GET_SYSTEM_ROOT_CAP` request can never observe an unmounted root.
/// The namespace dispatcher must already be running: the `/esp` mount
/// takes the VFS spawn path, which re-enters vfsd's namespace endpoint
/// to resolve `/services/fs/fatfs`. Returns whether the root mount
/// succeeded; `/esp` is best-effort and never gates the return value.
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

    auto_mount_esp(rt, ipc_buf);
    true
}

/// Handle a runtime MOUNT request from an authorized client.
///
/// vfsd self-mounts root and `/esp` at startup ([`self_mount`]), so no
/// in-tree caller currently issues MOUNT; it remains the explicit /
/// runtime-mount surface (foreign-GUID disks, user-invoked mounts).
///
/// IPC data layout (boot protocol v8+):
/// - `data[0]` low byte: [`MountRole`] discriminant
/// - `data[1]`: mount path length
/// - `data[2..]`: mount path bytes (packed into u64 words)
///
/// Decodes the wire payload and delegates to [`do_mount`] for the
/// real work. When the requested role is [`MountRole::Root`], vfsd
/// additionally auto-mounts the EFI System Partition at `/esp`.
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
    if path_len == 0 || path_len > 64
    {
        std::os::seraph::log!("MOUNT: invalid path length");
        let err = IpcMessage::new(ipc::vfsd_errors::NOT_FOUND);
        // SAFETY: ipc_buf is the registered IPC buffer.
        let _ = unsafe { ipc::ipc_reply(&err, ipc_buf) };
        return;
    }

    let mut path_buf = [0u8; 64];
    let path_bytes = recv.data_bytes();
    // Path bytes start at word 2 (byte offset 16) under the new wire shape.
    let path_src_start = 2 * 8;
    let path_src_end = (path_src_start + path_len).min(path_bytes.len());
    let copy_len = path_src_end.saturating_sub(path_src_start).min(path_len);
    if copy_len > 0
    {
        path_buf[..copy_len]
            .copy_from_slice(&path_bytes[path_src_start..path_src_start + copy_len]);
    }

    let reply = match do_mount(rt, ipc_buf, role, &path_buf[..path_len])
    {
        Ok(0) => IpcMessage::new(ipc::vfsd_errors::SUCCESS),
        Ok(cap) => IpcMessage::builder(ipc::vfsd_errors::SUCCESS)
            .cap(cap)
            .build(),
        Err(label) => IpcMessage::new(label),
    };

    // Auto-mount the EFI System Partition at /esp once root is up so
    // userspace can read kernel + bundle + bootloader without a separate
    // MOUNT call (the historic role of `mounts.conf`). Best-effort —
    // failure does not propagate into the root mount's reply.
    if matches!(role, MountRole::Root) && reply.label == ipc::vfsd_errors::SUCCESS
    {
        auto_mount_esp(rt, ipc_buf);
    }

    // SAFETY: ipc_buf is the registered IPC buffer.
    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
}

/// One-shot best-effort mount of the EFI System Partition at `/esp`. Logs
/// a diagnostic on any failure. Idempotent if invoked twice — the
/// install attempt against an already-terminal mount path is rejected by
/// `root_backend::install_mount`.
fn auto_mount_esp(rt: &VfsdRuntime, ipc_buf: *mut u64)
{
    let parts = &rt.gpt_parts;
    let mut esp_found = false;
    for p in parts
    {
        if p.active && p.type_guid == role_guids::EFI_SYSTEM_PARTITION
        {
            esp_found = true;
            break;
        }
    }
    if !esp_found
    {
        std::os::seraph::log!("MOUNT: no EFI System Partition found; skipping /esp auto-mount");
        return;
    }
    match do_mount_internal(rt, ipc_buf, &role_guids::EFI_SYSTEM_PARTITION, b"/esp")
    {
        Ok(_) => std::os::seraph::log!("MOUNT: /esp auto-mounted"),
        Err(code) => std::os::seraph::log!("MOUNT: /esp auto-mount failed: code={code:#x}"),
    }
}

/// Delete `slot` and log the kernel error code on failure. A no-op on
/// `slot == 0` (sentinel for "no cap held"). Used at every `cap_delete`
/// site whose failure would otherwise be operator-invisible: the kernel
/// reports invalid-slot / table-corruption via the returned code and
/// silent discards leak that signal.
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

/// Mount a partition identified by `uuid` at `path`.
///
/// Looks up the UUID in the GPT table, registers the partition bound
/// with virtio-blk, spawns a fatfs driver, registers a mount entry,
/// and captures a tokened SEND on the driver's namespace endpoint
/// into [`VfsdRootBackend`] so the system-root cap can resolve through
/// the new mount.
///
/// On success returns a fresh tokened SEND for the caller (zero if
/// minting failed; the mount itself still landed). On failure
/// returns the matching `vfsd_errors::*` label.
// do_mount runs the full mount-and-publish transaction inline:
// GPT lookup, partition cap registration with virtio-blk, fatfs
// driver spawn, mount-table registration, and namespace-root cap
// minting all share the partition_lba / partition_len / driver_ep
// locals; folding any subset into helpers requires threading those
// locals through and obscures the failure-paths' resource releases.
#[allow(clippy::too_many_lines)]
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
/// internally-triggered (`auto_mount_esp`) mounts. Takes a type-GUID
/// directly so callers without a [`MountRole`] (the ESP auto-mount)
/// can reuse the transaction body.
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
                std::os::seraph::log!(
                    "MOUNT: FATAL — multiple partitions share the role GUID with tied priority"
                );
                return Err(ipc::vfsd_errors::NO_MOUNT);
            }
        };
    std::os::seraph::log!(
        "MOUNT: partition LBA={partition_lba:#018x} length={partition_len:#018x}"
    );

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

    let Some(driver_ep) = driver::spawn_fatfs_driver(
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

    // Root MOUNT succeeded — drop the boot module cap. The IPC has already
    // transferred a derived child to procmgr; this releases vfsd's outer slot.
    log_cap_delete("module_cap (post-spawn)", module_cap_for_spawn);

    // Mint two tokened SEND caps on the driver's namespace endpoint,
    // both addressing this mount's root at full namespace rights:
    //   - `caller_root_cap` rides back to the caller (or is dropped
    //     by an internal caller).
    //   - `synthetic_root_cap` is captured into vfsd's
    //     `VfsdRootBackend` so `NS_LOOKUP` against the system-root
    //     cap returns a `cap_derive`-d copy of the underlying
    //     driver's root.
    //
    // Two derives instead of one cap_copy because vfsd must be able
    // to `cap_delete` either slot in isolation (e.g. an unmount drops
    // the synthetic-root entry without forcing the caller to drop its
    // copy). For revocation, the supported primitive is
    // destroy-the-fs-driver: `cap_revoke` on the driver's namespace
    // endpoint cascades through the kernel derivation graph and
    // invalidates every cap ever derived from it (caller copies
    // included), which is the namespace-model `kill the server` shape
    // (see `docs/namespace-model.md` § Revocation). Per-cap revocation
    // (e.g. revoking the synthetic-root entry without affecting the
    // caller's copy) is not supported by this scheme.
    let root_token = namespace_protocol::pack(
        namespace_protocol::NodeId::ROOT,
        namespace_protocol::NamespaceRights::ALL,
    );
    let caller_root_cap =
        syscall::cap_derive_token(driver_ep, syscall::RIGHTS_SEND, root_token).ok();
    let synthetic_root_cap =
        syscall::cap_derive_token(driver_ep, syscall::RIGHTS_SEND, root_token).ok();

    let Some(cap) = synthetic_root_cap
    else
    {
        std::os::seraph::log!("MOUNT: synthetic-root cap derive failed");
        log_cap_delete(
            "caller_root_cap (derive-fail)",
            caller_root_cap.unwrap_or(0),
        );
        return Err(ipc::vfsd_errors::IO_ERROR);
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
        backend.install(path, cap)
    };
    let Some(install_result) = install_result
    else
    {
        std::os::seraph::log!("MOUNT: synthetic-root install full or oversized");
        log_cap_delete("synthetic_root_cap (install-full)", cap);
        log_cap_delete(
            "caller_root_cap (install-full)",
            caller_root_cap.unwrap_or(0),
        );
        return Err(ipc::vfsd_errors::TABLE_FULL);
    };

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
/// `NotFound` instead of forwarding.
fn populate_fallthrough_caps(rt: &VfsdRuntime, ipc_buf: *mut u64, intermediates: &[u32])
{
    for &node_idx in intermediates
    {
        let mut path_buf = [0u8; 256];
        let path_len_and_cap = {
            let backend = rt
                .root_backend
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            let root_mount = backend.root_mount_cap();
            let path_len = backend.path_of(node_idx, &mut path_buf);
            (path_len, root_mount)
        };
        let (Some(path_len), root_mount_cap) = path_len_and_cap
        else
        {
            std::os::seraph::log!(
                "MOUNT: fallthrough skip node_idx={node_idx}: backend.path_of returned None",
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
        let path = &path_buf[..path_len];
        if let Some(cap) = walk_root_mount_path(root_mount_cap, path, ipc_buf)
        {
            let mut backend = rt
                .root_backend
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            backend.set_fallthrough_cap(node_idx, cap);
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
        // Cast is range-safe: components are bounded by MAX_ENTRY_NAME
        // (64) on the install side.
        #[allow(clippy::cast_possible_truncation)]
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
/// tokened `SEND_GRANT` cap scoped to that partition.
///
/// vfsd's `rt.blk_ep` is itself a tokened cap (the `MOUNT_AUTHORITY` cap
/// minted by devmgr), so vfsd cannot mint partition caps locally — the
/// kernel rejects re-tokening of a tokened source. Partition cap
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
