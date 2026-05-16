# Process Lifecycle

System-wide model of userspace process creation, identity, and
destruction. This document covers the userspace half of the boot
sequence (init onward) and the steady-state process-creation and
-death flows that follow. The bootloader-and-kernel half lives in
[`bootstrap.md`](bootstrap.md); this document picks up where init
begins executing.

---

## Scope

This document is authoritative for:

- The boot ordering of userspace tier-1 services
  (`init` → `memmgr` → `procmgr` → `svcmgr`).
- The capability flow at each step — who hands what to whom.
- The `ProcessInfo` / `InitInfo` handover discipline: which fields are
  parent-chosen runtime values, which are ABI constants, and how the
  ASLR transition will reshape the boundary.
- The steady-state process-creation flow under procmgr.
- The process-death notification flow that drives memmgr reclamation.
- The procmgr-restart fallback when procmgr itself dies.

Component-internal details (memmgr's pool structure, procmgr's ELF
loader, init's per-stage code) live in those components' own docs.

---

## Userspace Boot Order

```
kernel (Phase 9 handoff)
   │
   ▼
init                  no_std; receives the full initial CSpace
   │
   ├── spawns memmgr   no_std; receives all RAM Frame caps
   │     │
   │     └── ready to serve REQUEST_FRAMES
   │
   ├── spawns procmgr  std-using; bootstraps its heap via memmgr
   │     │
   │     └── ready to serve CREATE_PROCESS
   │
   ├── requests procmgr to spawn devmgr, svcmgr, drivers, vfsd, ...
   │
   ├── delegates per-service capability subsets via IPC
   │
   ├── registers all started services with svcmgr
   │
   └── exits
       │
       ▼
svcmgr is the resident supervisor (steady state)
```

After the split between memmgr and procmgr, the only `no_std`
userspace services in the system are `init` and `memmgr`. Every other
service (procmgr, svcmgr, devmgr, drivers, vfsd, fs drivers, base
applications) is std-built and bootstraps its heap via memmgr.

### Kernel → init

The kernel hands init the maximal capability set in init's CSpace
(see [`capability-model.md`](capability-model.md) §"Initial Capability
Distribution") and the `InitInfo` page at `INIT_INFO_VADDR` describing
it. `InitInfo.memory_frame_base` and `InitInfo.memory_frame_count`
identify the contiguous slot range in init's CSpace holding the RAM
Frame caps.

Init never gives up the kernel-minted root caps directly — it derives
intermediaries (the "derive twice" pattern in
[`capability-model.md`](capability-model.md)) and delegates the second
derivation to each downstream service. This preserves init's ability to
revoke if a service misbehaves before svcmgr takes over supervision.

### Init → memmgr

Init creates memmgr's `AddressSpace`, `CSpace`, and `Thread` via raw
syscalls. It loads memmgr's ELF (from a boot module Frame cap), maps
the segments into memmgr's address space, populates memmgr's
`ProcessInfo`, copies every RAM Frame cap from init's CSpace into
memmgr's CSpace using derive-twice, and starts memmgr's thread.

Init then serves a single bootstrap-IPC round to memmgr carrying the
Frame slot range `(memory_frame_base, memory_frame_count)` so memmgr
knows where in its own CSpace the pool lives.

After this step, memmgr is ready: it serves `REQUEST_FRAMES`,
`RELEASE_FRAMES`, `REGISTER_PROCESS`, and `PROCESS_DIED` (the last two
restricted to procmgr; see [`memmgr/docs/ipc-interface.md`](../services/memmgr/docs/ipc-interface.md)).

memmgr is `no_std` and inherits the constraint that motivated the split:
it cannot bootstrap a heap against itself while owning frame allocation.

### Init → procmgr

Init creates procmgr's `AddressSpace`, `CSpace`, and `Thread` and loads
procmgr's ELF identically to memmgr. Before starting procmgr's thread,
init:

1. Calls `memmgr.REGISTER_PROCESS` to mint a tokened SEND cap on
   memmgr's endpoint identifying procmgr.
2. Installs that cap into procmgr's `ProcessInfo.memmgr_endpoint_cap`
   so procmgr's std `_start` finds memmgr on its first IPC.
3. Starts procmgr's thread. Procmgr's heap-bootstrap path issues
   `REQUEST_FRAMES` on `ProcessInfo.memmgr_endpoint_cap` and the
   `System` allocator comes online.

Procmgr is the first std-using process in the system. Every later
process spawned by procmgr inherits the same `memmgr_endpoint_cap`
mechanism — but procmgr is the chooser from that point forward (see
"Steady-state process creation" below).

### Init → remaining services

Init requests procmgr to start the remaining boot-time services in
order — devmgr, svcmgr, drivers, vfsd, optionally netd — by IPC to
procmgr's `CREATE_PROCESS` endpoint. For each service, init delegates
the appropriate capability subset (see
[`capability-model.md`](capability-model.md) §"Initial Capability
Distribution") and registers the service with svcmgr along with its
restart policy. Init then exits.

After init exits, svcmgr is the resident supervisor. See
[`services/svcmgr/README.md`](../services/svcmgr/README.md).

---

## Authority Boundaries Between memmgr and procmgr

memmgr and procmgr are sister tier-1 services with disjoint authority:

| Authority | Owner |
|---|---|
| RAM frame allocation and reclamation | memmgr |
| Per-process frame ownership tracking | memmgr |
| Process creation (ELF load, kernel-object allocation, ProcessInfo population) | procmgr |
| Process-death observation and notification | procmgr → memmgr |
| Process registry and lifecycle queries | procmgr |
| Service supervision and restart | svcmgr (post-init) |

Procmgr is itself a memmgr client. Its heap is backed by `REQUEST_FRAMES`,
its driver-allocated DMA frames (during ELF-load scratch and `ProcessInfo`
population) come from the same path. Procmgr never sees a Frame cap that
did not originate in memmgr — except for the boot-module ELF Frame caps
that init transfers to it for ELF loading, which procmgr consumes as
read-only sources.

Procmgr is the privileged caller for memmgr's two procmgr-only labels
(`REGISTER_PROCESS`, `PROCESS_DIED`). No other service can mint or
retire process tokens against memmgr.

---

## ProcessInfo / InitInfo Handover Discipline

Two handover surfaces carry the parent-to-child contract:

- **`InitInfo`** — kernel-populated, delivered to init at boot. Defined
  by [`abi/init-protocol`](../abi/init-protocol/). Carries the entire
  initial CSpace layout, including platform resources only init needs.
- **`ProcessInfo`** — procmgr-populated for every other process.
  Defined by [`abi/process-abi`](../abi/process-abi/). Carries only
  what a single service or application requires.

Both structures separate three categories of information:

### Runtime fields (parent-chosen, per-process)

Fields that the parent picks per child, written into the handover page
at creation time. Examples:

- `ProcessInfo.ipc_buffer_vaddr` — procmgr picks the IPC-buffer VA per
  child.
- `ProcessInfo.creator_endpoint_cap` — tokened SEND back to the parent's
  bootstrap endpoint, distinct per child.
- `ProcessInfo.memmgr_endpoint_cap` — tokened SEND on memmgr's endpoint,
  identifying this process; minted by `REGISTER_PROCESS` per child.
- `ProcessInfo.procmgr_endpoint_cap` — tokened SEND on procmgr's
  endpoint, for process-lifecycle queries.
- `ProcessInfo.log_send_cap` — tokened SEND cap on the master log
  endpoint, minted by procmgr per child via
  `cap_derive_token(log_send_source, RIGHTS_SEND, process_token)`.
  The cap's kernel-attached token equals procmgr's process token,
  which also equals the death-EQ correlator procmgr posts to
  logd. Identity is reconciled across the three views without
  any auxiliary mapping.
- `InitInfo.memory_frame_base`, `InitInfo.memory_frame_count` — chosen
  by the kernel per init invocation.

### ABI constants today, runtime fields after ASLR

Fields that are pinned at well-known virtual addresses today
(`PROCESS_INFO_VADDR`, `PROCESS_STACK_TOP`, `PROCESS_MAIN_TLS_VADDR`,
`INIT_INFO_VADDR`). Each is declared in its respective ABI crate
(`abi/process-abi`, `abi/init-protocol`) and consumed by both the
parent-side populator and the child-side `_start` to find its handover
page.

The ASLR work (tracked separately) promotes these to runtime fields:
the parent draws each VA from the system RNG and writes it into a typed
field on the handover page; the child reads the field to locate the
page and its bootstrap regions. The mechanism is identical to today's
runtime-field path; only the source of the value changes.

This document declares the ASLR-transition shape so consumers reading
the `ProcessInfo` / `InitInfo` ABI today understand which constants are
expected to migrate.

### CSpace slot conventions

The `ProcessInfo` page also names the well-known CSpace slots that the
parent populates (see
[`abi/process-abi/README.md`](../abi/process-abi/README.md) §"Fixed
CSpace slot conventions"). These are slot indices, not VAs, and are
unaffected by ASLR.

---

## Steady-State Process Creation

After bootstrap, every process is created by procmgr. The flow:

1. **Caller IPC.** A service (init, svcmgr, devmgr, vfsd) sends
   `CREATE_PROCESS` (or `CREATE_PROCESS_FROM_VFS`) to procmgr.
2. **Procmgr ELF load.** Procmgr maps the ELF source, parses headers,
   and computes the segment layout. ELF-load scratch frames come from
   procmgr's own heap (backed by memmgr).
3. **Procmgr → memmgr.** Procmgr calls `memmgr.REGISTER_PROCESS` and
   receives a tokened SEND cap identifying the new process.
4. **Procmgr kernel-object allocation.** Procmgr creates the new
   process's `AddressSpace`, `CSpace`, and `Thread` via the
   `cap_create_*` syscalls.
5. **Procmgr → memmgr (frames).** Procmgr requests Frame caps from
   memmgr to back the child's stack, IPC buffer, `ProcessInfo` page,
   TLS block, and ELF segments. These calls go over procmgr's own
   `memmgr_endpoint_cap`, so memmgr accounts the frames against
   procmgr's per-process record — they belong to procmgr until procmgr
   transfers them.
6. **Procmgr maps + populates the child.** Procmgr maps the frames
   into the child's address space at procmgr-chosen VAs, copies ELF
   segment bytes, populates `ProcessInfo` (including
   `memmgr_endpoint_cap` from step 3 and the procmgr/log endpoints).
7. **Procmgr transfers ownership.** For each Frame cap that should
   belong to the child, procmgr derives a copy into the child's CSpace
   and informs memmgr (a single `RELEASE_FRAMES`-style accounting
   message; or memmgr accepts the transfer as part of `REGISTER_PROCESS`
   bookkeeping — concrete shape lives in
   [`memmgr/docs/ipc-interface.md`](../services/memmgr/docs/ipc-interface.md)).
8. **Procmgr starts the thread.** `thread_configure` + `thread_start`.
   The child's std `_start` registers its IPC buffer, bootstraps the
   heap by calling `REQUEST_FRAMES` on its own
   `memmgr_endpoint_cap`, and enters `main()`.
9. **Procmgr replies to caller.** `CREATE_PROCESS` returns the
   process handle, child CSpace cap, `ProcessInfo` frame cap, and
   thread cap to the original caller.

A process created via `CREATE_PROCESS` is suspended until
`START_PROCESS`; the heap-bootstrap step (8) only runs after the caller
has finished injecting any additional capabilities.

---

## Process Death

A process dies when:

- It calls `sys_thread_exit` on its last thread.
- Its `AddressSpace` capability is revoked (the "kill process" pattern;
  see [`capability-model.md`](capability-model.md) §"Kill process pattern").
- An unhandled fault terminates its threads.

The death-notification flow:

1. **Procmgr observes.** Procmgr's existing supervision path detects
   the death (death notification on the child's thread cap, or
   explicit teardown initiated by procmgr itself).
2. **Procmgr → memmgr.** Procmgr sends `PROCESS_DIED` to memmgr,
   transferring the dead process's tokened endpoint cap. The cap's
   token identifies which per-process record memmgr reclaims.
3. **Memmgr reclaims.** Memmgr walks the per-process frame list and
   inserts each Frame cap back into its free pool.
4. **Memmgr coalesces.** Reverse-`frame_split` merges adjacent free
   runs to sustain `REQUIRE_CONTIGUOUS` success rates. See
   [`memmgr/docs/frame-pool.md`](../services/memmgr/docs/frame-pool.md)
   §"Coalescing".
5. **Procmgr clears its registry entry.** Independent of memmgr's
   reclamation; the procmgr-side process table releases its slot.

Frame caps the dead process held in its CSpace become unreachable as
part of the kernel's CSpace teardown when the `AddressSpace` is
revoked. Memmgr's intermediary derivations (retained at allocation time
per the derive-twice pattern) are unaffected and are what the
reclamation step inserts back into the free pool.

---

## Procmgr Restart Fallback

If procmgr itself dies, no other process can spawn replacements via the
normal path. svcmgr holds the raw `cap_create_aspace`,
`cap_create_cspace`, and `cap_create_thread` capabilities as a fallback
to recreate procmgr (see
[`services/svcmgr/README.md`](../services/svcmgr/README.md)).

memmgr is unaffected by procmgr restart in steady state — memmgr's
state is independent of procmgr's, and memmgr's `REGISTER_PROCESS`
authority is held by whichever process holds the procmgr-side tokened
cap at the time. svcmgr re-establishes that cap when restarting
procmgr; the concrete protocol is owned by svcmgr's design and is out
of scope here.

If memmgr dies, the system cannot recover. Memmgr is on the trusted
path of every std-built service; its death implies an unrecoverable
fault. svcmgr does not restart memmgr.

---

## Non-Goals

- **`fork()` and copy-on-write.** Seraph does not implement either.
  Process creation is always from-scratch via `CREATE_PROCESS`. Zero-
  copy buffer handoff between processes uses Frame-cap moves over IPC,
  not write-trap CoW.
- **Kernel-side process abstraction.** The kernel has no Process
  object. A process is a userspace convention: an `AddressSpace` plus
  a `CSpace` plus one or more `Thread`s, grouped by procmgr.
- **Pager protocols and userspace page-fault delivery.** No mechanism
  delivers page faults to userspace; faulting threads terminate.

---

## Summarized By

[Architecture Overview](architecture.md), [Bootstrap](bootstrap.md), [Userspace Memory Model](userspace-memory-model.md), [memmgr/README.md](../services/memmgr/README.md), [procmgr/README.md](../services/procmgr/README.md), [init/README.md](../services/init/README.md)
