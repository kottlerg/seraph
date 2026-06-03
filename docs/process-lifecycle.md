# Process Lifecycle

System-wide model of userspace process creation, identity, and destruction from init onward.

---

## Scope

This document is authoritative for:

- The boot ordering of userspace tier-1 services
  (`init` → `memmgr` → `procmgr` → `svcmgr`).
- The capability flow at each step — who hands what to whom.
- The `ProcessInfo` / `InitInfo` handover discipline: which fields are
  parent-chosen runtime values and which are ABI constants.
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
   ├── spawns memmgr   no_std; receives all RAM Memory caps
   │     │
   │     └── ready to serve REQUEST_MEMORY_CAPS
   │
   ├── spawns procmgr  std-using; bootstraps its heap via memmgr
   │     │
   │     └── ready to serve CREATE_PROCESS
   │
   ├── requests procmgr to spawn devmgr, svcmgr, drivers, vfsd, ...
   │
   ├── delegates per-service capability subsets via IPC
   │
   ├── endows svcmgr (its endpoints + publish-source caps + substrate
   │     thread caps) over the bootstrap-round handover endowment
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
it. `InitInfo.memory_base` and `InitInfo.memory_count`
identify the contiguous slot range in init's CSpace holding the RAM
Memory caps.

Init never gives up the kernel-minted root caps directly — it derives
intermediaries (the "derive twice" pattern in
[`capability-model.md`](capability-model.md)) and delegates the second
derivation to each downstream service. This preserves init's ability to
revoke if a service misbehaves before svcmgr takes over supervision.

### Init → memmgr

Init creates memmgr's `AddressSpace`, `CSpace`, and `Thread` via raw
syscalls. It loads memmgr's ELF (from a boot module Memory cap), maps
the segments into memmgr's address space, populates memmgr's
`ProcessInfo`, copies every RAM Memory cap from init's CSpace into
memmgr's CSpace using derive-twice, and starts memmgr's thread.

Init then serves a single bootstrap-IPC round to memmgr carrying the
Memory slot range `(memory_base, memory_count)` so memmgr
knows where in its own CSpace the pool lives.

After this step, memmgr is ready: it serves `REQUEST_MEMORY_CAPS`,
`RELEASE_MEMORY_CAPS`, `REGISTER_PROCESS`, and `PROCESS_DIED` (the last two
restricted to procmgr; see [`memmgr/docs/ipc-interface.md`](../services/memmgr/docs/ipc-interface.md)).

memmgr is `no_std` and inherits the constraint that motivated the split:
it cannot bootstrap a heap against itself while owning frame allocation.

### Init → procmgr

Init creates procmgr's `AddressSpace`, `CSpace`, and `Thread` and loads
procmgr's ELF identically to memmgr. Before starting procmgr's thread,
init:

1. Calls `memmgr.REGISTER_PROCESS` to mint a badged SEND cap on
   memmgr's endpoint identifying procmgr.
2. Installs that cap into procmgr's `ProcessInfo.memmgr_endpoint_cap`
   so procmgr's std `_start` finds memmgr on its first IPC.
3. Starts procmgr's thread. Procmgr's heap-bootstrap path issues
   `REQUEST_MEMORY_CAPS` on `ProcessInfo.memmgr_endpoint_cap` and the
   `System` allocator comes online.

Procmgr is the first std-using process in the system. Every later
process spawned by procmgr inherits the same `memmgr_endpoint_cap`
mechanism — but procmgr is the chooser from that point forward (see
"Steady-state process creation" below).

### Init → remaining services

Init requests procmgr to start only the bootstrap-essential services
— devmgr, vfsd, optionally netd, then svcmgr — by IPC to
procmgr's `CREATE_FROM_FILE` / `CREATE_PROCESS` endpoints. The
non-bootstrap services (`logd`, `timed`, `pwrmgr`, the staged test
harnesses) are not in this list: svcmgr launches them itself
post-handover from
their `/config/svcmgr/services/*.svc` recipes. Nor is the per-arch RTC
chip driver: devmgr spawns it during its enumeration sweep, and timed
resolves it via `devmgr_labels::QUERY_RTC_DEVICE` at startup. For each
service init starts, it delegates the appropriate capability subset (see
[`capability-model.md`](capability-model.md) §"Initial Capability
Distribution"). svcmgr is configured with the universal
`system_root_cap` so it can read `/config/svcmgr/services/*.svc`
post-handover.

Init then serves svcmgr the **handover endowment** over the
bootstrap-round protocol: round 1 carries svcmgr's own endpoints plus the
publish-role source caps (a `SEND` on the root filesystem namespace
endpoint and a badge-0 `SEND|GRANT` source on devmgr's registry
endpoint); each subsequent round carries one `(name, thread_cap)` pair for
a substrate service init bootstrapped (`memmgr`, `procmgr`, `devmgr`,
`vfsd`, `logd`). svcmgr — not init — then publishes the well-known names
it owns into its own registry (`ipc::published_names::ROOTFS_ROOT`,
`SVCMGR`, `DEVMGR_REGISTRY`, minted from the endowed sources) and installs
devmgr's `/services/drivers/` cap via `devmgr_labels::SET_DRIVERS_DIR`.
The provider names (`timed`, `pwrmgr.shutdown`, `pwrmgr.deny`) are
published by svcmgr's provider path on each provider's launch. Recipes for
all svcmgr-supervised services live on disk at
`/config/svcmgr/services/<name>.svc`, not on the wire — see
[`services/svcmgr/docs/service-definitions.md`](../services/svcmgr/docs/service-definitions.md).

### Init reap

After Phase 3 signals `svcmgr_labels::HANDOVER_COMPLETE` (svcmgr
replies immediately, then scans `/config/svcmgr/services/`, binds the
endowed substrate bind-only, and launches every defined-but-unparked
service — `logd`, the `timed` and `pwrmgr` providers on a normal boot,
plus any staged test recipes such as `svctest.svc` / `usertest.svc` and
the co-staged `crasher.svc` restart fixture), init signs over its own
kernel-object caps
(`AddressSpace`, `CSpace`, main `Thread`, init-logd `Thread`) and
every reclaimable Memory cap it solely owns (ELF segments, user stack
pages, `InitInfo` pages, the bootloader/bundle reclaim ranges, the
AP-trampoline frame, and the boot-module ELF sources) to
procmgr via `procmgr_labels::REGISTER_INIT_TEARDOWN`, then
`sys_thread_exit`s. The usable-RAM range (already memmgr's) and the
firmware read-only caps (RSDP/ACPI/DTB) are excluded. init's own
bootstrap backing — its endpoint and log-thread retype slabs plus the
offset-mapped IPC buffer and log-thread stack/IPC — is not in this set:
it lives in a single contiguous arena Memory cap that init forwards to
memmgr as an in-use run at bootstrap (`finalize_memmgr`), so those pages
are already accounted in memmgr's pool and never reach the reap route.

Procmgr binds a death-EQ observer on **both** init threads (main +
init-logd) and reaps only once both have exited — init is threadless. The
main thread exits at the end of Phase 3, but init-logd keeps serving the
master log endpoint until the svcmgr-launched real-logd pulls its
handover, so it outlives main; reclaiming init's address space while a
thread still runs in it would fault that thread. On the last death procmgr
tears down init's kernel objects in order (Threads → AddressSpace → donate
Memory caps to memmgr → CSpace cascade), leaving zero init residue. The
implementation is in
[`services/procmgr/README.md`](../services/procmgr/README.md) §"Init
reap".

After init's reap completes, svcmgr is the resident supervisor. See
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

Procmgr is itself a memmgr client. Its heap is backed by `REQUEST_MEMORY_CAPS`,
its driver-allocated DMA frames (during ELF-load scratch and `ProcessInfo`
population) come from the same path. Procmgr never sees a Memory cap that
did not originate in memmgr — except for the boot-module ELF Memory caps
that init transfers to it for ELF loading, which procmgr consumes as
read-only sources.

Procmgr is the privileged caller for memmgr's two procmgr-only labels
(`REGISTER_PROCESS`, `PROCESS_DIED`). No other service can mint or
retire process badges against memmgr.

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
- `ProcessInfo.creator_endpoint_cap` — badged SEND back to the parent's
  bootstrap endpoint, distinct per child.
- `ProcessInfo.memmgr_endpoint_cap` — badged SEND on memmgr's endpoint,
  identifying this process; minted by `REGISTER_PROCESS` per child.
- `ProcessInfo.procmgr_endpoint_cap` — badged SEND on procmgr's
  endpoint, for process-lifecycle queries.
- `ProcessInfo.log_send_cap` — badged SEND cap on the master log
  endpoint, minted by procmgr per child via
  `cap_derive_badge(log_send_source, RIGHTS_SEND, process_badge)`.
  The cap's kernel-attached badge equals procmgr's process badge,
  which also equals the death-EQ correlator procmgr posts to
  logd. Identity is reconciled across the three views without
  any auxiliary mapping.
- `ProcessInfo.sched_control_cap` — baseline `SchedControl` cap (default
  band `[1, 20]`) so the child can set its own threads' priorities. procmgr
  `cap_copy`s its own baseline (delivered by init) into every child; a child
  with a zero slot holds no scheduling authority and cannot set any priority.
  Added in `PROCESS_ABI_VERSION` 17 (#185).
- `InitInfo.memory_base`, `InitInfo.memory_count` — chosen
  by the kernel per init invocation.

### ABI constants

Fields that are pinned at well-known virtual addresses
(`PROCESS_INFO_VADDR`, `PROCESS_STACK_TOP`, `PROCESS_MAIN_TLS_VADDR`,
`INIT_INFO_VADDR`). Each is declared in its respective ABI crate
(`abi/process-abi`, `abi/init-protocol`) and consumed by both the
parent-side populator and the child-side `_start` to find its handover
page.

### CSpace slot conventions

The `ProcessInfo` page also names the well-known CSpace slots that the
parent populates (see
[`abi/process-abi/README.md`](../abi/process-abi/README.md) §"Fixed
CSpace slot conventions"). These are slot indices, not VAs.

---

## Steady-State Process Creation

After bootstrap, every process is created by procmgr. The flow:

1. **Caller IPC.** A service (init, svcmgr, devmgr, vfsd) sends
   `CREATE_PROCESS` (or `CREATE_PROCESS_FROM_VFS`) to procmgr.
2. **Procmgr ELF load.** Procmgr maps the ELF source, parses headers,
   and computes the segment layout. ELF-load scratch frames come from
   procmgr's own heap (backed by memmgr).
3. **Procmgr → memmgr.** Procmgr calls `memmgr.REGISTER_PROCESS` and
   receives a badged SEND cap identifying the new process.
4. **Procmgr kernel-object allocation.** Procmgr creates the new
   process's `AddressSpace`, `CSpace`, and `Thread` via the
   `cap_create_*` syscalls.
5. **Procmgr → memmgr (frames).** Procmgr requests Memory caps from
   memmgr to back the child's stack, IPC buffer, `ProcessInfo` page,
   TLS block, and ELF segments. These calls go over procmgr's own
   `memmgr_endpoint_cap`, so memmgr accounts the frames against
   procmgr's per-process record — they belong to procmgr until procmgr
   transfers them.
6. **Procmgr maps + populates the child.** Procmgr maps the frames
   into the child's address space at procmgr-chosen VAs, copies ELF
   segment bytes, populates `ProcessInfo` (including
   `memmgr_endpoint_cap` from step 3 and the procmgr/log endpoints).
7. **Procmgr transfers ownership.** For each Memory cap that should
   belong to the child, procmgr derives a copy into the child's CSpace
   and informs memmgr (a single `RELEASE_MEMORY_CAPS`-style accounting
   message; or memmgr accepts the transfer as part of `REGISTER_PROCESS`
   bookkeeping — concrete shape lives in
   [`memmgr/docs/ipc-interface.md`](../services/memmgr/docs/ipc-interface.md)).
8. **Procmgr starts the thread.** `thread_configure` + `thread_start`.
   The child's std `_start` registers its IPC buffer, bootstraps the
   heap by calling `REQUEST_MEMORY_CAPS` on its own
   `memmgr_endpoint_cap`, and enters `main()`.
9. **Procmgr replies to caller.** `CREATE_PROCESS` returns the
   process handle, child CSpace cap, `ProcessInfo` memory cap, and
   thread cap to the original caller.

A process created via `CREATE_PROCESS` is suspended until
`START_PROCESS`; the heap-bootstrap step (8) only runs after the caller
has finished injecting any additional capabilities.

---

## Process Death

A process dies when:

- It calls `sys_thread_exit` on its last thread.
- Its `AddressSpace` capability is revoked (the "kill process" pattern;
  see [`capability-model.md`](capability-model.md) §`"Kill process" pattern`).
- An unhandled fault terminates its threads.

The death-notification flow:

1. **Procmgr observes.** Procmgr's existing supervision path detects
   the death (death notification on the child's thread cap, or
   explicit teardown initiated by procmgr itself).
2. **Procmgr → memmgr.** Procmgr sends `PROCESS_DIED` to memmgr,
   transferring the dead process's badged endpoint cap. The cap's
   badge identifies which per-process record memmgr reclaims.
3. **Memmgr reclaims.** Memmgr walks the per-process frame list and
   inserts each Memory cap back into its free pool.
4. **Memmgr coalesces.** Reverse-`memory_split` merges adjacent free
   runs to sustain `REQUIRE_CONTIGUOUS` success rates. See
   [`memmgr/docs/memory-pool.md`](../services/memmgr/docs/memory-pool.md)
   §"Coalescing".
5. **Procmgr clears its registry entry.** Independent of memmgr's
   reclamation; the procmgr-side process table releases its slot.

Memory caps the dead process held in its CSpace become unreachable as
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
authority is held by whichever process holds the procmgr-side badged
cap at the time. svcmgr re-establishes that cap when restarting
procmgr; the concrete protocol is owned by svcmgr's design and is out
of scope here.

If memmgr dies, the system cannot recover. Memmgr is on the trusted
path of every std-built service; its death implies an unrecoverable
fault. svcmgr does not restart memmgr.

---

## Out of Scope

Seraph does not implement `fork()` or copy-on-write. Process creation
is always from-scratch via `CREATE_PROCESS`; zero-copy buffer handoff
between processes uses Memory-cap moves over IPC.

Page faults are not delivered to userspace; faulting threads terminate,
which surfaces through the normal process-death notification flow above.

---

## Summarized By

[README.md](../README.md),
[Architecture Overview](architecture.md),
[Bootstrap](bootstrap.md),
[Userspace Memory Model](userspace-memory-model.md),
[init/README.md](../services/init/README.md),
[logd/README.md](../services/logd/README.md),
[memmgr/README.md](../services/memmgr/README.md),
[procmgr/README.md](../services/procmgr/README.md),
[svcmgr/README.md](../services/svcmgr/README.md)
