# Process Lifecycle

System-wide model of userspace process creation, identity, and destruction from init onward.

---

## Scope

This document is authoritative for:

- The boot ordering of userspace tier-1 services
  ([`init`](../services/init/README.md) → [`memmgr`](../services/memmgr/README.md) →
  [`procmgr`](../services/procmgr/README.md) → [`svcmgr`](../services/svcmgr/README.md)).
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
   ├── requests procmgr to spawn devmgr, vfsd, svcmgr
   │
   ├── delegates per-service capability subsets via IPC
   │
   ├── endows svcmgr (its endpoints + publish-source caps + substrate
   │     thread caps + log-sink sources) over the bootstrap-round handover endowment
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
Distribution") and an `InitInfo` page — mapped at a kernel-chosen VA delivered
in init's entry register — describing it. `InitInfo.memory_base` and
`InitInfo.memory_count` identify the contiguous slot range in init's CSpace
holding the RAM Memory caps. The kernel coalesces physically-adjacent drained
RAM into the fewest contiguous extents and places the largest at `memory_base`,
so the first cap is the largest; consumers that take the whole range read each
cap's size individually and do not depend on the order of the rest.

Init delegates authority to downstream services by deriving intermediaries
(the "derive twice" pattern in
[`capability-internals.md`](../core/kernel/docs/capability-internals.md#safe-delegation-the-derive-twice-pattern))
and handing each service the second derivation. This preserves init's ability to
revoke if a service misbehaves before svcmgr takes over supervision. At the
init-reap handoff init moves only its kernel-object caps and the reclaimable
Memory caps it solely owns to procmgr (see "Init reap" below). The remaining
root caps (the RAM roots of memory forwarded to memmgr, the firmware caps, and
the `Interrupt`, `IoPort`, `SbiControl`, `Mmio`, and elevated `SchedControl`
roots) stay in init's CSpace, which the kernel pins (it is the root CSpace; see
[capability-internals.md § Kernel Object Reference Counting](../core/kernel/docs/capability-internals.md#kernel-object-reference-counting)),
so they remain alive but unreachable; releasing them at the reap is design intent, not yet
implemented ([#443](https://github.com/kottlerg/seraph/issues/443); see [Init reap](#init-reap)).

### Init → memmgr

Init creates memmgr's `AddressSpace`, `CSpace`, and `Thread` via raw
syscalls. It loads memmgr's ELF (from a boot module Memory cap), maps
the segments into memmgr's address space, populates memmgr's
`ProcessInfo`, copies the RAM Memory caps left after init's own bootstrap
allocations into memmgr's CSpace using derive-twice (as many as one bootstrap
round carries; the remainder reaches memmgr via the init-reap donation),
forwards the memmgr/procmgr/init bootstrap arenas as in-use runs, and starts
memmgr's thread (`finalize_memmgr`).

Init then serves a single bootstrap-IPC round to memmgr carrying the
Memory slot range `(memory_base, memory_count)` so memmgr
knows where in its own CSpace the pool lives.

After this step, memmgr is ready to serve its labels, including
`REQUEST_MEMORY_CAPS`, `RELEASE_MEMORY_CAPS`, and the procmgr-only
`REGISTER_PROCESS`, `PROCESS_DIED`, and `DELEGATE_ASPACE` (see
[`memmgr/docs/ipc-interface.md`](../services/memmgr/docs/ipc-interface.md)).

memmgr is `no_std` and inherits the constraint that motivated the split:
it cannot bootstrap a heap against itself while owning frame allocation.

### Init → procmgr

Init creates procmgr's `AddressSpace`, `CSpace`, and `Thread` and loads
procmgr's ELF identically to memmgr. Before starting procmgr's thread,
init:

1. Mints a badged `SEND|GRANT` cap on memmgr's endpoint (`cap_derive_badge`
   with a bootstrap badge) identifying procmgr, and passes that badge to
   memmgr in memmgr's bootstrap round so memmgr gates the procmgr-only
   labels on it.
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
— devmgr and vfsd (`CREATE_PROCESS`, from boot modules), then svcmgr
(`CREATE_FROM_FILE`, from `/services/svcmgr`) — by IPC to procmgr's service
endpoint. The
non-bootstrap services (`logd`, `timed`, `pwrmgr`, `terminal`, the staged test
harnesses) are not in this list: svcmgr launches them itself
post-handover from
their `/config/svcmgr/services/*.svc` recipes. Nor is the per-arch RTC
chip driver: devmgr spawns it from `/services/drivers/` once svcmgr installs
the drivers-dir cap (`devmgr_labels::SET_DRIVERS_DIR`), and
[timed](../services/timed/README.md) resolves it via
`devmgr_labels::QUERY_RTC_DEVICE` at startup. For each
service init starts, it delegates the appropriate capability subset (see
[`capability-model.md`](capability-model.md) §"Initial Capability
Distribution"). svcmgr is configured with the universal
`system_root_cap` so it can read `/config/svcmgr/services/*.svc`
post-handover.

Init then serves svcmgr the **handover endowment** (see
[`services/svcmgr/docs/ipc-interface.md`](../services/svcmgr/docs/ipc-interface.md)
§ Handover endowment) over the
bootstrap-round protocol: round 1 carries svcmgr's own endpoints plus the
publish-role source caps (a `SEND` on the root filesystem namespace
endpoint and a badge-0 `SEND|GRANT` source on devmgr's registry
endpoint); each subsequent `SUBSTRATE` round carries one `(name, thread_cap)`
pair for a substrate service init bootstrapped (`memmgr`, `procmgr`,
`devmgr`, `vfsd`), and a terminal `LOGD_SOURCES` round carries the
master-log endpoint source and a badge-0 `SEND|GRANT` source on procmgr's
endpoint, from which svcmgr launches real logd (restart: design intent; not
yet implemented (#262), per
[Restart Protocol](../services/svcmgr/docs/restart-protocol.md#supervision-hierarchy)
§ Supervision hierarchy). svcmgr — not init — then publishes the
well-known names it owns into its own registry
(`ipc::published_names::ROOTFS_ROOT`, `SVCMGR`, `DEVMGR_REGISTRY`, minted
from the endowed sources) and installs devmgr's `/services/drivers/` cap
via `devmgr_labels::SET_DRIVERS_DIR`.
The provider names (`timed`, `pwrmgr.shutdown`, `pwrmgr.deny`) are
published by svcmgr's provider path on each provider's launch. Recipes for
all svcmgr-supervised services live on disk at
`/config/svcmgr/services/<name>.svc`, not on the wire — see
[`services/svcmgr/docs/service-definitions.md`](../services/svcmgr/docs/service-definitions.md).

### Init reap

Before signalling `svcmgr_labels::HANDOVER_COMPLETE`, init moves its own
kernel-object caps (`AddressSpace`, `CSpace`, main `Thread`, init-logd
`Thread`) to procmgr in the first `procmgr_labels::REGISTER_INIT_TEARDOWN`
round, so procmgr's death observers are bound before real-logd can release
init-logd. After the handover reply (svcmgr replies immediately, then scans
`/config/svcmgr/services/`, binds the endowed substrate bind-only, and
launches every defined-but-unparked service — `logd`, the `timed` and
`pwrmgr` providers, and `terminal` on a normal boot, plus any staged test
recipes such as `svctest.svc` / `usertest.svc` and the co-staged
`crasher.svc` restart fixture), init streams every reclaimable Memory cap
it solely owns (ELF segments, user stack pages, `InitInfo` pages, the
bootloader/bundle reclaim ranges, the AP-trampoline frame, and the
boot-module ELF sources) in further `REGISTER_INIT_TEARDOWN` rounds, sends
`INIT_TEARDOWN_DONE`, then
`sys_thread_exit`s. The usable-RAM prefix init consumed or forwarded at
`finalize_memmgr` (already memmgr's) and the firmware read-only caps
(RSDP/ACPI/DTB) are excluded; the usable-RAM tail that did not fit memmgr's
bootstrap round and the free remainders `MemoryAlloc` abandoned while
carving bootstrap arenas are donated with the set above. init's own
bootstrap backing — its endpoint and log-thread retype slabs plus the
offset-mapped IPC buffer and log-thread stack/IPC — is not in this set:
it lives in a single contiguous arena Memory cap that init forwards to
memmgr as an in-use run at bootstrap (`finalize_memmgr`), so those pages
are already accounted in memmgr's pool and never reach the reap route.

Procmgr binds a death-EQ observer on **both** init threads (main + init-logd) and reaps only once
both have exited — init is threadless. The main thread exits at the end of init's Handover stage,
but init-logd keeps serving the master log endpoint until the svcmgr-launched real-logd pulls its
handover, so it outlives main; reclaiming init's address space while a thread still runs in it would
fault that thread. On the last death procmgr tears down init's kernel objects in order (Threads →
AddressSpace → donate Memory caps to memmgr → CSpace), leaving two init residues: the caps init
still holds, and the kernel-direct page-table nodes behind its bootstrap mappings. The caps stay in
init's CSpace, which the kernel pins (it is the root CSpace; see
[capability-internals.md § Kernel Object Reference Counting](../core/kernel/docs/capability-internals.md#kernel-object-reference-counting)),
so procmgr's delete drops only its own reference and they remain alive but unreachable; releasing
them at the reap is design intent, not yet implemented
([#443](https://github.com/kottlerg/seraph/issues/443)). The page-table nodes stay consumed after
init's AddressSpace is gone, an accepted cost owned by
[memory-internals.md § Page Table Node Ownership](../core/kernel/docs/memory-internals.md#page-table-node-ownership).
The procmgr-side protocol is specified in
[procmgr IPC Interface](../services/procmgr/docs/ipc-interface.md) § `REGISTER_INIT_TEARDOWN` and §
`INIT_TEARDOWN_DONE`.

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
and its allocations for child kernel objects, ELF segments, stacks, TLS
blocks, and `ProcessInfo` pages come from the same path. Apart from the
boot-module ELF Memory caps (transient derived copies init lends for ELF
loading, consumed as read-only sources) and the Memory caps init streams to
it for the init-reap donation (forwarded to memmgr via
`DONATE_MEMORY_CAPS`), every Memory cap procmgr holds originates in memmgr.

Procmgr is the privileged caller for memmgr's three procmgr-only labels
(`REGISTER_PROCESS`, `PROCESS_DIED`, `DELEGATE_ASPACE`). No other service
can mint or retire process badges against memmgr. See
[`memmgr/docs/ipc-interface.md`](../services/memmgr/docs/ipc-interface.md)
§ Badge Discipline.

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
- `ProcessInfo.stack_top_vaddr` / `ProcessInfo.main_tls_vaddr` — the
  per-process stack top and main-thread TLS block base, chosen by the
  creator via `shared/process-layout` (`main_tls_vaddr` is zero when the
  binary has no `PT_TLS`).
- `ProcessInfo.creator_endpoint_cap` — badged SEND back to the parent's
  bootstrap endpoint, distinct per child.
- `ProcessInfo.memmgr_endpoint_cap` — badged SEND on memmgr's endpoint,
  identifying this process; minted by `REGISTER_PROCESS` per child.
- `ProcessInfo.procmgr_endpoint_cap` — badged SEND on procmgr's
  endpoint, for process-lifecycle queries.
- `ProcessInfo.log_send_cap` — badged SEND cap on the master log
  endpoint, minted by procmgr per child via
  `cap_derive_badge(log_send_source, RIGHTS_EP_SEND, process_badge)`.
  The cap's kernel-attached badge equals procmgr's process badge,
  which also equals the death-EQ correlator procmgr posts to
  logd. Identity is reconciled across the three views without
  any auxiliary mapping.
- `ProcessInfo.sched_control_cap` — baseline `SchedControl` cap covering the
  band the spawner assigned (`[1, band_max]`, from the create label's
  `CREATE_BAND_MAX` field; default is a copy of the creator's own band).
  procmgr mints it from its baseline (delivered by init) — a plain `cap_copy`
  for a full-width band, copy-then-`SYS_SCHED_SPLIT` for a narrowed one. A
  child with a zero slot holds no scheduling authority and cannot set any
  priority.
- `ProcessInfo.initial_priority` — the level the creator placed the child's
  initial thread at (the create label's `CREATE_PRIORITY` field, defaulted
  and validated by procmgr against the creator's band). Always within the
  child's own band, so the runtime can create further threads at the same
  level via `SYS_CAP_CREATE_THREAD`'s scheduling arguments.
- `InitInfo.memory_base`, `InitInfo.memory_count` — chosen
  by the kernel per init invocation.

### Handover-page addresses (creator-chosen, register-delivered)

The handover page itself (`ProcessInfo`, or `InitInfo` for init) cannot
record its own address — that address is what locates the page. The
creator draws it per-process from a fixed randomisation window (ASLR,
[#39](https://github.com/kottlerg/seraph/issues/39); procmgr/init via
[`shared/process-layout`](../shared/process-layout/README.md), the kernel via
`choose_init_layout` for init)
and delivers it to the child in the entry register (`rdi`/`a0`); the
child's `_start` takes it as its argument. The stack, TLS, and
IPC-buffer VAs are likewise creator-drawn but travel as the runtime
`ProcessInfo` fields above. No
handover *address* is an ABI constant; the ABI crates declare only policy
bounds (`DEFAULT_PROCESS_STACK_PAGES`, `MAX_PROCESS_STACK_PAGES`,
`PROCESS_MAIN_TLS_MAX_PAGES`, `INIT_STACK_PAGES`, `INIT_INFO_MAX_PAGES`).

### CSpace slot conventions

The `ProcessInfo` page also names the well-known CSpace slots that the
parent populates (see
[`abi/process-abi/README.md`](../abi/process-abi/README.md) §"Fixed
CSpace slot conventions"). These are slot indices, not VAs.

---

## Steady-State Process Creation

After bootstrap, every process is created by procmgr. The flow:

1. **Caller IPC.** A service (init, svcmgr, devmgr, vfsd) sends
   `CREATE_PROCESS` (or `CREATE_FROM_FILE`) to procmgr.
2. **Procmgr → memmgr.** Procmgr calls `memmgr.REGISTER_PROCESS` and
   receives a badged SEND cap identifying the new process; every later
   allocation for the child uses it.
3. **Procmgr ELF parse.** Procmgr maps the ELF source, validates its
   headers, draws the image load bias, and computes the segment layout
   and relocation plan (PIE; see
   [userspace-memory-model.md](userspace-memory-model.md) "Image
   Placement").
4. **Procmgr kernel-object allocation.** Procmgr creates the new
   process's `AddressSpace`, `CSpace`, and `Thread` via the
   `cap_create_*` syscalls.
5. **Procmgr → memmgr (frames).** Procmgr requests Memory caps from
   memmgr to back the child's stack, IPC buffer, `ProcessInfo` page,
   TLS block, and ELF segments. These calls go over the child's badged
   SEND cap returned by `REGISTER_PROCESS` (step 2), so memmgr accounts
   the frames against the child's per-process record from allocation.
6. **Procmgr maps + populates the child.** Procmgr stages each ELF
   segment's frames through a transient procmgr-side scratch mapping,
   copying the segment bytes and applying the image's relocations, then
   maps the frames into the child's address space at procmgr-chosen VAs
   and populates `ProcessInfo` (including `memmgr_endpoint_cap` from
   step 2 and the procmgr/log endpoints).
7. **No ownership transfer.** Every child frame and kernel-object retype
   slab is requested on the child's badged memmgr cap, so memmgr accounts
   it to the child's record from the moment it leaves the pool; procmgr
   deletes its transient slots after mapping, and `PROCESS_DIED` reclaims
   the set (see
   [`memmgr/docs/ipc-interface.md`](../services/memmgr/docs/ipc-interface.md)).
8. **Procmgr replies to caller.** `CREATE_PROCESS` returns the badged
   process handle and a thread cap to the original caller.
9. **Caller sends `START_PROCESS`.** Procmgr runs `thread_configure` +
   `thread_start`; the child's std `_start` registers its IPC buffer,
   bootstraps the heap by calling `REQUEST_MEMORY_CAPS` on its own
   `memmgr_endpoint_cap`, and enters `main()`.

A process created via `CREATE_PROCESS` is suspended until
`START_PROCESS`; the heap-bootstrap step (9) only runs after the caller
has finished injecting any additional capabilities.

Unless the caller sets `CREATE_PINNED`, procmgr delegates the child's
`AddressSpace` to memmgr (`DELEGATE_ASPACE`) and binds the initial thread's
fault handler to memmgr, the default demand-paging pager, before replying;
see [Fault Handling](fault-handling.md).

---

## Process Death

A process dies when:

- It calls `sys_process_exit` (the `std::process::exit` / `main`-return path),
  carrying a voluntary exit code.
- It calls `sys_thread_exit` on its last thread (a thread completing).
- procmgr revokes and deletes its caps to the process's `Thread`, `CSpace`, and `AddressSpace` (the
  "kill process" pattern; see [`capability-model.md`](capability-model.md)
  §`"Kill process" pattern`).
- The last capability to its `CSpace` or `AddressSpace` is deleted: the kernel stops every thread
  bound to the object (retained exit reason `EXIT_KILLED`) before reclaiming it, so the process's
  threads cannot outlive either. A thread deleting the last capability to its own `CSpace` or
  `AddressSpace` is stopped by that same delete and never returns from it.
- An unhandled fault terminates its threads.

The kill-process pattern and the `CSpace`/`AddressSpace` teardown have known kernel memory-safety
gaps, tracked in [#443](https://github.com/kottlerg/seraph/issues/443) (see
[IPC Design](ipc-design.md#the-callreply-model) and
[Capability Internals](../core/kernel/docs/capability-internals.md#storage-hybrid-two-level-radix)).

### Exit reason

The kernel records a single 32-bit **exit reason** at death and delivers it
(low 32 bits) through the thread death-observer surface. It is a flat,
kernel-owned space partitioned into disjoint ranges so userspace can never forge
a fault or kill reason — defined once in `syscall_abi`:

| Reason value | Class | Meaning |
|---|---|---|
| `0` (`EXIT_VOLUNTARY`) | Voluntary, clean | success — `sys_process_exit(0)`, `sys_thread_exit`, `ExitCode::SUCCESS` |
| `1 ..= 0x0FFF` | Voluntary, code | `sys_process_exit(code)` via `encode_exit_code` (saturating); `std::process::exit(n)` / non-zero `ExitCode` |
| `0x1000 ..= 0x1FFF` (`EXIT_FAULT_BASE + vector`) | Fault | unhandled CPU/VM fault; kernel-terminated |
| `0x2000` (`EXIT_KILLED`) | Killed | recorded by the kernel as the retained reason of a thread stopped by its `CSpace`/`AddressSpace` teardown (that stop posts no death event; an observer bound afterwards receives the retained reason through the bind); posted by userspace (`Child::kill`) |

`sys_process_exit` records the encoded reason as the calling thread's exit reason and posts it to
that thread's death observers — a parent that bound the main thread (so `ExitStatus::code()` carries
it) and procmgr's per-thread observer (which reaps the process). It is structurally identical to
`sys_thread_exit` but with the encoded caller-supplied reason (zero for `exit(0)`), and schedules
away immediately after the post; it does **not** post to the address-space death surface (reserved
for terminal faults), because doing so on every clean exit would dereference the address space after
procmgr had already been woken to reap it. The kernel only *notifies*; it does not enumerate or stop
sibling threads at that point — they are stopped when procmgr's cap-revoke teardown below deletes
the process's `CSpace` (every thread bound to it is stopped before its storage is reclaimed,
wherever their thread caps are held, subject to the #443 gaps stated above) and reaped through
their own thread caps.
`ExitStatus::success()`/`code()` decode the reason on the consumer side. This is a Seraph-native
encoding, not POSIX: codes are not 8-bit `WEXITSTATUS`-truncated and faults are native fault
classes, not signals. See [`core/kernel/docs/syscalls.md`](../core/kernel/docs/syscalls.md) §
`SYS_PROCESS_EXIT`.

The death-notification flow:

1. **Procmgr observes.** Procmgr's existing supervision path detects
   the death (a death notification on the child's main thread, an
   address-space death notification for a terminal fault in any thread,
   or an explicit `DESTROY_PROCESS` teardown).
2. **Procmgr → memmgr.** Procmgr sends `PROCESS_DIED` to memmgr carrying
   the dead process's memmgr badge in `data[0]` (the badged cap is not
   transferred; procmgr deletes its copy afterwards). The badge identifies
   which per-process record memmgr reclaims (see
   [`memmgr/docs/ipc-interface.md`](../services/memmgr/docs/ipc-interface.md)
   § Label 4).
3. **Memmgr reclaims.** Memmgr walks the per-process frame list and
   inserts each Memory cap back into its free pool.
4. **Memmgr coalesces.** Reverse-`memory_split` merges adjacent free
   runs to sustain `REQUIRE_CONTIGUOUS` success rates. See
   [`memmgr/docs/memory-pool.md`](../services/memmgr/docs/memory-pool.md)
   §"Coalescing".
5. **Procmgr clears its registry entry.** Independent of memmgr's
   reclamation; the procmgr-side process table releases its slot.

Memory caps the dead process held in its CSpace become unreachable when
procmgr's teardown revokes and deletes the child's `CSpace`. Memmgr's
intermediary derivations (retained at allocation time
per the derive-twice pattern) are unaffected and are what the
reclamation step inserts back into the free pool.

---

## Procmgr Restart Fallback

If procmgr itself dies, no other process can spawn replacements via the
normal path. procmgr's recipe is `restart = never`, `critical = yes`:
svcmgr does not recreate procmgr and initiates a graceful shutdown (see
[Restart Protocol](../services/svcmgr/docs/restart-protocol.md#procmgr-fallback)
§ procmgr Fallback and
[`.svc` Service Definitions](../services/svcmgr/docs/service-definitions.md#critical)
§ `critical`). A raw-syscall
fallback that recreates procmgr and re-establishes its memmgr cap is not
implemented.

memmgr's state is independent of procmgr's, and memmgr's `REGISTER_PROCESS`
authority is held by whichever process holds the procmgr-side badged
cap at the time.

If memmgr dies, the system cannot recover. Memmgr is on the trusted
path of every std-built service; its death implies an unrecoverable
fault. svcmgr does not restart memmgr.

---

## Out of Scope

Seraph does not implement `fork()` or copy-on-write. Process creation
is always from-scratch via `CREATE_PROCESS` or `CREATE_FROM_FILE`; zero-copy
buffer handoff between processes uses Memory-cap moves over IPC.

Userspace fault handling is specified as the pager protocol in
[Fault Handling](fault-handling.md). An unresolved fault is delivered to the
thread's bound handler (memmgr, the default pager, unless the process was
created `CREATE_PINNED`); a thread with no bound handler, or whose handler
replies `KILL`, terminates, which surfaces through the normal process-death
notification flow above.

---

## Summarized By

[abi/init-protocol/README.md](../abi/init-protocol/README.md),
[Memory Map Translation](../core/boot/docs/memory-map.md),
[Capability Subsystem Internals](../core/kernel/docs/capability-internals.md),
[Kernel Initialization Sequence](../core/kernel/docs/initialization.md),
[Memory Subsystem Internals](../core/kernel/docs/memory-internals.md),
[Scheduler Internals](../core/kernel/docs/scheduler.md),
[SMP Scheduling and Locking Invariants](../core/kernel/docs/scheduling-internals.md),
[Syscall Interface Specification](../core/kernel/docs/syscalls.md),
[Architecture Overview](architecture.md), [System Bootstrap](bootstrap.md),
[Capability Model](capability-model.md), [Fault Handling](fault-handling.md), [Testing](testing.md),
[Userspace Memory Model](userspace-memory-model.md),
[programs/pipefault/README.md](../programs/pipefault/README.md),
[programs/relrofault/README.md](../programs/relrofault/README.md),
[programs/stackoverflow/README.md](../programs/stackoverflow/README.md),
[programs/threadstack/README.md](../programs/threadstack/README.md),
[runtime/ruststd/README.md](../runtime/ruststd/README.md),
[services/crasher/README.md](../services/crasher/README.md),
[services/init/README.md](../services/init/README.md),
[init Bootstrap Stages](../services/init/docs/bootstrap.md),
[services/logd/README.md](../services/logd/README.md),
[logd IPC interface](../services/logd/docs/ipc-interface.md),
[services/memmgr/README.md](../services/memmgr/README.md),
[memmgr IPC Interface](../services/memmgr/docs/ipc-interface.md),
[memmgr Memory Pool](../services/memmgr/docs/memory-pool.md),
[services/procmgr/README.md](../services/procmgr/README.md),
[procmgr IPC Interface](../services/procmgr/docs/ipc-interface.md),
[services/svcmgr/README.md](../services/svcmgr/README.md),
[svcmgr IPC Interface](../services/svcmgr/docs/ipc-interface.md),
[Restart Protocol](../services/svcmgr/docs/restart-protocol.md),
[`.svc` Service Definitions](../services/svcmgr/docs/service-definitions.md),
[shared/elf/README.md](../shared/elf/README.md), [shared/log/README.md](../shared/log/README.md),
[shared/process-layout/README.md](../shared/process-layout/README.md)
