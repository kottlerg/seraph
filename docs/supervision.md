# Supervision

System-wide model of who supervises which userspace service, which services restart and how, and
what the death of a service that cannot restart does to the system.

---

## Scope

This document is authoritative for:

- The supervision hierarchy: which process observes each service's death and decides what follows
  it.
- The late-launch rule: which services init launches and which svcmgr launches.
- The core set, the services that never restart, and system death.
- The restart shapes, and which service uses which.
- The authority a supervisor holds to restart what it supervises.

Each supervisor's own mechanism (svcmgr's death detection, decision tree, spawn primitives and
recipe storage; devmgr's driver withdrawal; procmgr's reaping) is specified in that component's
documents, linked below. The recipe keys (`restart`, `critical`, `shutdown_actuator`) are specified
in [`.svc` Service Definitions](../services/svcmgr/docs/service-definitions.md).

---

## Supervision Hierarchy

A supervisor observes a process's death and applies a policy to it: restart the process, continue
without it, or power the system off. Observing a death is not supervising it: procmgr observes the
death of every process it created, and reaps each one
([Process Lifecycle § Process Death](process-lifecycle.md#process-death)), but decides no restart
and no shutdown.

```
init            launches the bootstrap substrate, endows svcmgr, exits; supervises nothing
svcmgr          supervises the substrate (memmgr, procmgr, devmgr, vfsd) and every service it
   │            launches from a recipe (logd, timed, pwrmgr, crashd, ...)
   ├── devmgr   observes every driver's death and withdraws the driver; restarts none
   └── vfsd     observes no fs driver's death; restarts none
pwrmgr          observes svcmgr (design intent; not yet implemented, #262)
```

| Supervisor | Supervises | Observes death through | On death |
|---|---|---|---|
| svcmgr | memmgr, procmgr, devmgr, vfsd (endowed by init) | a death observer bound on the thread cap each endowment round delivers | the service's recipe decides; every one of these is `restart = never`, `critical = yes`, so its death powers the system off |
| svcmgr | each service it launches with a `restart` other than `never` | a death observer bound on the thread cap procmgr's create reply returns | the recipe's `restart` policy and budget, then `critical` ([Restart Protocol § Decision tree](../services/svcmgr/docs/restart-protocol.md#decision-tree)) |
| devmgr | drivers it spawns | a death observer bound on each driver's thread | the driver is withdrawn and its DMA hold released once its device is quiesced; no restart (design intent; not yet implemented, #1077; the IOMMU driver, #1079) ([devmgr responsibilities](../services/devmgr/docs/responsibilities.md#relationship-to-drivers)) |
| vfsd | fs drivers it spawns | nothing | the mount stays installed against the dead endpoint; no restart (design intent; not yet implemented, #1078) ([Storage § Failure and Revocation Invariants](storage.md#failure-and-revocation-invariants)) |
| pwrmgr | svcmgr | an event queue svcmgr binds to its own death (§ Observing svcmgr) | power-off (design intent; not yet implemented, #262) |

A `restart = never` service that svcmgr launches, rather than binds, is launched one-shot: svcmgr
binds no death observer for it and keeps no record of it, so that service has no supervisor
([Restart Protocol](../services/svcmgr/docs/restart-protocol.md#supervision-hierarchy)
§ Supervision hierarchy).

---

## Late-Launch Rule

init launches only the bootstrap substrate, the services that must run before svcmgr can read a
recipe: memmgr and procmgr, by raw syscalls; devmgr and vfsd, from boot modules through procmgr; and
svcmgr, from the root filesystem through procmgr. devmgr and vfsd start the drivers carried as boot
modules, which the console and the root mount need. Every other top-level service MUST be
first-launched by svcmgr from its recipe, never by init, so that one recipe defines its first launch
and its restart, and the authority it receives is what that recipe grants. A new service adds a
recipe under `/config/svcmgr/services/`, not an init stage. The stage-by-stage bring-up is specified
in [Process Lifecycle § Userspace Boot Order](process-lifecycle.md#userspace-boot-order) and [init
Bootstrap Stages](../services/init/docs/bootstrap.md).

---

## Core Set and System Death

memmgr, procmgr and svcmgr are the core set. None of them restarts, and the death of any of them is
system death: the system powers off.

- **memmgr** holds every RAM frame and is the pager of nearly every process
  ([Fault Handling § Default System Pager](fault-handling.md#default-system-pager)).
- **procmgr** holds every process's kernel objects, death bindings, memmgr badge and DMA hold
  ([services/procmgr/README.md](../services/procmgr/README.md) § Process table and death queues).
- **svcmgr** holds the restart recipes and the persistent endpoint sources (§ Restart Authority).

None of the three can be rebuilt without the state it holds, and a restart that loses that state
leaves orphaned, unreapable processes and leaked frames. A fault in a core service is evidence that
its state is already corrupt. The cost is no availability across a core fault: the core's
correctness bounds the system's uptime. The policy stays in userspace: the kernel has no notion of
a critical thread.

The recipes of memmgr and procmgr are `restart = never`, `critical = yes`, so svcmgr routes either
death to its graceful shutdown through the shutdown actuator, pwrmgr
([Restart Protocol § Decision tree](../services/svcmgr/docs/restart-protocol.md#decision-tree)).
svcmgr cannot observe its own death. pwrmgr observing it and powering the system off is design
intent; not yet implemented (#262) (§ Observing svcmgr): today svcmgr's death is observed only by
procmgr, which reaps it, and the system runs on unsupervised.

devmgr and vfsd are `restart = never`, `critical = yes`, and are not in the core set: their restart
is future work that no principle excludes, and no restart of either is designed yet. The death of
either is system death through the same graceful shutdown, by its recipe, not by membership of the
core set.

The path from a core or critical death to power-off MUST NOT depend on the service that died. svcmgr
and pwrmgr are demand-paged on memmgr (memmgr and procmgr are pinned by construction, per
[Fault Handling § Default System Pager](fault-handling.md#default-system-pager)), so whether a
memmgr death reaches power-off is not established. A test that kills each core and critical service
and checks the power-off on both architectures, with the fixes it needs, is design intent; not yet
implemented (#262).

---

## Restart Shapes

A supervised service outside the core set restarts in one of two shapes, chosen by what its clients'
capabilities name, or its recipe states why its loss is critical.

- **Persistent endpoint.** The endpoint's holder keeps the endpoint's original for the system's life
  and gives each instance a fresh RECV derived from it. Clients' SENDs are derived from the same
  original, so they survive the death and reach the next instance with no re-resolution. It fits a
  service whose badges carry the caller's identity or authority and name no state held in the dead
  instance.
- **Revoke and re-resolve.** The supervisor keeps the dead instance's endpoint original and revokes
  it, which invalidates every capability derived from it
  ([Capability Model § Revocation](capability-model.md#revocation)), so a client's stale capability
  fails closed. It starts a fresh instance, and clients resolve the service again through the
  supervisor. It fits a stateful session service, whose badges name server-side state (an open node,
  a driver session) that a fresh instance cannot honour.
- **No restart.** The core set (§ Core Set and System Death).

| Service | Supervisor | Shape |
|---|---|---|
| memmgr, procmgr, svcmgr | none restarts them | no restart: core set |
| devmgr, vfsd | svcmgr | no restart: `critical = yes`, outside the core set |
| timed, pwrmgr | svcmgr | persistent endpoint, held by svcmgr |
| logd | svcmgr | persistent endpoint (the master log endpoint), held by svcmgr; a working restart is design intent; not yet implemented (#262) |
| crashd | svcmgr | persistent endpoint (procmgr's crash endpoint), held by procmgr, which declines faults while no crash service is registered and hands the endpoint to the restarted crashd when it registers ([crashd Operation § Startup](../services/crashd/docs/operation.md#startup)) |
| drivers | devmgr | none today; the shape is chosen per driver (design intent; not yet implemented, #1077); the IOMMU driver (#1079) |
| fs drivers | vfsd | none today; revoke and re-resolve (design intent; not yet implemented, #1078) |

---

## Restart Authority

A supervisor holds, for the system's life, what a restart of each service it supervises needs, so
that no restart depends on the dead instance or on a process that has exited. No supervisor holds
process-creation authority: every restart creates the new instance through procmgr
([Architecture Overview § Userspace Services](architecture.md#userspace-services)).

svcmgr holds:

- each launched service's recipe, recorded at reconciliation, and the universal root capability it
  walks the recipe's binary path from on every launch
  ([Restart Protocol § Recipe storage](../services/svcmgr/docs/restart-protocol.md#recipe-storage));
- the original of each provider's service endpoint, which it creates on the provider's first launch;
- the master log endpoint source and a source on procmgr's endpoint, from which it mints each logd
  instance's caps and each `debug_authority` service's debug authority
  ([svcmgr IPC Interface](../services/svcmgr/docs/ipc-interface.md) § Handover endowment);
- the devmgr registry source and the published names, from which it re-resolves a restarted
  service's seeds;
- a death observer on each supervised service's main thread.

svcmgr holds no authority to recreate the substrate init launched. memmgr and procmgr were built by
init's raw syscalls from boot modules, and devmgr and vfsd received firmware authority and tokened
capabilities from init that svcmgr cannot mint ([init Bootstrap
Stages](../services/init/docs/bootstrap.md#per-stage-authority-transfers)). A restart of devmgr or
vfsd would first need that authority to reach svcmgr.

devmgr holds the per-device capabilities it delegates to each driver and the release token of each
driver's DMA hold ([Device Management § DMA-Safe Teardown](device-management.md#dma-safe-teardown)).
vfsd keeps each fs driver's service endpoint original, from which it mints the mount's caps
([Storage § Failure and Revocation Invariants](storage.md#failure-and-revocation-invariants)).

---

## Observing svcmgr

Design intent; not yet implemented (#262). The mechanism uses existing kernel surfaces.

svcmgr creates one event queue at startup and binds two death observers on it: one on its own main
thread (`SYS_THREAD_BIND_NOTIFICATION`, through `ProcessInfo.self_thread_cap`), and one on its own
address space (`SYS_ASPACE_BIND_NOTIFICATION`, through `ProcessInfo.self_aspace_cap`), which a
terminal fault of any svcmgr thread posts to. svcmgr keeps the queue's original and delivers a
derivation carrying only the receive right to the shutdown actuator, pwrmgr, in the bootstrap round
of each of its launches. pwrmgr waits on that queue beside its service endpoint; an entry on it is
svcmgr's death, and pwrmgr powers the platform off.

svcmgr binds itself because both binds need Control on the observed object ([Syscall Interface
Specification](../core/kernel/docs/syscalls.md) § `SYS_THREAD_BIND_NOTIFICATION` (47) and §
`SYS_ASPACE_BIND_NOTIFICATION` (53)), and Control on a thread carries writes to its registers and to
the memory of its address space ([Capability Model § Thread](capability-model.md#thread)): a
capability pwrmgr could bind with would give pwrmgr all of svcmgr's authority. The receive right
gives pwrmgr only the death entry.

The bindings are on svcmgr's own thread and address space, so they survive every pwrmgr restart,
and each pwrmgr instance receives a fresh derivation of the same queue. An entry posted while
pwrmgr is down waits in the queue, but with svcmgr dead nothing restarts pwrmgr: a pwrmgr that is
down when svcmgr dies leaves svcmgr's death unobserved.

---

## Design Intent

Each item below is specified above or in the document it names, and is not yet implemented:

- pwrmgr observes svcmgr and powers off on its death (§ Observing svcmgr): #262.
- A test of each core and critical death, on a power-off path that does not depend on the dying
  service (§ Core Set and System Death): #262.
- logd restarts cleanly on its persistent endpoint
  ([Restart Protocol](../services/svcmgr/docs/restart-protocol.md#supervision-hierarchy)
  § Supervision hierarchy):
  #262.
- devmgr restarts drivers: #1077. The IOMMU driver survives and restarts: #1079.
- vfsd restarts fs drivers by revoke and re-resolve: #1078.
- procmgr tears down the processes a dead pager other than memmgr served: #226.

---

## Summarized By

[Architecture Overview](architecture.md), [Process Lifecycle](process-lifecycle.md),
[services/procmgr/README.md](../services/procmgr/README.md),
[services/pwrmgr/README.md](../services/pwrmgr/README.md),
[services/svcmgr/README.md](../services/svcmgr/README.md),
[Restart Protocol](../services/svcmgr/docs/restart-protocol.md)
