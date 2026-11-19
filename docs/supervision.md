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

The supervision of sessions, the processes a user starts through an interface, is specified in
[Session Supervision](session-supervision.md). Each supervisor's own mechanism (svcmgr's death
detection, decision tree, spawn primitives and recipe storage; devmgr's driver withdrawal;
procmgr's reaping) is specified in that component's documents, linked below. The recipe keys
(`restart`, `critical`, `shutdown_actuator`) are specified in
[`.svc` Service Definitions](../services/svcmgr/docs/service-definitions.md).

---

## Supervision Hierarchy

A supervisor observes a process's death and applies a policy to it: restart the process, continue
without it, or power the system off. Observing a death is not supervising it: procmgr observes the
death of every process it created, and reaps each one
([Process Lifecycle § Process Death](process-lifecycle.md#process-death)), but decides no restart
and no shutdown.

```
init            launches the bootstrap substrate, endows svcmgr, exits; supervises nothing, and
                halts the boot on a death before the handover (§ Core Set and System Death)
svcmgr          supervises the substrate (memmgr, procmgr, devmgr, vfsd) and every service it
   │            launches from a recipe (logd, timed, pwrmgr, crashd, ...)
   ├── devmgr   observes each driver's death, withdraws a dead driver, restarts a served one
   ├── vfsd     observes each fs driver's death, restarts the driver of a mount below /
   └── sessiond supervises each session's leader
pwrmgr          observes svcmgr; powers the system off on its death
```

| Supervisor | Supervises | Observes death through | On death |
|---|---|---|---|
| svcmgr | memmgr, procmgr, devmgr, vfsd (endowed by init) | two death observers: one on the main thread, through the thread cap each endowment round delivers, and one on the address space, which the first terminal fault of any thread posts (memmgr and procmgr through a Control-only address-space cap init endows; devmgr and vfsd through their process handles, which init endows and procmgr binds on svcmgr's behalf) | the service's recipe decides; every one of these is `restart = never`, `critical = yes`, so its death powers the system off |
| svcmgr | each service it launches with a `restart` other than `never` | two death observers, bound before `START_PROCESS`: one on the main thread, through the thread cap procmgr's create reply returns, and one on the address space, which procmgr binds on the process handle (`BIND_DEATH_OBSERVER`) with a `POST` copy of a svcmgr death queue | the recipe's `restart` policy and budget, then `critical` ([Restart Protocol § Decision tree](../services/svcmgr/docs/restart-protocol.md#decision-tree)) |
| devmgr | drivers it spawns | a death observer bound on each driver's main thread, and one procmgr binds on its address space (`BIND_DEATH_OBSERVER`), which the first terminal fault of any of its threads posts | the driver is withdrawn and its DMA hold released once its device is quiesced, and a served driver that died of a fault or a kill is restarted ([devmgr responsibilities](../services/devmgr/docs/responsibilities.md#driver-restart)); the IOMMU driver is not restarted (design intent; not yet implemented, #1079) ([devmgr responsibilities](../services/devmgr/docs/responsibilities.md#relationship-to-drivers)) |
| vfsd | fs drivers it spawns | a death queue per mount, bound on the driver's main thread, to whose relay (`CREATE_DEATH_RELAY`) procmgr posts the driver's end, whoever ends it, a terminal fault in any of its threads included | the driver of a mount below `/` is restarted on the same partition, within a per-mount budget, and once the budget is spent the mount is torn down and its path falls through to the root filesystem; the root mount's driver's death ends vfsd, so the system shuts down ([Storage § Failure and Revocation Invariants](storage.md#failure-and-revocation-invariants); [vfsd namespace composition § Driver restart](../services/vfsd/docs/namespace-composition.md#driver-restart)) |
| sessiond | each session's leader and, through containment, every process the leader starts | a death observer on the leader's main thread, and one procmgr binds on its address space | the session ends: procmgr destroys what is left of the leader's subtree ([Session Supervision](session-supervision.md#sessiond)) |
| pwrmgr | svcmgr | an event queue svcmgr binds to its own death (§ Observing svcmgr) | power-off |

A `restart = never` service that svcmgr launches, rather than binds, is launched one-shot: svcmgr
binds no death observer for it and keeps no record of it, so that service has no supervisor
([Restart Protocol](../services/svcmgr/docs/restart-protocol.md#supervision-hierarchy)
§ Supervision hierarchy).

svcmgr binds both observers for every supervised service, so the policy above applies to the death
of any thread. A terminal fault in a thread other than the main thread of a service (crashd, logd,
devmgr and vfsd run worker threads) drives procmgr's teardown of the whole process. That teardown
revokes svcmgr's thread cap, and its stop of the main thread posts no death
([Process Lifecycle § Exit reason](process-lifecycle.md#exit-reason)), but the fault is the address
space's first terminal fault, so the address-space observer posts it. A fault of a critical
service's worker thread therefore reaches the critical shutdown path, and of a restartable
service's its restart policy. A main-thread fault that is the space's first terminal fault posts
twice; svcmgr routes the first and drops the second ([Restart Protocol § Death
detection](../services/svcmgr/docs/restart-protocol.md#death-detection)).

devmgr also has procmgr bind an observer on each driver's address space
([procmgr IPC Interface](../services/procmgr/docs/ipc-interface.md) § Label 25:
`BIND_DEATH_OBSERVER`), so a terminal fault in a driver's worker thread, which drives the same
teardown, still reaches devmgr, which withdraws the driver.

---

## Late-Launch Rule

init launches only the bootstrap substrate, the services that must run before svcmgr can read a
recipe: memmgr and procmgr, by raw syscalls; devmgr and vfsd, from boot modules through procmgr; and
svcmgr, from the root filesystem through procmgr. devmgr and vfsd start the drivers carried as boot
modules: those the root mount needs, which are part of the bootstrap closure ([Boot
Media](boot-media.md) § The Bootstrap Closure); devmgr starts the console's `serial` and
`framebuffer` drivers from the root filesystem. Every other top-level service MUST be
first-launched by svcmgr from its recipe, never by init, so that one recipe defines its first launch
and its restart, and the authority it receives is what that recipe grants. A new service adds a
recipe under `/config/svcmgr/services/`, not an init stage. The stage-by-stage bring-up is specified
in [Process Lifecycle § Userspace Boot Order](process-lifecycle.md#userspace-boot-order) and [init
Bootstrap Stages](../services/init/docs/bootstrap.md).

---

## Core Set and System Death

memmgr, procmgr and svcmgr are the core set. None of them restarts, and the death of any of them is
system death: the system powers off, except before svcmgr's handover, where system death is init's
logged halt (below).

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
svcmgr cannot observe its own death; pwrmgr observes it and powers the system off (§ Observing
svcmgr). What svcmgr observes of memmgr and procmgr is the death of the main thread and the first
terminal fault of any thread, through the Control-only address-space cap init endows for each
(§ Supervision Hierarchy). A terminal fault in another of their threads (such as procmgr's reaper or
request workers) is therefore the service's death and powers the system off.

devmgr and vfsd are `restart = never`, `critical = yes`, and are not in the core set: their restart
is future work that no principle excludes, and no restart of either is designed yet. The death of
either, of its main thread or of any worker thread, is system death through the same graceful
shutdown, by its recipe, not by membership of the core set (§ Supervision Hierarchy). svcmgr calls
both before its reconciliation records them, and checks the liveness of each before each step
that calls it and after each call that fails. A devmgr death it finds is recorded at
reconciliation and routed then. svcmgr reads its recipes through vfsd, so a vfsd death before
reconciliation leaves it no recipe and no shutdown actuator: it routes the death as system death,
which with no actuator is the logged degraded state
([Restart Protocol § Death detection](../services/svcmgr/docs/restart-protocol.md#death-detection)).
A server that dies after the check, while svcmgr's next call to it waits unreceived, leaves svcmgr
blocked: a call on an endpoint none of whose receivers is left never returns (#1185).

The root filesystem's driver and the driver of the disk under it never restart, and the root is not
remounted in a running system ([Boot Media](boot-media.md) § Bootstrap-Only Boot Copies). The loss
of either is system death through vfsd: the death of the root mount's driver, or the loss of its
disk (devmgr withdraws the disk when its driver dies or the device is removed), ends vfsd, whose
death svcmgr routes to the graceful shutdown above ([Storage § Failure and Revocation
Invariants](storage.md#failure-and-revocation-invariants)).

The path from a core or critical death to power-off MUST NOT depend on the service that died.
`cargo xtask test-core-death` kills memmgr, procmgr (a request worker, and its reaper thread),
svcmgr, devmgr, vfsd and logd (until svcmgr's restart budget for it is spent), one boot each, by a
terminal fault made from outside the guest, and checks that the system powers off, on both
architectures ([Testing § Core death](testing.md#core-death-test-core-death)). It kills devmgr and
vfsd once svcmgr has reconciled its recipes, after the window that #1185 leaves open above, and
logd from the stub's first attach to it, which can fall before logd asks svcmgr for its bootstrap
round. svcmgr does not wait for good on a service that dies after its start and before that
request: its wait for the request ends at the death, which it routes by the service's restart
policy, on the first launch and on a restart alike, and it goes on with its reconciliation or its
supervision ([Restart Protocol § Death
detection](../services/svcmgr/docs/restart-protocol.md#death-detection)). The path does not yet
hold the requirement by construction: svcmgr, pwrmgr and, on x86-64, acpid are
demand-paged on memmgr and grow their heaps through it (memmgr and procmgr are pinned by
construction, per [Fault Handling § Default System Pager](fault-handling.md#default-system-pager)),
so a fault on a page not yet resident, or a call to memmgr, on the path after memmgr's death waits
for good. A power-off path that neither faults nor calls memmgr after a core death is design
intent; not yet implemented (#1290).

Before svcmgr's handover no supervisor runs, and init is the one process placed to see a death: it
serves the bootstrap rounds of memmgr, procmgr, devmgr, vfsd and svcmgr, and reads the child's main
thread while it waits for each request ([init Bootstrap Stages § A death during the
bootstrap](../services/init/docs/bootstrap.md#a-death-during-the-bootstrap)). A death init sees
there is system death, and before the handover system death is a logged halt, not a power-off:
init logs `init: FATAL: <service> died during its bootstrap (exit reason 0x<reason>)`, serves
nothing more and its main thread exits, and the system stays up, halted, until an operator or a
watchdog acts. No power-off is reachable there on x86-64: S5 needs the `\_S5_` sleep value, which
only acpid evaluates, and acpid is a driver launched after the handover. One halt on both
architectures keeps the window to the rule every other bootstrap failure of init follows. The
halted system keeps the FATAL line on the serial console, which init-logd writes until real-logd
takes over, and a test boot fails at that line, which the `FATAL:` marker of the run's fail
pattern matches, rather than at its deadline.

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
| logd | svcmgr | persistent endpoint (the master log endpoint), held by svcmgr ([Restart Protocol § Supervision hierarchy](../services/svcmgr/docs/restart-protocol.md#supervision-hierarchy)) |
| crashd | svcmgr | persistent endpoint (procmgr's crash endpoint), held by procmgr, which declines faults while no crash service is registered and hands the endpoint to the restarted crashd when it registers ([crashd Operation § Startup](../services/crashd/docs/operation.md#startup)) |
| drivers | devmgr | revoke and re-resolve, at the class's next ordinal, within a per-record budget ([devmgr responsibilities](../services/devmgr/docs/responsibilities.md#driver-restart); [restart-budget](../shared/restart-budget/README.md)); the IOMMU driver is not restarted (design intent; not yet implemented, #1079); the driver of the root filesystem's disk never restarts (§ Core Set and System Death) |
| fs drivers | vfsd | revoke and re-resolve, at the same mount path, within a per-mount budget ([vfsd namespace composition § Driver restart](../services/vfsd/docs/namespace-composition.md#driver-restart); [restart-budget](../shared/restart-budget/README.md)); the root filesystem's driver never restarts (§ Core Set and System Death) |

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
  instance's caps and each `debug_authority` service's debug authority, and the `EntropyControl`
  source, from which it derives the `entropy_authority` service's copy
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
vfsd keeps each fs driver's service endpoint original, from which it mints the mount's caps, the
partition cap it registered for the mount, from which it derives each instance's, and the mount's
restart budget; it starts each restarted driver from its installed path on the root filesystem,
through vfsd's own system-root cap (vfsd
[namespace composition § Driver restart](../services/vfsd/docs/namespace-composition.md#driver-restart)).

---

## Observing svcmgr

The mechanism uses existing kernel surfaces.

svcmgr creates one event queue at startup, with room for an entry from each observer, and binds two
death observers on it: one on its own main thread (`SYS_THREAD_BIND_NOTIFICATION`, through
`ProcessInfo.self_thread_cap`), and one on its own address space (`SYS_ASPACE_BIND_NOTIFICATION`,
through `ProcessInfo.self_aspace_cap`), which the first terminal fault of any svcmgr thread posts
to. svcmgr keeps the queue's original and delivers a derivation carrying only the receive right to
the shutdown actuator, pwrmgr, in the bootstrap round of each of its launches
([`shutdown_actuator`](../services/svcmgr/docs/service-definitions.md#shutdown_actuator)). pwrmgr
waits on that queue beside its service endpoint, in one wait set; an entry on it is svcmgr's death,
and pwrmgr logs it and powers the platform off as a `SHUTDOWN` request does
([services/pwrmgr/README.md](../services/pwrmgr/README.md#responsibilities)). A queue svcmgr cannot
create or bind, or a wait set pwrmgr cannot make, is logged at error level, and svcmgr's death then
goes unobserved; svcmgr keeps the queue when one of its two binds holds.

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

- A power-off path that neither faults nor calls memmgr after a core death (§ Core Set and System
  Death): #1290.
- The IOMMU driver survives and restarts: #1079.
- procmgr tears down the processes a dead pager other than memmgr served: #226.
- sessiond supervises every session, and oomd stops a session's programs before any service
  ([Session Supervision](session-supervision.md)).

---

## Summarized By

[Architecture Overview](architecture.md), [Boot Media](boot-media.md),
[Process Lifecycle](process-lifecycle.md),
[Session Supervision](session-supervision.md),
[services/procmgr/README.md](../services/procmgr/README.md),
[services/pwrmgr/README.md](../services/pwrmgr/README.md),
[services/svcmgr/README.md](../services/svcmgr/README.md),
[Restart Protocol](../services/svcmgr/docs/restart-protocol.md)
