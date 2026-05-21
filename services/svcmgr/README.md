# svcmgr

Service supervisor and discovery registry. Started by init before
init exits; runs for the lifetime of the system. svcmgr is a
self-driven process: it spawns into an already-running system (root
mounted; vfsd, procmgr, devmgr, fs/block drivers up), reads service
*definitions* from `/etc/svcmgr/services.d/`, and reconciles them
against init's pending `REGISTER_SERVICE` announcements to either
supervise the running instance or launch a fresh one.

svcmgr also owns the system-wide discovery registry: well-known names
(`rootfs.root`, `pwrmgr.shutdown`, `pwrmgr.deny`, `svcmgr`, …) are
published into it by init at Phase 3, and consumers resolve them via
`QUERY_ENDPOINT` (or transparently through their `.svc` `seed = ...`
line at launch time).

svcmgr also holds raw process-creation syscall capabilities as a
documented future fallback to restart procmgr if procmgr itself
crashes. This is the only service that can create a process without
going through procmgr.

---

## Source layout

```
svcmgr/
├── Cargo.toml
├── README.md
├── src/
│   ├── main.rs                    # _start, IPC dispatch, dispatch_deaths,
│   │                              # initiate_graceful_shutdown
│   ├── service.rs                 # ServiceEntry, SvcmgrCaps, restart-policy
│   │                              # and criticality constants
│   ├── restart.rs                 # Shared spawn primitives
│   │                              # (walk_and_create_from_file, mint_child_creator,
│   │                              # start_process, apply_namespace_policy),
│   │                              # death handling, DeathOutcome
│   ├── definitions/
│   │   ├── mod.rs                 # Definition struct + RestartPolicy /
│   │   │                          # Criticality / NamespaceShape enums
│   │   ├── parse.rs               # `.svc` key=value parser
│   │   ├── launch.rs              # First-launch path
│   │   └── reconcile.rs           # PendingRegistration + reconcile_and_launch
│   └── arch/                      # Per-arch halt() entry
└── docs/
    ├── ipc-interface.md           # v3 REGISTER_SERVICE, HANDOVER_COMPLETE,
    │                              # PUBLISH_ENDPOINT / QUERY_ENDPOINT
    ├── restart-protocol.md        # Death detection, restart sequencing,
    │                              # shared spawn primitives, criticality
    │                              # semantics
    └── service-definitions.md     # `.svc` recipe authoritative spec
```

---

## Responsibilities

- **Service registration** — accept the v3 `REGISTER_SERVICE` wire
  (name + thread_cap) from init for services init bootstrapped
  before svcmgr existed. Recipes (binary, argv, env, restart policy,
  criticality, namespace shape, seed names) live on disk, not on the
  wire — see [docs/service-definitions.md](docs/service-definitions.md).
- **Reconciliation** — at `HANDOVER_COMPLETE` scan
  `/etc/svcmgr/services.d/`, parse each `<name>.svc`, and pair it
  with the pending-registration table. Three outcomes: `bind only`
  (registered AND defined), `launching` (defined only),
  `registered without definition` (registered AND no recipe → hard
  error).
- **Launch** — for `defined only` services, spawn via the shared
  primitives in [`restart.rs`](src/restart.rs)
  (`walk_and_create_from_file`, `apply_namespace_policy`,
  `start_process`) and serve the seed bootstrap round.
- **Health monitoring** — bind every supervised service's main
  thread to one shared `deaths_eq` with `correlator =
  service_index`. Detect crashes via async notifications.
- **Restart management** — on detected crash, route through
  [`restart::handle_death`](src/restart.rs); shared spawn primitives
  re-spawn the service from the on-disk recipe. The `.svc` file is
  the single source of truth for both launch and restart.
- **Discovery registry** — `PUBLISH_ENDPOINT` (init's
  `PUBLISH_AUTHORITY`-tokened SENDs) and `QUERY_ENDPOINT`
  (per-process SEND seeded into `ProcessInfo.service_registry_cap`).
- **Graceful shutdown** — when a `critical = high` service dies
  unrecoverably, resolve `ipc::published_names::PWRMGR_SHUTDOWN`
  from the registry and issue `pwrmgr_labels::SHUTDOWN`.

---

## Namespace authority

Init spawns svcmgr with the **universal** `system_root_cap` (post-#21).
svcmgr reads `/etc/svcmgr/services.d/*.svc` directly via `std::fs`,
walks `/bin/<name>` for first-launch, and applies per-service
namespace attenuation from each `.svc` `namespace = ...` line via
`procmgr_labels::CONFIGURE_NAMESPACE`. Restart-time attenuation reads
the same `ServiceEntry`-stored policy that reconcile installed.

---

## Service definitions

The authoritative spec lives in
[docs/service-definitions.md](docs/service-definitions.md). A
minimal example:

```
binary    = /bin/svctest
argv      = svctest run
env       = SERAPH_TEST=1 SERAPH_MODE=boot
restart   = never
critical  = low
namespace = universal
cwd       = /srv
seed      = rootfs.root pwrmgr.shutdown pwrmgr.deny
```

Recognised keys: `binary` (required), `argv`, `env`, `restart`
(required), `critical` (required), `namespace` (required), `cwd`,
`seed`. Unknown keys are hard errors. Restart values:
`never | on_failure | always`. Criticality values: `low | normal | high`.
Namespace forms: `none | universal | subtree:<path>:<rights>`.

---

## Cap publication

Init publishes the following well-known names into svcmgr's registry
during Phase 3 (post-#21). Names are FS-driver- and platform-agnostic
by design; consumers resolve them through their `.svc` `seed = ...`
lines or via direct `QUERY_ENDPOINT` calls.

| Name | Source | Cap shape |
|---|---|---|
| `rootfs.root` | init Phase 3 | tokened SEND on the root filesystem's namespace endpoint at its root directory |
| `pwrmgr.shutdown` | init Phase 3 | `SHUTDOWN_AUTHORITY`-tokened SEND on pwrmgr's service endpoint |
| `pwrmgr.deny` | init Phase 3 | no-authority SEND on pwrmgr's service endpoint (negative-test twin) |
| `svcmgr` | init Phase 3 | un-tokened SEND on svcmgr's own service endpoint |
| `rtc.primary` | init bring-up | SEND on the per-board RTC driver's service endpoint |
| `timed` | init bring-up | SEND on timed's service endpoint |

Centralised name constants live in `ipc::published_names`.

---

## Criticality

`critical = high` services trigger a graceful shutdown via pwrmgr on
unrecoverable death (either `restart = never` or restart budget
exhausted). Edge case: pwrmgr itself cannot trigger shutdown on its
own death (the shutdown source is gone); svcmgr logs the degraded
state. See [docs/restart-protocol.md](docs/restart-protocol.md) for
the decision tree.

---

## Restart policy

Each `.svc` carries `restart = never | on_failure | always`. Restart
attempts are counted per service. After a configurable maximum
(`MAX_RESTARTS`, currently `1`) in a short window, the service is
marked degraded and not restarted automatically. See
[docs/restart-protocol.md](docs/restart-protocol.md).

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/architecture.md](../../docs/architecture.md) | System design, init/procmgr/svcmgr roles |
| [docs/capability-model.md](../../docs/capability-model.md) | Capability types, verb-bit authority, revocation |
| [docs/process-lifecycle.md](../../docs/process-lifecycle.md) | Userspace boot order, Phase 3 handover, process-death flow |
| [docs/coding-standards.md](../../docs/coding-standards.md) | Formatting, naming, safety rules |
| [docs/documentation-standards.md](../../docs/documentation-standards.md) | Document hierarchy, authority, backlinks |

---

## Summarized By

[Architecture Overview](../../docs/architecture.md), [System Bootstrap](../../docs/bootstrap.md), [Process Lifecycle](../../docs/process-lifecycle.md)
