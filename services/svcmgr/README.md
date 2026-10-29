# svcmgr

Service supervisor and discovery registry. Started by init before
init exits; runs for the lifetime of the system (boot order in
[docs/process-lifecycle.md](../../docs/process-lifecycle.md)). svcmgr is a
self-driven process: it spawns into an already-running system (root
mounted; vfsd, procmgr, devmgr, fs/block drivers up), reads service
*definitions* from `/config/svcmgr/services/`, and reconciles them
against the substrate registrations init delivers in the handover
endowment to either supervise the running instance or launch a fresh
one ([docs/service-definitions.md](docs/service-definitions.md) § Reconciliation).

svcmgr also owns the system-wide discovery registry: it publishes the
well-known names it owns (`rootfs.root`, `svcmgr`, `devmgr.registry`,
`devmgr.shutdown`, `devmgr.test`, and each provider's `provides` names like
`pwrmgr.shutdown` / `timed`) into the registry itself — from the source caps init endows it with at
handover, and from each provider's launch. Consumers resolve any name
through their `.svc` `seed = ...` line at launch time, and the public
names (`svcmgr`, `pwrmgr.deny`, `timed`) also via `QUERY_ENDPOINT`; a
name whose cap carries authority is seed-only, so `QUERY_ENDPOINT`
answers it `UNKNOWN_NAME`. The endowment and registry wire format are in
[docs/ipc-interface.md](docs/ipc-interface.md).

A raw-syscall fallback that lets svcmgr recreate procmgr if procmgr
itself crashes is design intent; not yet implemented (#26); svcmgr holds no
process-creation capabilities today
([docs/restart-protocol.md](docs/restart-protocol.md) § procmgr Fallback).

---

## Source layout

```
svcmgr/
├── Cargo.toml
├── README.md
├── src/
│   ├── main.rs                    # main() (std runtime), IPC dispatch,
│   │                              # dispatch_deaths, initiate_graceful_shutdown
│   ├── service.rs                 # ServiceEntry, RestartRecipe, SvcmgrCaps,
│   │                              # restart-policy constants
│   ├── restart.rs                 # Shared spawn primitives
│   │                              # (walk_and_create_from_file, mint_child_creator,
│   │                              # configure_namespace_caps, start_process),
│   │                              # restart's apply_namespace_policy,
│   │                              # death handling, DeathOutcome
│   ├── definitions/
│   │   ├── mod.rs                 # On-disk definitions; re-exports svc-defs
│   │   ├── launch.rs              # First-launch path
│   │   └── reconcile.rs           # PendingRegistration + reconcile_and_launch
│   └── arch/                      # Per-arch halt() entry
├── svc-defs/                      # `svcmgr-defs` crate: host-tested `.svc`
│                                  # Definition types, parser, argv/env
│                                  # wire-blob encoder (`build_blob`), and
│                                  # the `cwd_rights` / `handover_permitted`
│                                  # decisions
├── endowment/                     # `svcmgr-endowment`, its own component
│                                  # shared with init: host-tested codec of
│                                  # init's handover endowment (see
│                                  # endowment/README.md)
└── docs/
    ├── ipc-interface.md           # handover endowment, HANDOVER_COMPLETE,
    │                              # PUBLISH_ENDPOINT / QUERY_ENDPOINT
    ├── restart-protocol.md        # Death detection, restart sequencing,
    │                              # shared spawn primitives, criticality
    │                              # semantics
    └── service-definitions.md     # `.svc` recipe authoritative spec
```

---

## Responsibilities

- **Handover endowment** — drain init's bootstrap-round endowment in
  [`service::bootstrap_caps`](src/service.rs): svcmgr's own endpoints,
  the publish-role source caps (`rootfs.root` SEND, devmgr-registry
  `SEND|GRANT` source), one `(name, thread_cap)` round per substrate
  service init bootstrapped before svcmgr existed, and a terminal
  `LOGD_SOURCES` round carrying the two log-sink source caps svcmgr holds
  for the system's lifetime (the master-log source and a badge-0
  `SEND|GRANT` death-auth source on procmgr's service endpoint). Recipes
  (binary, argv, env, restart policy, criticality, namespace shape, seed
  names) live on disk, not on the wire — see
  [docs/service-definitions.md](docs/service-definitions.md). The round
  layout is specified in
  [docs/ipc-interface.md](docs/ipc-interface.md#handover-endowment-bootstrap-rounds).
- **Reconciliation** — at `HANDOVER_COMPLETE` scan
  `/config/svcmgr/services/`, parse each `<name>.svc`, and pair it
  with the pending-registration table (substrate pairs parked from the
  endowment). Three outcomes: `bind only` (parked AND defined),
  `launching` (defined only), `registered without definition`
  (parked AND no recipe → hard error). See
  [docs/service-definitions.md](docs/service-definitions.md) § Reconciliation.
- **Launch** — for `defined only` services, spawn via the shared
  primitives in [`restart.rs`](src/restart.rs)
  (`walk_and_create_from_file`, `configure_namespace_caps`,
  `start_process`) and serve the seed bootstrap round; only restart
  resolves the namespace through `apply_namespace_policy`
  ([docs/restart-protocol.md](docs/restart-protocol.md) § Shared spawn primitives).
- **Health monitoring** — bind every supervised service's main
  thread to one shared `deaths_eq` with `correlator =
  service_index`. Detect crashes via async notifications
  ([docs/restart-protocol.md](docs/restart-protocol.md) § Death detection).
- **Restart management** — on detected crash, route through
  [`restart::handle_death`](src/restart.rs); shared spawn primitives
  re-spawn the service from the recorded recipe. The `.svc` file is the
  single source of truth for both launch and restart — fixed fields on
  `ServiceEntry`, the argv/env/cwd/seed, log-sink flag, and scheduling
  fields on a parallel `RestartRecipe` — so a restart reproduces the
  first-launch surfaces
  ([docs/restart-protocol.md](docs/restart-protocol.md) § Recipe storage).
  Whether a service restarts is decided by its `restart` policy + budget
  alone; `critical` is orthogonal (see graceful shutdown below and
  [docs/restart-protocol.md](docs/restart-protocol.md) § Decision tree).
- **Discovery registry** — svcmgr publishes the names it owns directly
  (internal `registry.publish`); `PUBLISH_ENDPOINT` is the external
  write-API (reserved for a future devmgr publisher) and `QUERY_ENDPOINT`
  the lookup, served on the per-process SEND seeded into
  `ProcessInfo.service_registry_cap` ([docs/ipc-interface.md](docs/ipc-interface.md) § Messages).
- **Graceful shutdown** — when a `critical = yes` service is permanently
  down (restart not attempted, budget exhausted, or restart failed), resolve
  `ipc::published_names::PWRMGR_SHUTDOWN` from the registry and issue
  `pwrmgr_labels::SHUTDOWN` ([docs/restart-protocol.md](docs/restart-protocol.md) § Decision tree).

---

## Namespace authority

Init spawns svcmgr with the **universal** `system_root_cap`
([docs/process-lifecycle.md](../../docs/process-lifecycle.md) § Init → remaining services).
svcmgr reads `/config/svcmgr/services/*.svc` directly via `std::fs`,
walks the recipe's `binary` path for first-launch, and applies per-service
namespace attenuation from each `.svc` `namespace = ...` line via
`procmgr_labels::CONFIGURE_NAMESPACE`
([docs/service-definitions.md](docs/service-definitions.md) § `namespace`).
Restart-time attenuation reads the same `ServiceEntry`-stored policy that
reconcile installed ([docs/restart-protocol.md](docs/restart-protocol.md)
§ Recipe storage).

svcmgr scans only `/config/svcmgr/services/`. The sibling directory
`/config/svcmgr/tests/` holds opt-in test-harness recipes; svcmgr never
reads it. The test gating contract — copy a `tests/<harness>.svc` into
`services/` between build and run — is owned by
[docs/testing.md](../../docs/testing.md).

---

## Service definitions

The authoritative spec lives in
[docs/service-definitions.md](docs/service-definitions.md). A
minimal example:

```
binary    = /tests/svctest
argv      = svctest run
env       = SERAPH_TEST=1 SERAPH_MODE=boot
restart   = never
critical  = no
namespace = universal
cwd       = /data
seed      = rootfs.root pwrmgr.shutdown devmgr.registry devmgr.test
```

Recognised keys: `binary` (required), `argv`, `env`, `restart`
(required), `critical` (required), `namespace` (required), `cwd`,
`seed`, `provides`, `log_sink`, `priority`, `sched_max`. Unknown keys
are hard errors. Restart values: `never | on_failure | always`.
Critical values: `yes | no`. Namespace forms:
`none | universal | subtree:<path>:<rights>`. `priority` / `sched_max`
are the service's scheduling placement (level and `SchedControl` band
ceiling, validated against svcmgr's own band); the parser and types live
in the host-tested `svc-defs` crate.

---

## Cap publication

svcmgr publishes every well-known name into its own registry — there is
no init-side `PUBLISH_ENDPOINT` traffic. The first five are published in
`main()` right after the endowment is drained, from the source caps init
endows svcmgr with at handover; the provider names are published on each
provider's launch path from its `provides` line
([docs/service-definitions.md](docs/service-definitions.md) § `provides`). Names are
FS-driver- and platform-agnostic by
design; consumers resolve them through their `.svc` `seed = ...` lines,
and the public ones also via direct `QUERY_ENDPOINT` calls (the Query
column). The handover endowment and
`PUBLISH_ENDPOINT` / `QUERY_ENDPOINT` wire format are specified in
[docs/ipc-interface.md](docs/ipc-interface.md).

| Name | Source | Cap shape | Query |
|---|---|---|---|
| `rootfs.root` | svcmgr (endowed `rootfs.root` SEND) | badged SEND on the root filesystem's namespace endpoint at its root directory | no |
| `svcmgr` | svcmgr (its own service ep) | `PUBLISHED_SEND_BADGE`-badged SEND on svcmgr's own service endpoint (no verb-bit) | yes |
| `devmgr.registry` | svcmgr (minted from the endowed devmgr-registry source) | `REGISTRY_QUERY_AUTHORITY`-badged SEND on devmgr's registry endpoint | no |
| `devmgr.shutdown` | svcmgr (minted from the endowed devmgr-registry source) | `REGISTRY_QUERY_AUTHORITY \| SHUTDOWN_DEVICE_AUTHORITY`-badged SEND on devmgr's registry endpoint (seeded by pwrmgr only) | no |
| `devmgr.test` | svcmgr (minted from the endowed devmgr-registry source) | `REGISTRY_QUERY_AUTHORITY \| ORPHAN_TEST_AUTHORITY`-badged SEND on devmgr's registry endpoint (seeded by svctest only; TODO(#165)) | no |
| `pwrmgr.shutdown` | svcmgr (`pwrmgr.svc` [provider](docs/service-definitions.md)) | `SHUTDOWN_AUTHORITY`-badged SEND on pwrmgr's service endpoint | no |
| `pwrmgr.deny` | svcmgr (`pwrmgr.svc` [provider](docs/service-definitions.md)) | no-authority SEND on pwrmgr's service endpoint (negative-test twin) | yes |
| `timed` | svcmgr (`timed.svc` [provider](docs/service-definitions.md)) | SEND on timed's service endpoint | yes |

Centralised name constants live in `ipc::published_names`.

---

## Criticality

`critical` is binary (`yes` / `no`) and orthogonal to `restart`: it
governs only what happens once a service is permanently down, not
whether it restarts ([docs/service-definitions.md](docs/service-definitions.md)
§ `critical`). A `critical = yes` service triggers a graceful
shutdown via pwrmgr on permanent death (restart not attempted, budget
exhausted, or restart failed); a `critical = no` service is logged and
the system continues degraded. Edge case: pwrmgr itself cannot trigger
shutdown on its own death (the shutdown source is gone); svcmgr logs the
degraded state. See
[docs/restart-protocol.md](docs/restart-protocol.md) for the decision
tree.

---

## Restart policy

Each `.svc` carries `restart = never | on_failure | always`. Restarts
are counted per service over its lifetime (no window, no reset). Once
`MAX_RESTARTS` (currently `1`) restarts have run, the service's next
death leaves it permanently down — degraded, or a graceful shutdown for
`critical = yes`. See
[docs/restart-protocol.md](docs/restart-protocol.md).

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/architecture.md](../../docs/architecture.md) | System design, init/procmgr/svcmgr roles |
| [docs/capability-model.md](../../docs/capability-model.md) | Capability types, verb-bit authority, revocation |
| [docs/process-lifecycle.md](../../docs/process-lifecycle.md) | Userspace boot order, init's Handover stage, process-death flow |
| [docs/coding-standards.md](../../docs/coding-standards.md) | Formatting, naming, safety rules |
| [docs/documentation-standards.md](../../docs/documentation-standards.md) | Document hierarchy, authority, backlinks |
| [services/svcmgr/endowment/README.md](endowment/README.md) | `svcmgr-endowment`: the handover-endowment wire codec svcmgr decodes with |

---

## Summarized By

[Architecture Overview](../../docs/architecture.md),
[Process Lifecycle](../../docs/process-lifecycle.md), [Testing](../../docs/testing.md),
[services/init/README.md](../init/README.md)
